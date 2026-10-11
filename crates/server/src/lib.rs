//! # twosecret-server
//!
//! A small, self-hostable, zero-knowledge sync server for 2Secret. It stores
//! encrypted vaults and items, public keys and slow hashes of authentication
//! keys – never anything that allows decrypting user data.
//!
//! It can also serve the 2Secret web app, so a single binary provides both the
//! sync API and the browser vault.

pub mod auth;
pub mod db;
pub mod error;
pub mod ratelimit;
pub mod routes;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Method};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use twosecret_core::crypto::SymmetricKey;

pub use db::Db;

/// Who may create accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum SignupMode {
    /// Anyone who can reach the server.
    Open,
    /// Only people with an invite code.
    Invite,
    /// Nobody (existing accounts keep working).
    Closed,
}

/// Server configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub signups: SignupMode,
    pub invite_codes: Vec<String>,
    pub session_days: i64,
    pub web_dir: Option<PathBuf>,
    pub cors_origins: Vec<String>,
    pub max_item_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            signups: SignupMode::Open,
            invite_codes: vec![],
            session_days: 30,
            web_dir: None,
            cors_origins: vec![],
            max_item_bytes: 16 * 1024 * 1024,
            max_body_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Shared state of all request handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
    /// Random per-installation secret used to answer pre-login requests for
    /// unknown e-mail addresses with stable fake parameters.
    pub server_secret: Arc<SymmetricKey>,
    pub login_limiter: Arc<ratelimit::RateLimiter>,
}

impl AppState {
    pub fn new(db: Db, config: Config, server_secret: SymmetricKey) -> Self {
        Self {
            db,
            config: Arc::new(config),
            server_secret: Arc::new(server_secret),
            login_limiter: Arc::new(ratelimit::RateLimiter::new(10, 15 * 60)),
        }
    }

    /// Open (or create) the database and server secret in `data_dir`.
    pub fn open(data_dir: &std::path::Path, config: Config) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let db = Db::open(&data_dir.join("2secret.db"))?;
        let secret = {
            let conn = rusqlite::Connection::open(data_dir.join("2secret.db"))?;
            match db::get_meta(&conn, "server_secret")? {
                Some(s) => SymmetricKey::from_b64(&s)?,
                None => {
                    let k = SymmetricKey::generate();
                    db::set_meta(&conn, "server_secret", &k.to_b64())?;
                    k
                }
            }
        };
        Ok(Self::new(db, config, secret))
    }

    /// In-memory state for tests.
    pub fn in_memory(config: Config) -> anyhow::Result<Self> {
        Ok(Self::new(Db::open_in_memory()?, config, SymmetricKey::generate()))
    }
}

/// Build the complete HTTP application.
pub fn app(state: AppState) -> Router {
    let config = state.config.clone();
    let api = routes::api_router().with_state(state);

    let mut app = Router::new().nest("/api/v1", api).layer(DefaultBodyLimit::max(config.max_body_bytes));

    if let Some(dir) = &config.web_dir {
        let index = dir.join("index.html");
        app = app.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)));
    }

    let security_headers = [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        ),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; \
             connect-src 'self' https://api.pwnedpasswords.com; frame-ancestors 'none'; \
             base-uri 'none'; form-action 'self'; object-src 'none'",
        ),
    ];
    for (name, value) in security_headers {
        app = app.layer(SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value)));
    }
    app = app.layer(SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store")));

    if !config.cors_origins.is_empty() {
        let origins: Vec<HeaderValue> =
            config.cors_origins.iter().filter_map(|o| HeaderValue::from_str(o).ok()).collect();
        let allow =
            if config.cors_origins.iter().any(|o| o == "*") { AllowOrigin::any() } else { AllowOrigin::list(origins) };
        app = app.layer(
            CorsLayer::new()
                .allow_origin(allow)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        );
    }

    app.layer(tower_http::trace::TraceLayer::new_for_http())
}

/// Serve the application on an already bound listener until shutdown.
pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> anyhow::Result<()> {
    axum::serve(listener, app(state)).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}
