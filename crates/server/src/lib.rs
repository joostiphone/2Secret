//! # twosecret-server
//!
//! A small, self-hostable, zero-knowledge sync server for 2Secret. It stores
//! encrypted vaults and items, public keys and slow hashes of authentication
//! keys – never anything that allows decrypting user data.
//!
//! It can also serve the 2Secret web app, so a single binary provides both the
//! sync API and the browser vault.

pub mod auth;
pub mod client_ip;
pub mod db;
pub mod emergency;
pub mod error;
pub mod ratelimit;
pub mod routes;
pub mod share;

use std::net::SocketAddr;
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
    /// No new accounts once there are this many.
    pub max_accounts: Option<u64>,
    /// Storage per account for the vaults it owns (shared vaults count for
    /// their owner).
    pub account_quota_bytes: Option<u64>,
    /// New accounts per client IP address (IPv6: per /64) per day.
    pub signups_per_ip: Option<u32>,
    /// Header with the client's address, set by a reverse proxy on this
    /// machine (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`). Only
    /// believed for connections from the loopback interface and from
    /// `trusted_proxies`.
    pub client_ip_header: Option<String>,
    /// Reverse proxies on other machines (cloudflared in another container)
    /// whose `client_ip_header` is believed.
    pub trusted_proxies: Vec<client_ip::TrustedProxy>,
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
            max_accounts: None,
            account_quota_bytes: None,
            signups_per_ip: None,
            client_ip_header: None,
            trusted_proxies: vec![],
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
    /// Counts new accounts per client address.
    pub signup_limiter: Arc<ratelimit::RateLimiter>,
    /// Counts attempts to open share links per client address.
    pub share_limiter: Arc<ratelimit::RateLimiter>,
    /// Counts failed sign-ins and wrong invite codes per client address.
    pub attempt_limiter: Arc<ratelimit::RateLimiter>,
    /// Password hashes (Argon2id, memory-hard) running at the same time: one
    /// per processor, so a flood of sign-ins cannot exhaust the server.
    pub hash_slots: Arc<tokio::sync::Semaphore>,
}

impl AppState {
    pub fn new(db: Db, config: Config, server_secret: SymmetricKey) -> Self {
        let signups_per_ip = config.signups_per_ip.unwrap_or(u32::MAX);
        Self {
            db,
            config: Arc::new(config),
            server_secret: Arc::new(server_secret),
            login_limiter: Arc::new(ratelimit::RateLimiter::new(10, 15 * 60)),
            signup_limiter: Arc::new(ratelimit::RateLimiter::new(signups_per_ip, 24 * 3600)),
            share_limiter: Arc::new(ratelimit::RateLimiter::new(60, 15 * 60)),
            attempt_limiter: Arc::new(ratelimit::RateLimiter::new(30, 15 * 60)),
            hash_slots: Arc::new(tokio::sync::Semaphore::new(
                std::thread::available_parallelism().map_or(2, |n| n.get()).max(2),
            )),
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
    let api = routes::api_router().merge(share::api()).merge(emergency::api()).with_state(state.clone());
    let pages = share::pages().with_state(state);

    let mut app = Router::new().nest("/api/v1", api).merge(pages).layer(DefaultBodyLimit::max(config.max_body_bytes));

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
    // Rate limiters hold client addresses and e-mail addresses in memory:
    // forget them as soon as their window has passed.
    let limiters = [state.login_limiter.clone(), state.signup_limiter.clone(), state.share_limiter.clone()];
    let db = state.db.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = twosecret_core::util::now();
            limiters.iter().for_each(|l| l.prune(now));
            // Expired share links go.
            let _ = db.run(|c| Ok(share::delete_expired(c)?)).await;
        }
    });
    // The peer address is needed for the per-address sign-up limit.
    let service = app(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, service).with_graceful_shutdown(shutdown_signal()).await?;
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
