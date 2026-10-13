use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use twosecret_server::{AppState, Config, SignupMode};

/// 2Secret sync server – self-hosted, zero-knowledge storage for your vaults.
#[derive(Parser, Debug)]
#[command(name = "2secret-server", version, about)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "TWOSECRET_BIND", default_value = "127.0.0.1:8743")]
    bind: SocketAddr,

    /// Directory for the database.
    #[arg(long, env = "TWOSECRET_DATA_DIR", default_value = "./2secret-data")]
    data_dir: PathBuf,

    /// Serve the 2Secret web app from this directory.
    #[arg(long, env = "TWOSECRET_WEB_DIR")]
    web_dir: Option<PathBuf>,

    /// Who may create accounts.
    #[arg(long, env = "TWOSECRET_SIGNUPS", value_enum, default_value = "open")]
    signups: SignupMode,

    /// Invite codes accepted when signups are `invite` (comma separated).
    #[arg(long, env = "TWOSECRET_INVITE_CODES", value_delimiter = ',')]
    invite_codes: Vec<String>,

    /// Days of inactivity after which a device is signed out.
    #[arg(long, env = "TWOSECRET_SESSION_DAYS", default_value_t = 30)]
    session_days: i64,

    /// Allowed CORS origins for web clients hosted elsewhere (comma separated, `*` for any).
    #[arg(long, env = "TWOSECRET_CORS_ORIGINS", value_delimiter = ',')]
    cors_origins: Vec<String>,

    /// Accept no new accounts once there are this many.
    #[arg(long, env = "TWOSECRET_MAX_ACCOUNTS")]
    max_accounts: Option<u64>,

    /// Storage limit per account in megabytes, for the vaults it owns
    /// (shared vaults count for their owner).
    #[arg(long, env = "TWOSECRET_ACCOUNT_STORAGE_MB")]
    account_storage_mb: Option<u64>,

    /// New accounts per client address per day (IPv6: per /64).
    #[arg(long, env = "TWOSECRET_SIGNUPS_PER_IP")]
    signups_per_ip: Option<u32>,

    /// Header with the client's address, set by a reverse proxy on this
    /// machine: `CF-Connecting-IP` (Cloudflare Tunnel), `X-Forwarded-For`
    /// (Caddy, nginx) or `X-Real-IP`. Believed only for local connections.
    #[arg(long, env = "TWOSECRET_CLIENT_IP_HEADER")]
    client_ip_header: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .init();
    let args = Args::parse();
    if args.signups == SignupMode::Invite && args.invite_codes.is_empty() {
        anyhow::bail!("--signups invite requires at least one --invite-codes value");
    }
    let config = Config {
        signups: args.signups,
        invite_codes: args.invite_codes.into_iter().filter(|c| !c.trim().is_empty()).collect(),
        session_days: args.session_days.max(1),
        web_dir: args.web_dir.clone(),
        cors_origins: args.cors_origins,
        max_accounts: args.max_accounts,
        account_quota_bytes: args.account_storage_mb.map(|mb| mb.saturating_mul(1_000_000)),
        signups_per_ip: args.signups_per_ip,
        client_ip_header: args.client_ip_header.filter(|h| !h.trim().is_empty()),
        ..Config::default()
    };
    if let Some(dir) = &args.web_dir {
        if !dir.join("index.html").exists() {
            tracing::warn!("web dir {} has no index.html", dir.display());
        }
    }
    let state = AppState::open(&args.data_dir, config)?;
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(
        "2Secret server {} listening on http://{} (data: {})",
        twosecret_core::VERSION,
        listener.local_addr()?,
        args.data_dir.display()
    );
    let limits: Vec<String> = [
        state.config.account_quota_bytes.map(|b| format!("{} MB per account", b / 1_000_000)),
        state.config.signups_per_ip.map(|n| format!("{n} sign-ups per address per day")),
        state.config.max_accounts.map(|n| format!("at most {n} accounts")),
        state.config.client_ip_header.as_ref().map(|h| format!("client address from {h}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !limits.is_empty() {
        tracing::info!("limits: {}", limits.join(", "));
    }
    if !args.bind.ip().is_loopback() {
        tracing::warn!("serving on a public interface: put a TLS-terminating reverse proxy in front of 2Secret");
    }
    twosecret_server::serve(listener, state).await
}
