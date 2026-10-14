//! # twosecret-client
//!
//! Talks to a 2Secret sync server. Works natively (CLI, desktop, iOS) and in
//! the browser (WebAssembly) – the same code drives every 2Secret app.
//!
//! * [`Client`] – thin typed wrapper around the `/api/v1` endpoints.
//! * [`flows`] – complete user-level operations: sign up, sign in, connect a
//!   local account to a server, sync, share vaults, change the password, and
//!   the Have I Been Pwned breach check.
//! * [`update`] – signed app updates from the GitHub releases (native only).

// Websites do not let browsers read their icons (CORS), so only the apps fetch them.
#[cfg(not(target_arch = "wasm32"))]
pub mod favicon;
pub mod flows;
#[cfg(not(target_arch = "wasm32"))]
pub mod update;

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use twosecret_core::api::*;

pub use flows::*;

#[derive(Debug, Error)]
pub enum Error {
    #[error("could not reach the server: {0}")]
    Network(String),
    #[error("{message}")]
    Api { status: u16, code: String, message: String },
    #[error("your session on the server has expired; sign in again")]
    Unauthorized,
    #[error("this account is not connected to a sync server")]
    NotLinked,
    #[error(transparent)]
    Core(#[from] twosecret_core::Error),
    #[error("unexpected response from server: {0}")]
    Protocol(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The 2Secret server that anyone may use, so nobody has to run their own.
pub const OFFICIAL_SERVER: &str = "https://sync.2secret.app";

impl Error {
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } => Some(*status),
            Error::Unauthorized => Some(401),
            _ => None,
        }
    }

    pub fn is_not_found(&self) -> bool {
        self.status() == Some(404)
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Network(e.to_string())
    }
}

/// Normalise a server URL typed by a user (`vault.example.com` →
/// `https://vault.example.com`).
pub fn normalize_server_url(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else if url.starts_with("localhost") || url.starts_with("127.0.0.1") {
        format!("http://{url}")
    } else {
        format!("https://{url}")
    }
}

/// Typed API client.
#[derive(Clone, Debug)]
pub struct Client {
    base: String,
    http: reqwest::Client,
    token: Option<String>,
}

fn build_http() -> reqwest::Client {
    #[cfg(not(target_arch = "wasm32"))]
    {
        reqwest::Client::builder()
            .user_agent(concat!("2Secret/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default()
    }
    #[cfg(target_arch = "wasm32")]
    {
        reqwest::Client::new()
    }
}

impl Client {
    pub fn new(base_url: &str) -> Self {
        Self { base: normalize_server_url(base_url), http: build_http(), token: None }
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn set_token(&mut self, token: Option<String>) {
        self.token = token;
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.base, path)
    }

    async fn send<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<reqwest::Response> {
        let mut req = self.http.request(method, self.url(path));
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        if status == StatusCode::UNAUTHORIZED {
            // Distinguish "bad credentials" (login) from "session expired".
            let body: Option<ErrorResponse> = resp.json().await.ok();
            return Err(match body {
                Some(e) if e.error == "invalid_credentials" => {
                    Error::Api { status: 401, code: e.error, message: e.message }
                }
                _ => Error::Unauthorized,
            });
        }
        let text = resp.text().await.unwrap_or_default();
        let (code, message) = match serde_json::from_str::<ErrorResponse>(&text) {
            Ok(e) => (e.error, e.message),
            Err(_) => ("http_error".to_string(), format!("server returned HTTP {}", status.as_u16())),
        };
        Err(Error::Api { status: status.as_u16(), code, message })
    }

    async fn json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let resp = self.send(method, path, body).await?;
        resp.json::<T>().await.map_err(|e| Error::Protocol(e.to_string()))
    }

    async fn empty<B: Serialize + ?Sized>(&self, method: Method, path: &str, body: Option<&B>) -> Result<()> {
        self.send(method, path, body).await.map(|_| ())
    }

    pub async fn health(&self) -> Result<HealthResponse> {
        self.json(Method::GET, "/health", None::<&()>).await
    }

    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        self.json(Method::POST, "/prelogin", Some(&PreloginRequest { email: email.to_string() })).await
    }

    pub async fn register(&self, req: &RegisterRequest) -> Result<SessionResponse> {
        self.json(Method::POST, "/register", Some(req)).await
    }

    pub async fn login(&self, req: &LoginRequest) -> Result<SessionResponse> {
        self.json(Method::POST, "/login", Some(req)).await
    }

    pub async fn logout(&self) -> Result<()> {
        self.empty(Method::POST, "/logout", None::<&()>).await
    }

    pub async fn account(&self) -> Result<AccountInfo> {
        self.json(Method::GET, "/account", None::<&()>).await
    }

    pub async fn update_account(&self, name: &str) -> Result<()> {
        self.empty(Method::PUT, "/account", Some(&UpdateAccountRequest { name: name.to_string() })).await
    }

    pub async fn change_password(&self, req: &ChangePasswordRequest) -> Result<()> {
        self.empty(Method::POST, "/account/password", Some(req)).await
    }

    pub async fn delete_account(&self, auth_key: &str) -> Result<()> {
        self.empty(Method::DELETE, "/account", Some(&DeleteAccountRequest { auth_key: auth_key.to_string() })).await
    }

    pub async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        self.json(Method::GET, "/devices", None::<&()>).await
    }

    pub async fn revoke_device(&self, id: &str) -> Result<()> {
        self.empty(Method::DELETE, &format!("/devices/{id}"), None::<&()>).await
    }

    pub async fn lookup_user(&self, email: &str) -> Result<PublicKeyResponse> {
        let q: String = email
            .trim()
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        self.json(Method::GET, &format!("/users/lookup?email={q}"), None::<&()>).await
    }

    pub async fn vaults(&self) -> Result<Vec<VaultDto>> {
        self.json(Method::GET, "/vaults", None::<&()>).await
    }

    pub async fn create_vault(&self, req: &CreateVaultRequest) -> Result<VaultDto> {
        self.json(Method::POST, "/vaults", Some(req)).await
    }

    pub async fn update_vault(&self, id: &str, req: &UpdateVaultRequest) -> Result<()> {
        self.empty(Method::PUT, &format!("/vaults/{id}"), Some(req)).await
    }

    pub async fn delete_vault(&self, id: &str) -> Result<()> {
        self.empty(Method::DELETE, &format!("/vaults/{id}"), None::<&()>).await
    }

    /// Replace our own wrapped key for a vault.
    pub async fn set_vault_key(&self, vault_id: &str, req: &SetVaultKeyRequest) -> Result<()> {
        self.empty(Method::PUT, &format!("/vaults/{vault_id}/key"), Some(req)).await
    }

    /// Replace a vault's key (see [`RotateVaultKeyRequest`]).
    pub async fn rotate_vault_key(&self, vault_id: &str, req: &RotateVaultKeyRequest) -> Result<()> {
        self.empty(Method::POST, &format!("/vaults/{vault_id}/rotate-key"), Some(req)).await
    }

    /// Publish our ML-KEM-768 public key.
    pub async fn set_pq_key(&self, req: &SetPqKeyRequest) -> Result<()> {
        self.empty(Method::PUT, "/account/pq-key", Some(req)).await
    }

    pub async fn members(&self, vault_id: &str) -> Result<Vec<MemberDto>> {
        self.json(Method::GET, &format!("/vaults/{vault_id}/members"), None::<&()>).await
    }

    pub async fn add_member(&self, vault_id: &str, req: &AddMemberRequest) -> Result<()> {
        self.empty(Method::POST, &format!("/vaults/{vault_id}/members"), Some(req)).await
    }

    pub async fn update_member(&self, vault_id: &str, account_id: &str, req: &UpdateMemberRequest) -> Result<()> {
        self.empty(Method::PUT, &format!("/vaults/{vault_id}/members/{account_id}"), Some(req)).await
    }

    pub async fn remove_member(&self, vault_id: &str, account_id: &str) -> Result<()> {
        self.empty(Method::DELETE, &format!("/vaults/{vault_id}/members/{account_id}"), None::<&()>).await
    }

    pub async fn sync(&self, req: &SyncRequest) -> Result<SyncResponse> {
        self.json(Method::POST, "/sync", Some(req)).await
    }
}
