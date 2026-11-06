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
// Vaults in storage folders: the apps and the command line, not the web.
#[cfg(not(target_arch = "wasm32"))]
pub mod folder;
#[cfg(not(target_arch = "wasm32"))]
pub mod update;

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use twosecret_core::api::*;
use twosecret_core::crypto::EncString;

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
    #[error("2Secret connects to a server only over https:// (plain http:// only on this device)")]
    InsecureServer,
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

/// Whether the apps may talk to a server address: `https://`, or plain
/// `http://` on this device only (a server under development). Over a
/// network, plain HTTP would show the sign-in key and the session token to
/// anyone on the way.
pub fn secure_server_url(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else { return false };
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    match url.scheme() {
        "https" => true,
        "http" => host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        _ => false,
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
        // The web vault talks to the server it was loaded from.
        #[cfg(not(target_arch = "wasm32"))]
        if !secure_server_url(&self.base) {
            return Err(Error::InsecureServer);
        }
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

    pub async fn set_avatar(&self, req: &SetAvatarRequest) -> Result<()> {
        self.empty(Method::PUT, "/account/avatar", Some(req)).await
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

    pub async fn create_share(&self, req: &CreateShareRequest) -> Result<()> {
        self.empty(Method::POST, "/shares", Some(req)).await
    }

    pub async fn shares(&self) -> Result<Vec<ShareDto>> {
        self.json(Method::GET, "/shares", None::<&()>).await
    }

    pub async fn revoke_share(&self, id: &str) -> Result<()> {
        self.empty(Method::DELETE, &format!("/shares/{id}"), None::<&()>).await
    }

    /// What anyone with the link may see before opening it.
    pub async fn share_info(&self, id: &str) -> Result<ShareInfo> {
        self.json(Method::GET, &format!("/shares/{id}"), None::<&()>).await
    }

    /// Open a link (uses up a view); what the page in the browser does.
    pub async fn open_share(&self, id: &str, proof: &str) -> Result<OpenShareResponse> {
        self.json(Method::POST, &format!("/shares/{id}/open"), Some(&OpenShareRequest { proof: proof.to_string() }))
            .await
    }

    pub async fn emergency(&self) -> Result<EmergencyOverview> {
        self.json(Method::GET, "/emergency", None::<&()>).await
    }

    pub async fn add_emergency_contact(&self, req: &AddEmergencyContactRequest) -> Result<AddEmergencyContactResponse> {
        self.json(Method::POST, "/emergency", Some(req)).await
    }

    pub async fn set_emergency_keys(&self, id: &str, req: &EmergencyKeysRequest) -> Result<()> {
        self.empty(Method::PUT, &format!("/emergency/{id}/keys"), Some(req)).await
    }

    pub async fn request_emergency_access(&self, id: &str) -> Result<()> {
        self.empty(Method::POST, &format!("/emergency/{id}/request"), None::<&()>).await
    }

    pub async fn approve_emergency_access(&self, id: &str) -> Result<()> {
        self.empty(Method::POST, &format!("/emergency/{id}/approve"), None::<&()>).await
    }

    pub async fn reject_emergency_access(&self, id: &str) -> Result<EmergencyRevoked> {
        self.json(Method::POST, &format!("/emergency/{id}/reject"), None::<&()>).await
    }

    pub async fn open_emergency_access(&self, id: &str) -> Result<()> {
        self.empty(Method::POST, &format!("/emergency/{id}/open"), None::<&()>).await
    }

    pub async fn remove_emergency_contact(&self, id: &str) -> Result<EmergencyRevoked> {
        self.json(Method::DELETE, &format!("/emergency/{id}"), None::<&()>).await
    }

    // --- Agents elsewhere (`twosecret_core::agent_remote`), the owner's side ---

    /// Register a pairing code (its token hash) for [`PAIRING_SECONDS`].
    ///
    /// [`PAIRING_SECONDS`]: twosecret_core::agent_remote::PAIRING_SECONDS
    pub async fn create_agent_pairing(&self, token_hash: &str) -> Result<CreatePairingResponse> {
        let req = CreatePairingRequest { token_hash: token_hash.to_string() };
        self.json(Method::POST, "/agents/pairings", Some(&req)).await
    }

    /// The agents elsewhere of this account: pending and confirmed.
    pub async fn agents(&self) -> Result<Vec<AgentDto>> {
        self.json(Method::GET, "/agents", None::<&()>).await
    }

    /// Confirm a pending agent with its encrypted record.
    pub async fn confirm_agent(&self, agent_id: &str, record: EncString) -> Result<()> {
        self.empty(Method::PUT, &format!("/agents/{agent_id}"), Some(&ConfirmAgentRequest { record })).await
    }

    pub async fn revoke_agent(&self, agent_id: &str) -> Result<()> {
        self.empty(Method::DELETE, &format!("/agents/{agent_id}"), None::<&()>).await
    }

    /// Open requests of this account's agents; with `wait` seconds (at most
    /// [`MAX_WAIT_SECONDS`]) the server holds the call until one arrives.
    ///
    /// [`MAX_WAIT_SECONDS`]: twosecret_core::agent_remote::MAX_WAIT_SECONDS
    pub async fn agent_requests(&self, wait: u32) -> Result<Vec<AgentRequestDto>> {
        self.json(Method::GET, &format!("/agents/requests?wait={wait}"), None::<&()>).await
    }

    /// Answer a request (409 when another device answered first).
    pub async fn answer_agent_request(&self, request_id: &str, answer: EncString) -> Result<()> {
        let path = format!("/agents/requests/{request_id}/answer");
        self.empty(Method::POST, &path, Some(&AgentAnswerRequest { answer })).await
    }

    pub async fn deny_agent_request(&self, request_id: &str) -> Result<()> {
        self.empty(Method::POST, &format!("/agents/requests/{request_id}/deny"), None::<&()>).await
    }

    /// The account keys behind a pairing token (no sign-in; the agent calls
    /// this before it pairs).
    pub async fn agent_pairing_info(&self, token: &str) -> Result<PairingInfo> {
        self.json(Method::GET, &format!("/agent/pairing/{token}"), None::<&()>).await
    }
}

/// The agent's side of the relay: every call carries the signed
/// `X-2Secret-Agent` header over the method, the path, the body and a fresh
/// time and nonce ([`HttpSignature`]).
///
/// [`HttpSignature`]: twosecret_core::agent_remote::HttpSignature
pub struct AgentClient {
    base: String,
    http: reqwest::Client,
    keys: twosecret_core::agent_remote::RemoteKeys,
}

impl std::fmt::Debug for AgentClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgentClient({}, {})", self.base, self.keys.agent_id())
    }
}

impl AgentClient {
    pub fn new(base_url: &str, keys: twosecret_core::agent_remote::RemoteKeys) -> Self {
        Self { base: normalize_server_url(base_url), http: build_http(), keys }
    }

    pub fn keys(&self) -> &twosecret_core::agent_remote::RemoteKeys {
        &self.keys
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    async fn signed<T: DeserializeOwned>(&self, method: Method, path: &str, body: Vec<u8>) -> Result<T> {
        #[cfg(not(target_arch = "wasm32"))]
        if !secure_server_url(&self.base) {
            return Err(Error::InsecureServer);
        }
        let full_path = format!("/api/v1{path}");
        let sig = twosecret_core::agent_remote::HttpSignature::sign(
            &self.keys,
            method.as_str(),
            &full_path,
            &body,
            twosecret_core::util::now(),
        );
        let mut req = self
            .http
            .request(method, format!("{}{full_path}", self.base))
            .header(twosecret_core::agent_remote::HTTP_HEADER, sig.header());
        if !body.is_empty() {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/json").body(body);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if status.is_success() {
            return resp.json::<T>().await.map_err(|e| Error::Protocol(e.to_string()));
        }
        let text = resp.text().await.unwrap_or_default();
        let (code, message) = match serde_json::from_str::<ErrorResponse>(&text) {
            Ok(e) => (e.error, e.message),
            Err(_) => ("http_error".to_string(), format!("server returned HTTP {}", status.as_u16())),
        };
        Err(Error::Api { status: status.as_u16(), code, message })
    }

    /// Pair with the account behind a code: the proof is
    /// `agent_remote::seal_proof`.
    pub async fn pair(&self, req: &PairAgentRequest) -> Result<PairAgentResponse> {
        self.signed(Method::POST, "/agent/pair", serde_json::to_vec(req).map_err(|e| Error::Protocol(e.to_string()))?)
            .await
    }

    /// Post a sealed request (`agent_remote::seal_request`).
    pub async fn post_request(&self, req: &PostAgentRequest) -> Result<PostAgentRequestResponse> {
        let body = serde_json::to_vec(req).map_err(|e| Error::Protocol(e.to_string()))?;
        self.signed(Method::POST, "/agent/requests", body).await
    }

    /// What became of a request; with `wait` seconds the server holds the
    /// call until the owner answers. An answer is handed out once.
    pub async fn request_status(&self, request_id: &str, wait: u32) -> Result<AgentRequestStatus> {
        self.signed(Method::GET, &format!("/agent/requests/{request_id}?wait={wait}"), Vec::new()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_only_on_this_device() {
        for ok in ["https://vault.example.com", "http://localhost:8743", "http://127.0.0.1:8743", "http://[::1]:8743"] {
            assert!(secure_server_url(ok), "{ok}");
        }
        for bad in
            ["http://vault.example.com", "http://192.168.1.10:8743", "http://127.0.0.1.example.com", "ftp://x.com", ""]
        {
            assert!(!secure_server_url(bad), "{bad}");
        }
        assert!(secure_server_url(&normalize_server_url("vault.example.com")));
        assert!(secure_server_url(&normalize_server_url("localhost:8743")));
    }
}
