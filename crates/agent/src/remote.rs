//! `2secret mcp --remote`: the agent runs on another computer than the
//! owner's 2Secret (a cloud agent, a build server, a second machine) and
//! reaches the owner's apps through the sync server, which relays sealed
//! envelopes it cannot read (`twosecret_core::agent_remote`).
//!
//! Pairing (`2secret agent pair <code>`) makes the agent's keys from a
//! random root, checks the account's public keys against the hash in the
//! code, proves the code's secret to the account and stores
//! `remote-<name>.json` in the data directory (readable only by the user):
//! the server, the account's keys and the root. The owner then confirms the
//! agent in 2Secret, where the same fingerprint is shown.
//!
//! [`RemoteBackend`] is the third backend of the MCP server, next to the
//! local app and the standalone vault: every tool call becomes a signed,
//! sealed request; the owner answers in any unlocked 2Secret; the answer
//! comes back encrypted with the reply key from the request. `fill_login`
//! is done here, through the browser's debugging port ([`crate::cdp`]):
//! the login never reaches the model.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use twosecret_client::{AgentClient, Client};
use twosecret_core::agent::{AgentError, FillCommand, FillOutcome, FillResult};
use twosecret_core::agent_remote::{self, PairingCode, RemoteKeys, MAX_WAIT_SECONDS, REQUEST_SECONDS};
use twosecret_core::api::{AgentRequestState, PairAgentRequest, PostAgentRequest};
use twosecret_core::crypto::AccountPublicKeys;
use twosecret_core::util::{b64, now, unb64, url_host};
use zeroize::Zeroizing;

use crate::cdp::{self, CdpError};
use crate::key::slug;
use crate::tools::Backend;

/// `remote-<name>.json`: one file per pairing.
pub const FILE_PREFIX: &str = "remote-";

/// What the model is told at `initialize` when it works through the relay.
pub const INSTRUCTIONS: &str = "2Secret is the user's password manager; this connection reaches it through the \
    user's sync server, because 2Secret runs on another computer. search_items and get_item show what exists \
    without secrets. read_field and get_otp hand a secret to you after the user approves it in the 2Secret app \
    on any of their devices (computer or phone); use them only when you really need the value yourself. When a \
    program needs a secret, use run_command with environment variables set to 2s:// references instead: the \
    program gets the value, you do not. To sign in on a website in the browser on this computer, use fill_login: \
    2Secret fills and submits the sign-in page through the browser's debugging port, and you never see the \
    password. Every request waits for the user's answer for up to ten minutes; if a call fails because 2Secret \
    is locked or the user did not answer, tell the user.";

#[derive(Serialize, Deserialize)]
struct StoredAccount {
    x25519: String,
    ml_kem: String,
    fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    server: String,
    name: String,
    agent_id: String,
    account: StoredAccount,
    /// The 32-byte root of the agent's keys (base64).
    root: String,
}

/// A pairing with an account: what `remote-<name>.json` holds.
pub struct Pairing {
    pub server: String,
    /// How the owner knows this agent, and the file's name.
    pub name: String,
    pub agent_id: String,
    pub account: AccountPublicKeys,
    pub account_fingerprint: String,
    root: Zeroizing<[u8; 32]>,
}

impl Pairing {
    pub fn path(home: &Path, name: &str) -> PathBuf {
        home.join(format!("{FILE_PREFIX}{}.json", slug(name)))
    }

    pub fn load(home: &Path, name: &str) -> Option<Self> {
        Self::parse(&std::fs::read_to_string(Self::path(home, name)).ok()?)
    }

    /// Every pairing in `home`: the file's slug and the pairing.
    pub fn list(home: &Path) -> Vec<(String, Pairing)> {
        let Ok(entries) = std::fs::read_dir(home) else { return Vec::new() };
        let mut out: Vec<(String, Pairing)> = entries
            .flatten()
            .filter_map(|e| {
                let file = e.file_name().to_string_lossy().into_owned();
                let slug = file.strip_prefix(FILE_PREFIX)?.strip_suffix(".json")?.to_string();
                Some((slug, Self::parse(&std::fs::read_to_string(e.path()).ok()?)?))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The pairing to use: the one called `name`, or the only one there is.
    pub fn choose(home: &Path, name: Option<&str>) -> Result<Pairing, RemoteError> {
        match name.map(str::trim).filter(|n| !n.is_empty()) {
            Some(name) => Self::load(home, name).ok_or_else(|| RemoteError::NotPaired(Some(name.to_string()))),
            None => {
                let mut all = Self::list(home);
                match all.len() {
                    1 => Ok(all.remove(0).1),
                    0 => Err(RemoteError::NotPaired(None)),
                    _ => Err(RemoteError::Ambiguous(all.into_iter().map(|(s, _)| s).collect())),
                }
            }
        }
    }

    /// Forget a pairing on this computer; `false` when there was none.
    pub fn remove(home: &Path, name: &str) -> io::Result<bool> {
        match std::fs::remove_file(Self::path(home, name)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn parse(text: &str) -> Option<Self> {
        let stored: Stored = serde_json::from_str(text).ok()?;
        if stored.version != 1 {
            return None;
        }
        let root: [u8; 32] = Zeroizing::new(unb64(&stored.root).ok()?).as_slice().try_into().ok()?;
        let account = AccountPublicKeys::from_b64(&stored.account.x25519, Some(&stored.account.ml_kem)).ok()?;
        Some(Self {
            server: stored.server,
            name: stored.name,
            agent_id: stored.agent_id,
            account_fingerprint: stored.account.fingerprint,
            account,
            root: Zeroizing::new(root),
        })
    }

    fn save(&self, home: &Path) -> io::Result<()> {
        std::fs::create_dir_all(home)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700));
        }
        let stored = Stored {
            version: 1,
            server: self.server.clone(),
            name: self.name.clone(),
            agent_id: self.agent_id.clone(),
            account: StoredAccount {
                x25519: self.account.x25519.to_b64(),
                ml_kem: self.account.ml_kem.as_ref().map(|k| k.to_b64()).unwrap_or_default(),
                fingerprint: self.account_fingerprint.clone(),
            },
            root: b64(&*self.root),
        };
        let json = Zeroizing::new(serde_json::to_string_pretty(&stored)?);
        write_private(&Self::path(home, &self.name), json.as_bytes())
    }

    pub fn keys(&self) -> RemoteKeys {
        RemoteKeys::from_root(*self.root)
    }

    /// The agent's fingerprint, as 2Secret shows it when confirming.
    pub fn fingerprint(&self) -> String {
        self.keys().fingerprint()
    }

    pub fn client(&self) -> AgentClient {
        AgentClient::new(&self.server, self.keys())
    }
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

/// This computer's name, for the owner to recognise the agent.
pub fn device_name() -> Option<String> {
    let from_env = std::env::var("HOSTNAME").ok().or_else(|| std::env::var("COMPUTERNAME").ok());
    let name = from_env.or_else(|| std::fs::read_to_string("/etc/hostname").ok()).or_else(|| {
        let out = std::process::Command::new("hostname").output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    })?;
    let name = name.trim().trim_end_matches(".local").to_string();
    (!name.is_empty()).then_some(name)
}

/// What went wrong on the agent's side; the text is for the model.
#[derive(Debug)]
pub enum RemoteError {
    /// No pairing (with this name) on this computer.
    NotPaired(Option<String>),
    /// Several pairings and none named.
    Ambiguous(Vec<String>),
    /// The owner revoked the agent.
    Revoked,
    /// The owner has not confirmed the agent yet.
    NotConfirmed,
    /// The owner said no.
    Denied,
    /// Nobody answered before the request expired.
    Timeout,
    /// The owner's 2Secret refused or failed the request.
    Rpc(AgentError),
    /// The server, or the connection to it.
    Server(twosecret_client::Error),
    Protocol(String),
    /// `fill_login` without a debugging port.
    NoCdp,
    Cdp(CdpError),
    Io(io::Error),
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoteError::NotPaired(Some(name)) => write!(
                f,
                "no pairing called '{name}' on this computer. In 2Secret: Settings → Agents elsewhere → Pair an agent, \
                 then run `2secret agent pair <code> --name {name}` here."
            ),
            RemoteError::NotPaired(None) => write!(
                f,
                "this computer is not paired with a 2Secret account. In 2Secret: Settings → Agents elsewhere → Pair an \
                 agent, then run `2secret agent pair <code>` here."
            ),
            RemoteError::Ambiguous(names) => {
                write!(f, "several pairings on this computer; name one with --remote <name>: {}", names.join(", "))
            }
            RemoteError::Revoked => {
                write!(f, "the owner revoked this agent in 2Secret. Pair again with a new code (2secret agent pair).")
            }
            RemoteError::NotConfirmed => write!(
                f,
                "the owner has not confirmed this agent in 2Secret yet (Settings → Agents elsewhere). The pairing \
                 dialog there shows the fingerprint of this agent (see 2secret agent status)."
            ),
            RemoteError::Denied => write!(f, "The user did not allow this in 2Secret."),
            RemoteError::Timeout => write!(
                f,
                "The user did not answer 2Secret's question in time: no unlocked 2Secret of theirs saw it, or they \
                 did not decide. Ask the user to open 2Secret and try again."
            ),
            RemoteError::Rpc(e) => f.write_str(&rpc_text(e)),
            RemoteError::Server(e) => write!(f, "could not reach the 2Secret server: {e}"),
            RemoteError::Protocol(m) => write!(f, "unexpected answer from the 2Secret server: {m}"),
            RemoteError::NoCdp => write!(
                f,
                "fill_login needs the browser's debugging port: start the browser on this computer with \
                 --remote-debugging-port=9222 and 2secret mcp --remote with --cdp 127.0.0.1:9222."
            ),
            RemoteError::Cdp(e) => write!(f, "{e}"),
            RemoteError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RemoteError {}

impl From<twosecret_core::Error> for RemoteError {
    fn from(e: twosecret_core::Error) -> Self {
        RemoteError::Protocol(e.to_string())
    }
}

impl From<io::Error> for RemoteError {
    fn from(e: io::Error) -> Self {
        RemoteError::Io(e)
    }
}

impl From<CdpError> for RemoteError {
    fn from(e: CdpError) -> Self {
        RemoteError::Cdp(e)
    }
}

impl From<serde_json::Error> for RemoteError {
    fn from(e: serde_json::Error) -> Self {
        RemoteError::Protocol(e.to_string())
    }
}

/// A server error as the agent should read it.
fn server_error(e: twosecret_client::Error) -> RemoteError {
    match &e {
        twosecret_client::Error::Api { code, .. } if code == "agent_revoked" => RemoteError::Revoked,
        twosecret_client::Error::Api { code, .. } if code == "agent_not_confirmed" => RemoteError::NotConfirmed,
        twosecret_client::Error::Api { code, .. } if code == "agent_signature" => RemoteError::Protocol(
            "the server did not accept this agent's signature: the pairing is gone (pair again), or this \
             computer's clock is off by more than five minutes"
                .into(),
        ),
        _ => RemoteError::Server(e),
    }
}

/// A message for the model about an error the owner's 2Secret returned.
pub fn rpc_text(e: &AgentError) -> String {
    match e.code {
        AgentError::DENIED => "The user did not allow this in 2Secret.".to_string(),
        AgentError::TIMEOUT => "The user did not answer 2Secret's question in time.".to_string(),
        AgentError::LOCKED => "2Secret is locked. Ask the user to unlock it, then try again.".to_string(),
        AgentError::OFF => "Agent Access is turned off in 2Secret (Settings → Desktop app → AI agents).".to_string(),
        AgentError::NOT_CONFIRMED => {
            "The owner has not confirmed this agent in 2Secret yet (Settings → Agents elsewhere).".to_string()
        }
        _ => e.message.clone(),
    }
}

fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()
}

/// What `2secret agent pair` reports.
#[derive(Clone, Debug, Serialize)]
pub struct Paired {
    pub name: String,
    pub server: String,
    pub agent_id: String,
    /// This agent's fingerprint; 2Secret shows the same one when confirming.
    pub fingerprint: String,
    pub account_fingerprint: String,
    /// Until when the owner can confirm.
    pub expires_at: i64,
}

/// Pair this computer with the account behind `code`, as `name`. New keys
/// for every pairing; the file replaces an earlier pairing of that name.
pub fn pair(home: &Path, name: &str, code: &PairingCode, version: &str) -> Result<Paired, RemoteError> {
    let rt = runtime()?;
    let keys = RemoteKeys::generate();
    let root = *keys.root();
    let info = rt.block_on(Client::new(&code.server).agent_pairing_info(&code.token())).map_err(server_error)?;
    let account = AccountPublicKeys::from_b64(&info.x25519, Some(&info.ml_kem))?;
    if !code.matches(&account) {
        return Err(RemoteError::Protocol(
            "the server's keys for this account are not the ones the pairing code was made for".into(),
        ));
    }
    let device = device_name();
    let proof = agent_remote::seal_proof(code, &account, &keys, name, version, device.as_deref())?;
    let client = AgentClient::new(&code.server, keys);
    let request = PairAgentRequest { token: code.token(), keys: client.keys().public(), proof };
    let answer = rt.block_on(client.pair(&request)).map_err(server_error)?;
    let pairing = Pairing {
        server: code.server.clone(),
        name: name.to_string(),
        agent_id: answer.agent_id.clone(),
        account_fingerprint: account.fingerprint(),
        account,
        root: Zeroizing::new(root),
    };
    pairing.save(home)?;
    Ok(Paired {
        name: name.to_string(),
        server: pairing.server.clone(),
        agent_id: answer.agent_id,
        fingerprint: pairing.fingerprint(),
        account_fingerprint: pairing.account_fingerprint.clone(),
        expires_at: answer.expires_at,
    })
}

/// The MCP backend that works through the relay.
pub struct RemoteBackend {
    home: PathBuf,
    name: Option<String>,
    /// The browser's debugging port for `fill_login`.
    cdp: Option<String>,
    rt: tokio::runtime::Runtime,
    connected: Option<(Pairing, AgentClient)>,
}

impl RemoteBackend {
    pub fn new(home: PathBuf, name: Option<String>, cdp: Option<String>) -> io::Result<Self> {
        Ok(Self { home, name, cdp: cdp.filter(|c| !c.trim().is_empty()), rt: runtime()?, connected: None })
    }

    fn connect(&mut self) -> Result<&(Pairing, AgentClient), RemoteError> {
        if self.connected.is_none() {
            let pairing = Pairing::choose(&self.home, self.name.as_deref())?;
            let client = pairing.client();
            self.connected = Some((pairing, client));
        }
        Ok(self.connected.as_ref().expect("connected"))
    }

    /// One request through the relay: sealed, posted, waited for, opened.
    pub fn request(&mut self, method: &str, params: Value) -> Result<Value, RemoteError> {
        self.connect()?;
        let (pairing, client) = self.connected.as_ref().expect("connected");
        let sealed = agent_remote::seal_request(client.keys(), &pairing.account, method, params, now())?;
        let post = PostAgentRequest { id: sealed.id.clone(), request: sealed.request.clone() };
        let answer = self.rt.block_on(async {
            client.post_request(&post).await.map_err(server_error)?;
            let deadline = Instant::now() + Duration::from_secs(REQUEST_SECONDS as u64 + 30);
            loop {
                let status = match client.request_status(&sealed.id, MAX_WAIT_SECONDS).await {
                    Ok(status) => status,
                    // Expired and cleaned up.
                    Err(e) if e.is_not_found() => return Err(RemoteError::Timeout),
                    Err(e) => return Err(server_error(e)),
                };
                match status.status {
                    AgentRequestState::Open if Instant::now() > deadline => return Err(RemoteError::Timeout),
                    AgentRequestState::Open => {}
                    AgentRequestState::Answered => {
                        return status.answer.ok_or_else(|| RemoteError::Protocol("the answer is missing".into()));
                    }
                    AgentRequestState::Denied => return Err(RemoteError::Denied),
                    AgentRequestState::Expired => return Err(RemoteError::Timeout),
                }
            }
        })?;
        let result = agent_remote::open_answer(&sealed.reply_key, &sealed.id, &answer)?;
        result.map_err(RemoteError::Rpc)
    }

    /// The owner allowed a fill: the app sent the login; fill it into the
    /// browser on this computer. The model only hears how it went.
    pub fn fill_login(&self, login: Value) -> Result<Value, RemoteError> {
        let command: FillCommand = serde_json::from_value(login)?;
        let Some(endpoint) = &self.cdp else {
            return Err(RemoteError::NoCdp);
        };
        let host = url_host(&command.url).unwrap_or_else(|| command.url.clone());
        let done = self.rt.block_on(cdp::fill(endpoint, &command))?;
        match done.outcome {
            FillOutcome::Filled => {
                Ok(serde_json::to_value(FillResult { filled: true, browser: done.browser, submitted: done.submitted })?)
            }
            outcome => Err(RemoteError::Rpc(AgentError::fill_failed(outcome, &host, &done.browser))),
        }
    }

    /// For `agent_status`.
    pub fn status_value(&mut self) -> Value {
        let cdp = self.cdp.clone();
        let browser = match &cdp {
            Some(endpoint) => match self.rt.block_on(cdp::browser(endpoint)) {
                Ok(b) => json!({ "endpoint": endpoint, "reachable": true, "browser": b }),
                Err(e) => json!({ "endpoint": endpoint, "reachable": false, "error": e.to_string() }),
            },
            None => Value::Null,
        };
        match self.connect() {
            Ok((pairing, _)) => json!({
                "mode": "remote",
                "paired": true,
                "pairing": pairing.name,
                "server": pairing.server,
                "agent_id": pairing.agent_id,
                "fingerprint": pairing.fingerprint(),
                "account_fingerprint": pairing.account_fingerprint,
                "cdp": browser,
            }),
            Err(e) => json!({ "mode": "remote", "paired": false, "error": e.to_string(), "cdp": browser }),
        }
    }
}

impl Backend for RemoteBackend {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let value = self.request(method, params).map_err(|e| e.to_string())?;
        if method == "fill" {
            return self.fill_login(value).map_err(|e| e.to_string());
        }
        Ok(value)
    }

    fn status(&mut self) -> Value {
        self.status_value()
    }

    fn may_run(&self) -> bool {
        true
    }

    fn instructions(&self) -> &'static str {
        INSTRUCTIONS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_file_roundtrip() {
        let home = std::env::temp_dir().join(format!("2secret-remote-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let keyset = twosecret_core::crypto::Keyset::generate();
        let account = keyset.public_keys();
        let keys = RemoteKeys::generate();
        let pairing = Pairing {
            server: "https://sync.example".into(),
            name: "Build server".into(),
            agent_id: keys.agent_id(),
            account_fingerprint: account.fingerprint(),
            account: account.clone(),
            root: Zeroizing::new(*keys.root()),
        };
        pairing.save(&home).unwrap();
        assert!(Pairing::path(&home, "Build server").ends_with("remote-build-server.json"));
        let back = Pairing::choose(&home, None).unwrap();
        assert_eq!(back.agent_id, keys.agent_id());
        assert_eq!(back.fingerprint(), keys.fingerprint());
        assert_eq!(back.account, account);
        assert_eq!(Pairing::list(&home).len(), 1);
        assert!(matches!(Pairing::choose(&home, Some("other")), Err(RemoteError::NotPaired(Some(_)))));
        let second = Pairing { name: "Laptop".into(), ..Pairing::choose(&home, Some("Build server")).unwrap() };
        second.save(&home).unwrap();
        assert!(matches!(Pairing::choose(&home, None), Err(RemoteError::Ambiguous(_))));
        assert!(Pairing::remove(&home, "Laptop").unwrap());
        assert!(!Pairing::remove(&home, "Laptop").unwrap());
        assert_eq!(Pairing::list(&home).len(), 1);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn errors_read_well() {
        assert!(RemoteError::NotPaired(None).to_string().contains("2secret agent pair"));
        assert!(RemoteError::NoCdp.to_string().contains("--remote-debugging-port"));
        assert!(rpc_text(&AgentError::locked()).contains("locked"));
    }
}
