//! Agent Access: AI agents (Claude Code, Cursor, Codex, any MCP client) and
//! other programs use the vault through the running desktop app, which asks
//! the user before it hands out a secret.
//!
//! This module holds everything that does not touch a socket or a window:
//!
//! - the wire protocol between an agent and the app (JSON-RPC 2.0, one
//!   object per line): [`Request`], the parameter and result types, and
//!   [`AgentError`];
//! - the agent's identity: an Ed25519 key it proves with a signature over a
//!   nonce ([`hello_challenge`], [`verify_hello`]); its id is the key's
//!   fingerprint;
//! - what the app shows the user and remembers: [`Ask`], [`Decision`],
//!   the encrypted [`AgentStore`] with paired agents, grants and the log;
//! - [`execute`]: the requests run against the unlocked [`Session`].
//!
//! Nothing here reveals a secret without a request that asks for it by
//! name: [`AgentItem`] (what `search` and `item` return) carries no values
//! of concealed or one-time password fields and no notes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{decrypt_json, encrypt_json, fingerprint_of, sha256, EncString, SymmetricKey};
use crate::generator::{GeneratorKind, GeneratorOptions};
use crate::item::{Category, Field, FieldKind, Item};
use crate::secret_ref::{self, SecretRef};
use crate::session::{ItemFilter, Session};
use crate::totp::Totp;
use crate::util::{b64, fill_rules, now, unb64, url_host, url_matches, FillRule};
use crate::{Error, Result};

/// Version of the socket protocol.
pub const PROTOCOL: u32 = 1;
/// Longest line (one JSON-RPC message) the app reads.
pub const MAX_LINE: usize = 1024 * 1024;
/// Longest agent name shown to the user.
pub const NAME_MAX: usize = 80;
/// Longest reason an agent may give for a request.
pub const REASON_MAX: usize = 200;
/// How long "allow for a while" lasts.
pub const GRANT_HOURS: u32 = 8;
/// Most items a search returns.
pub const SEARCH_LIMIT: usize = 100;
/// Log entries kept.
pub const MAX_LOG: usize = 1000;

const HELLO_CONTEXT: &[u8] = b"2secret/agent/v1/hello";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A JSON-RPC error: the code says what went wrong, the message is for
/// people (and for the model that reads the tool result).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentError {
    pub code: i64,
    pub message: String,
}

impl AgentError {
    /// The user said no, or an existing grant did not cover the request.
    pub const DENIED: i64 = -32001;
    /// The user did not answer in time.
    pub const TIMEOUT: i64 = -32002;
    /// The vault is locked and was not unlocked in time.
    pub const LOCKED: i64 = -32003;
    pub const NOT_FOUND: i64 = -32004;
    /// The agent has to connect (`hello` and `auth`) first.
    pub const NOT_PAIRED: i64 = -32005;
    /// Agent Access is turned off in the app.
    pub const OFF: i64 = -32006;
    /// No browser with the 2Secret extension is connected to the app.
    pub const NO_BROWSER: i64 = -32007;
    /// The browser could not fill: no matching tab, or no fields on the page.
    pub const FILL_FAILED: i64 = -32008;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL: i64 = -32603;

    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
    pub fn denied() -> Self {
        Self::new(Self::DENIED, "the user did not allow this")
    }
    pub fn timeout() -> Self {
        Self::new(Self::TIMEOUT, "the user did not answer in time")
    }
    pub fn locked() -> Self {
        Self::new(Self::LOCKED, "2Secret is locked; unlock it and try again")
    }
    pub fn not_paired() -> Self {
        Self::new(Self::NOT_PAIRED, "connect first (hello, then auth)")
    }
    pub fn off() -> Self {
        Self::new(Self::OFF, "Agent Access is turned off in 2Secret (Settings → Desktop app)")
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Self::INVALID_PARAMS, message)
    }
    pub fn no_browser() -> Self {
        Self::new(
            Self::NO_BROWSER,
            "no browser is connected to 2Secret: open a browser with the 2Secret extension and set up the \
             browser connection under Settings → Desktop app → Browser connection",
        )
    }
    /// Why a fill did not happen, for the agent: `host` is the website,
    /// `browser` the browser (or browsers) that looked.
    pub fn fill_failed(outcome: FillOutcome, host: &str, browser: &str) -> Self {
        let message = match outcome {
            FillOutcome::NoTab => {
                format!("no open tab for {host} in {browser}: open the sign-in page and make it the active tab")
            }
            FillOutcome::Nothing => {
                format!("nothing to fill on the {host} page in {browser}: no user name, password or code field")
            }
            FillOutcome::Filled => format!("the login was filled on {host} in {browser}"),
        };
        Self::new(Self::FILL_FAILED, message)
    }
    pub fn method_not_found(method: &str) -> Self {
        Self::new(Self::METHOD_NOT_FOUND, format!("unknown method '{method}'"))
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for AgentError {}

impl From<Error> for AgentError {
    fn from(e: Error) -> Self {
        let code = match &e {
            Error::NotFound(_) => Self::NOT_FOUND,
            Error::Invalid(_) | Error::Unsupported(_) => Self::INVALID_PARAMS,
            Error::PermissionDenied(_) => Self::DENIED,
            _ => Self::INTERNAL,
        };
        Self::new(code, e.to_string())
    }
}

impl From<serde_json::Error> for AgentError {
    fn from(e: serde_json::Error) -> Self {
        Self::invalid(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The id of an agent: the fingerprint of its Ed25519 public key, in the
/// style of the account fingerprints (`3F9A-77C1-0B2E-91D4`).
pub fn agent_id(public_key: &[u8]) -> String {
    fingerprint_of(&sha256(public_key))
}

/// What an agent signs to prove it holds the key it announced in `hello`.
pub fn hello_challenge(nonce: &[u8]) -> Vec<u8> {
    let mut out = HELLO_CONTEXT.to_vec();
    out.extend_from_slice(nonce);
    out
}

/// Check the signature from `auth` against the key from `hello`; returns
/// the agent id.
pub fn verify_hello(public_key_b64: &str, nonce: &[u8], signature_b64: &str) -> Result<String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let key: [u8; 32] =
        unb64(public_key_b64)?.try_into().map_err(|_| Error::invalid("the agent key is not an Ed25519 public key"))?;
    let sig: [u8; 64] =
        unb64(signature_b64)?.try_into().map_err(|_| Error::invalid("the signature has the wrong length"))?;
    let key =
        VerifyingKey::from_bytes(&key).map_err(|_| Error::invalid("the agent key is not an Ed25519 public key"))?;
    key.verify_strict(&hello_challenge(nonce), &Signature::from_bytes(&sig))
        .map_err(|_| Error::PermissionDenied("the signature does not match the agent key".into()))?;
    Ok(agent_id(&key.to_bytes()))
}

/// A string as the user sees it: no control, direction or zero-width
/// characters (which could make an agent's name or reason look like a line
/// of 2Secret itself), trimmed, at most `max` characters.
pub fn clean_label(s: &str, max: usize) -> String {
    let invisible = |c: char| {
        c.is_control()
            || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
    };
    s.chars().filter(|c| !invisible(*c)).collect::<String>().trim().chars().take(max).collect()
}

/// What connects to the app: an AI agent (through `2secret mcp`) or the
/// 2Secret extension in a browser (through the app's own native messaging
/// host). A browser connection never reads the vault; it only receives the
/// logins the user allowed an agent to fill, and reports the outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[default]
    Agent,
    Browser,
}

/// Who asks, as far as the app can tell. `name`, `version` and
/// `claimed_parent` are what the agent said about itself; `exe` and
/// `parent` are what the operating system reports about the process on the
/// other end of the socket and the process that started it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Fingerprint of the agent's key.
    pub id: String,
    pub name: String,
    pub version: String,
    /// Ed25519 public key (base64).
    pub public_key: String,
    #[serde(default)]
    pub role: Role,
    /// For a browser connection: `chrome`, `firefox`, ... (cleaned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    /// Path of the program on the other end, verified by the OS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// Name or path of the program that started it (the AI client), verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The parent as the agent itself claims it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_parent: Option<String>,
}

impl AgentIdentity {
    /// Builds the identity from a verified `hello`; cleans what the agent said.
    pub fn new(id: &str, hello: &HelloParams, exe: Option<String>, parent: Option<String>) -> Self {
        let name = clean_label(&hello.name, NAME_MAX);
        let browser = hello.browser.as_deref().map(browser_name).filter(|b| !b.is_empty());
        let fallback = match (hello.role, &browser) {
            (Role::Browser, Some(b)) => format!("{} extension", browser_label(b)),
            (Role::Browser, None) => "Browser extension".to_string(),
            (Role::Agent, _) => "An AI agent".to_string(),
        };
        Self {
            id: id.to_string(),
            name: if name.is_empty() { fallback } else { name },
            version: clean_label(&hello.version, 40),
            public_key: hello.agent_key.clone(),
            role: hello.role,
            browser,
            exe,
            parent,
            claimed_parent: hello.parent.as_deref().map(|p| clean_label(p, NAME_MAX)).filter(|p| !p.is_empty()),
        }
    }

    /// `Claude Code (via 2secret mcp)`: the name, and the program when it is
    /// known and says something more. A browser connection is shown as
    /// `Chrome extension`: its program is 2Secret itself.
    pub fn display(&self) -> String {
        if self.role == Role::Browser {
            return match &self.browser {
                Some(b) => format!("{} extension", browser_label(b)),
                None => self.name.clone(),
            };
        }
        let program = self.exe.as_deref().map(file_name).filter(|p| !p.eq_ignore_ascii_case(&self.name));
        match (program, self.parent.as_deref().map(file_name)) {
            (Some(p), Some(parent)) if !parent.eq_ignore_ascii_case(&self.name) => {
                format!("{} ({parent}, via {p})", self.name)
            }
            (Some(p), _) => format!("{} (via {p})", self.name),
            _ => self.name.clone(),
        }
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// A browser name as the protocol carries it: lowercase letters, digits
/// and dashes (`chrome`, `firefox`, `edge`, `brave`, ...), at most 20.
pub fn browser_name(raw: &str) -> String {
    let mut out: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    out.truncate(20);
    out
}

/// The browser name as the user sees it: `chrome` → `Chrome`, `edge` → `Microsoft Edge`.
pub fn browser_label(name: &str) -> String {
    match name {
        "chrome" => "Chrome".to_string(),
        "chromium" => "Chromium".to_string(),
        "edge" => "Microsoft Edge".to_string(),
        "brave" => "Brave".to_string(),
        "firefox" => "Firefox".to_string(),
        "vivaldi" => "Vivaldi".to_string(),
        "arc" => "Arc".to_string(),
        "opera" => "Opera".to_string(),
        "safari" => "Safari".to_string(),
        other => {
            let mut c = other.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloParams {
    pub protocol: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    /// Ed25519 public key (base64).
    pub agent_key: String,
    /// The AI client the agent serves, as it sees it.
    #[serde(default)]
    pub parent: Option<String>,
    /// An AI agent (default) or the browser extension.
    #[serde(default)]
    pub role: Role,
    /// For a browser connection: which browser (`chrome`, `firefox`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    /// For a browser connection: the extension's origin or id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloResult {
    pub protocol: u32,
    pub app_version: String,
    /// 32 random bytes (base64) to sign in `auth`.
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthParams {
    /// Ed25519 signature (base64) over [`hello_challenge`] of the nonce.
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResult {
    pub agent_id: String,
    /// `paired`
    pub state: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SearchParams {
    /// Words in the title, user name, website or tags.
    pub query: Option<String>,
    /// Only items for this website (matched like autofill does).
    pub url: Option<String>,
    /// Vault name or id.
    pub vault: Option<String>,
    pub category: Option<Category>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemParams {
    /// Item id, exact title or a `2s://` reference.
    pub item: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadParams {
    /// Item id, exact title or a `2s://` reference (then `field` may be left out).
    pub item: String,
    /// Field id or label, or `username`, `password`, `otp`, `url`, `notes`, `title`.
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadManyParams {
    /// `2s://` references.
    pub refs: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GenerateParams {
    /// Characters of a random password (default 20).
    pub length: Option<usize>,
    /// Words of a memorable passphrase instead.
    pub words: Option<usize>,
    /// Digits of a PIN instead.
    pub pin: Option<usize>,
    pub symbols: Option<bool>,
    pub digits: Option<bool>,
    pub uppercase: Option<bool>,
    pub lowercase: Option<bool>,
    pub avoid_ambiguous: Option<bool>,
}

impl GenerateParams {
    pub fn options(&self) -> GeneratorOptions {
        let mut o = GeneratorOptions::default();
        if let Some(n) = self.pin {
            o.kind = GeneratorKind::Pin;
            o.pin_length = n;
        } else if let Some(n) = self.words {
            o.kind = GeneratorKind::Memorable;
            o.words = n;
        } else {
            o.kind = GeneratorKind::Random;
            if let Some(n) = self.length {
                o.length = n;
            }
        }
        if let Some(v) = self.symbols {
            o.symbols = v;
        }
        if let Some(v) = self.digits {
            o.digits = v;
        }
        if let Some(v) = self.uppercase {
            o.uppercase = v;
        }
        if let Some(v) = self.lowercase {
            o.lowercase = v;
        }
        if let Some(v) = self.avoid_ambiguous {
            o.avoid_ambiguous = v;
        }
        o
    }
}

/// A field an agent sets when creating or changing an item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewField {
    pub label: String,
    pub value: String,
    /// Concealed, like a password.
    #[serde(default)]
    pub secret: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CreateParams {
    /// Vault name or id; the default vault when left out.
    pub vault: Option<String>,
    /// `login` when left out.
    pub category: Option<Category>,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Generate the password instead of giving one.
    pub generate: bool,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub fields: Vec<NewField>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SetFields {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateParams {
    pub item: String,
    pub set: SetFields,
    pub add_urls: Vec<String>,
    pub fields: Vec<NewField>,
    pub reason: Option<String>,
}

/// `fill`: fill a login in the user's browser (the agent never sees it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillParams {
    /// Item id, exact title or a `2s://` reference.
    pub item: String,
    /// The page to fill; the item's first website when left out. The item
    /// has to be a login for this website.
    #[serde(default)]
    pub url: Option<String>,
    /// Submit the form after filling (default true).
    #[serde(default)]
    pub submit: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// What the browser extension fills, after the user allowed it. Secrets are
/// wiped when it is dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FillCommand {
    #[zeroize(skip)]
    pub id: String,
    /// The page the agent named (the extension only fills tabs whose
    /// address matches `rules`, which come from the item).
    #[zeroize(skip)]
    pub url: String,
    #[zeroize(skip)]
    pub rules: Vec<FillRule>,
    pub username: String,
    pub password: String,
    /// The current one-time code, or empty.
    pub code: String,
    #[zeroize(skip)]
    pub submit: bool,
}

/// `browser.wait`: a fill for this browser, or nothing yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitResult {
    pub job: Option<FillCommand>,
}

/// What the extension reports after a fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillOutcome {
    Filled,
    /// No active tab for the item's website in this browser.
    NoTab,
    /// A matching tab, but no field to fill on the page.
    Nothing,
}

/// `browser.result`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillOutcomeParams {
    pub id: String,
    pub outcome: FillOutcome,
    #[serde(default)]
    pub submitted: bool,
}

/// What the agent gets back from `fill`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillResult {
    pub filled: bool,
    /// The browser that filled (`chrome`, `firefox`, ...).
    pub browser: String,
    pub submitted: bool,
}

/// A browser connected to the app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserInfo {
    pub browser: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    pub version: String,
    /// Connected since (Unix seconds).
    pub since: i64,
}

/// `status`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    pub app_version: String,
    pub browsers: Vec<BrowserInfo>,
}

/// A request after `hello` and `auth`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Search(SearchParams),
    Item(ItemParams),
    Read(ReadParams),
    ReadMany(ReadManyParams),
    Otp(ItemParams),
    Generate(GenerateParams),
    CreateItem(CreateParams),
    UpdateItem(UpdateParams),
    /// Fill a login in the user's browser (agents).
    Fill(FillParams),
    /// Wait for a login to fill (browsers).
    BrowserWait,
    /// Report how a fill went (browsers).
    BrowserResult(FillOutcomeParams),
    /// The app version and the connected browsers.
    Status,
    Grants,
    Ping,
}

impl Request {
    /// The JSON-RPC method names.
    pub const METHODS: [&'static str; 14] = [
        "search",
        "item",
        "read",
        "read_many",
        "otp",
        "generate",
        "create_item",
        "update_item",
        "fill",
        "browser.wait",
        "browser.result",
        "status",
        "grants",
        "ping",
    ];

    pub fn parse(method: &str, params: Option<Value>) -> std::result::Result<Request, AgentError> {
        fn take<T: for<'de> Deserialize<'de>>(params: Option<Value>) -> std::result::Result<T, AgentError> {
            Ok(serde_json::from_value(params.unwrap_or(Value::Object(Default::default())))?)
        }
        Ok(match method {
            "search" => Request::Search(take(params)?),
            "item" => Request::Item(take(params)?),
            "read" => Request::Read(take(params)?),
            "read_many" => Request::ReadMany(take(params)?),
            "otp" => Request::Otp(take(params)?),
            "generate" => Request::Generate(take(params)?),
            "create_item" => Request::CreateItem(take(params)?),
            "update_item" => Request::UpdateItem(take(params)?),
            "fill" => Request::Fill(take(params)?),
            "browser.wait" => Request::BrowserWait,
            "browser.result" => Request::BrowserResult(take(params)?),
            "status" => Request::Status,
            "grants" => Request::Grants,
            "ping" => Request::Ping,
            other => return Err(AgentError::method_not_found(other)),
        })
    }

    pub fn method(&self) -> &'static str {
        match self {
            Request::Search(_) => "search",
            Request::Item(_) => "item",
            Request::Read(_) => "read",
            Request::ReadMany(_) => "read_many",
            Request::Otp(_) => "otp",
            Request::Generate(_) => "generate",
            Request::CreateItem(_) => "create_item",
            Request::UpdateItem(_) => "update_item",
            Request::Fill(_) => "fill",
            Request::BrowserWait => "browser.wait",
            Request::BrowserResult(_) => "browser.result",
            Request::Status => "status",
            Request::Grants => "grants",
            Request::Ping => "ping",
        }
    }

    /// Whether the request can be answered without the vault (it needs no
    /// unlock and no consent).
    pub fn without_vault(&self) -> bool {
        matches!(
            self,
            Request::Generate(_) | Request::Ping | Request::BrowserWait | Request::BrowserResult(_) | Request::Status
        )
    }

    /// Whether only a browser connection may send it.
    pub fn browser_only(&self) -> bool {
        matches!(self, Request::BrowserWait | Request::BrowserResult(_))
    }

    /// What a browser connection may send: its own requests, `status` and `ping`.
    pub fn allowed_for(&self, role: Role) -> bool {
        match role {
            Role::Agent => !self.browser_only(),
            Role::Browser => self.browser_only() || matches!(self, Request::Status | Request::Ping),
        }
    }

    /// Whether the request changes the vault.
    pub fn writes(&self) -> bool {
        matches!(self, Request::CreateItem(_) | Request::UpdateItem(_))
    }

    /// The reason the agent gave, cleaned.
    pub fn reason(&self) -> Option<String> {
        let raw = match self {
            Request::Read(p) => p.reason.as_deref(),
            Request::ReadMany(p) => p.reason.as_deref(),
            Request::CreateItem(p) => p.reason.as_deref(),
            Request::UpdateItem(p) => p.reason.as_deref(),
            Request::Fill(p) => p.reason.as_deref(),
            _ => None,
        };
        raw.map(|r| clean_label(r, REASON_MAX)).filter(|r| !r.is_empty())
    }
}

// ---------------------------------------------------------------------------
// What an agent sees
// ---------------------------------------------------------------------------

/// A field as an agent sees it: the value only when it is not a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentField {
    pub id: String,
    pub label: String,
    pub kind: FieldKind,
    pub secret: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// An item as an agent sees it: everything but the secrets and the notes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentItem {
    pub id: String,
    pub vault_id: String,
    pub vault: String,
    pub category: Category,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_notes: bool,
    pub updated_at: i64,
    pub fields: Vec<AgentField>,
}

/// The non-secret view of an item.
pub fn agent_item(session: &Session, vault_id: &str, item: &Item) -> AgentItem {
    AgentItem {
        id: item.id.clone(),
        vault_id: vault_id.to_string(),
        vault: session.vault(vault_id).map(|v| v.name).unwrap_or_default(),
        category: item.category,
        title: item.title.clone(),
        username: item.username().map(str::to_string),
        urls: item.urls.clone(),
        host: item.host(),
        tags: item.tags.clone(),
        favorite: item.favorite,
        has_password: item.password().is_some(),
        has_totp: item.totp_secret().is_some(),
        has_notes: !item.notes.trim().is_empty(),
        updated_at: item.updated_at,
        fields: item
            .fields
            .iter()
            .filter(|f| !f.value.is_empty())
            .map(|f| AgentField {
                id: f.id.clone(),
                label: f.label.clone(),
                kind: f.kind,
                secret: f.kind.is_secret(),
                value: (!f.kind.is_secret()).then(|| f.value.clone()),
            })
            .collect(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResult {
    pub items: Vec<AgentItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemResult {
    pub item: AgentItem,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadResult {
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadManyResult {
    pub values: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpResult {
    pub code: String,
    pub seconds_remaining: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenerateResult {
    pub value: String,
    pub entropy_bits: f64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateResult {
    pub id: String,
    pub password_generated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantsResult {
    pub grants: Vec<Grant>,
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

/// What a request does, for the question to the user and for grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// First contact: the agent may search titles, user names and websites.
    Connect,
    /// Read one or more values.
    Read,
    /// Get the current one-time code.
    Otp,
    /// Save a new item.
    Create,
    /// Change an item.
    Update,
    /// Fill a login in the user's browser.
    Fill,
}

impl ActionKind {
    pub fn id(&self) -> &'static str {
        match self {
            ActionKind::Connect => "connect",
            ActionKind::Read => "read",
            ActionKind::Otp => "otp",
            ActionKind::Create => "create",
            ActionKind::Update => "update",
            ActionKind::Fill => "fill",
        }
    }

    /// Whether "allow for this item until 2Secret locks / for a while" makes
    /// sense: creating an item is approved one at a time.
    pub fn grantable(&self) -> bool {
        !matches!(self, ActionKind::Connect | ActionKind::Create)
    }
}

/// An item a request concerns, as shown to the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub item_id: String,
    pub title: String,
    /// The fields asked for (`password`, `otp`, …); empty for the whole item.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// The question to the user: an agent wants to do `action` with `targets`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    pub action: ActionKind,
    pub targets: Vec<Target>,
    /// What is created or changed: the title, the vault, the fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The agent's own words, cleaned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Ask {
    pub fn connect() -> Self {
        Self { action: ActionKind::Connect, targets: Vec::new(), detail: None, reason: None }
    }
}

/// The user's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Deny,
    Once,
    /// Also later requests for these items, until 2Secret locks (kept in
    /// memory by the app, never stored).
    UntilLock,
    /// Also later requests for these items for [`GRANT_HOURS`] hours (stored).
    ForHours,
}

/// What a request needs from the user, or `None` when it needs nothing
/// (metadata, generating). Resolves the items so the question names them.
pub fn ask_for(session: &Session, request: &Request) -> std::result::Result<Option<Ask>, AgentError> {
    let reason = request.reason();
    let target =
        |item: &Item, fields: Vec<String>| Target { item_id: item.id.clone(), title: item.title.clone(), fields };
    Ok(match request {
        Request::Search(_)
        | Request::Item(_)
        | Request::Generate(_)
        | Request::Grants
        | Request::Ping
        | Request::BrowserWait
        | Request::BrowserResult(_)
        | Request::Status => None,
        Request::Fill(p) => {
            let item = resolve_item(session, &p.item)?;
            let page = fill_page(item, p.url.as_deref())?;
            let fields = fill_fields(item);
            if fields.is_empty() {
                return Err(AgentError::new(
                    AgentError::NOT_FOUND,
                    format!("'{}' has no user name, password or one-time password to fill", item.title),
                ));
            }
            Some(Ask { action: ActionKind::Fill, targets: vec![target(item, fields)], detail: url_host(&page), reason })
        }
        Request::Read(p) => {
            let (item, field) = resolve_field(session, &p.item, p.field.as_deref())?;
            Some(Ask { action: ActionKind::Read, targets: vec![target(item, vec![field])], detail: None, reason })
        }
        Request::ReadMany(p) => {
            if p.refs.is_empty() {
                return Err(AgentError::invalid("refs is empty"));
            }
            let mut targets: Vec<Target> = Vec::new();
            for r in &p.refs {
                let (item, field) = resolve_field(session, r, None)?;
                match targets.iter_mut().find(|t| t.item_id == item.id) {
                    Some(t) => {
                        if !t.fields.contains(&field) {
                            t.fields.push(field);
                        }
                    }
                    None => targets.push(target(item, vec![field])),
                }
            }
            Some(Ask { action: ActionKind::Read, targets, detail: Some(p.refs.join("\n")), reason })
        }
        Request::Otp(p) => {
            let item = resolve_item(session, &p.item)?;
            if item.totp_secret().is_none() {
                return Err(AgentError::new(
                    AgentError::NOT_FOUND,
                    format!("'{}' has no one-time password", item.title),
                ));
            }
            Some(Ask { action: ActionKind::Otp, targets: vec![target(item, vec!["otp".into()])], detail: None, reason })
        }
        Request::CreateItem(p) => {
            let title = clean_label(&p.title, 200);
            if title.is_empty() {
                return Err(AgentError::invalid("title is required"));
            }
            let vault = match &p.vault {
                Some(v) => session.find_vault(v)?,
                None => {
                    let id = session.default_vault_id().ok_or_else(|| AgentError::invalid("no vault to write to"))?;
                    session.vault(&id).ok_or_else(|| AgentError::invalid("no vault to write to"))?
                }
            };
            Some(Ask {
                action: ActionKind::Create,
                targets: Vec::new(),
                detail: Some(format!("{title} → {}", vault.name)),
                reason,
            })
        }
        Request::UpdateItem(p) => {
            let item = resolve_item(session, &p.item)?;
            let mut what: Vec<String> = Vec::new();
            if p.set.title.is_some() {
                what.push("title".into());
            }
            if p.set.username.is_some() {
                what.push("username".into());
            }
            if p.set.password.is_some() {
                what.push("password".into());
            }
            if p.set.notes.is_some() {
                what.push("notes".into());
            }
            if !p.add_urls.is_empty() {
                what.push("website".into());
            }
            what.extend(p.fields.iter().map(|f| clean_label(&f.label, 60)));
            if what.is_empty() {
                return Err(AgentError::invalid("nothing to change"));
            }
            Some(Ask { action: ActionKind::Update, targets: vec![target(item, what)], detail: None, reason })
        }
    })
}

/// An item by id, exact title or `2s://` reference.
fn resolve_item<'a>(session: &'a Session, query: &str) -> std::result::Result<&'a Item, AgentError> {
    if secret_ref::is_reference(query) {
        let r = SecretRef::parse(query)?;
        let vault_id = match &r.vault {
            Some(v) => Some(session.find_vault(v)?.id),
            None => None,
        };
        return Ok(session.find_item(&r.item, vault_id.as_deref())?);
    }
    Ok(session.find_item(query, None)?)
}

/// An item and a field name from `item` (maybe a reference) and `field`.
fn resolve_field<'a>(
    session: &'a Session,
    item: &str,
    field: Option<&str>,
) -> std::result::Result<(&'a Item, String), AgentError> {
    let (item, field) = if secret_ref::is_reference(item) {
        let r = SecretRef::parse(item)?;
        (resolve_item(session, item)?, field.map(str::to_string).unwrap_or(r.field))
    } else {
        let field = field.filter(|f| !f.trim().is_empty()).ok_or_else(|| AgentError::invalid("field is required"))?;
        (resolve_item(session, item)?, field.to_string())
    };
    // Resolving checks that the field exists and is not empty.
    let reference = SecretRef { vault: None, item: item.id.clone(), field: field.clone() };
    reference.resolve(session)?;
    Ok((item, field.to_lowercase()))
}

/// The page a fill is for: `url`, or the item's first website; it has to be
/// one of the item's websites (matched like autofill does).
fn fill_page(item: &Item, url: Option<&str>) -> std::result::Result<String, AgentError> {
    let websites: Vec<&str> = item.urls.iter().map(|u| u.trim()).filter(|u| !u.is_empty()).collect();
    if websites.is_empty() {
        return Err(AgentError::invalid(format!("'{}' has no website; add one to the item first", item.title)));
    }
    let page = match url.map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => u.to_string(),
        None => websites[0].to_string(),
    };
    if !websites.iter().any(|w| url_matches(w, &page)) {
        return Err(AgentError::new(
            AgentError::NOT_FOUND,
            format!("'{}' is not a login for {}", item.title, url_host(&page).unwrap_or_else(|| page.clone())),
        ));
    }
    Ok(page)
}

/// Which of `username`, `password` and `otp` an item can fill.
fn fill_fields(item: &Item) -> Vec<String> {
    let mut fields = Vec::new();
    if item.username().is_some_and(|u| !u.is_empty()) {
        fields.push("username".to_string());
    }
    if item.password().is_some_and(|p| !p.is_empty()) {
        fields.push("password".to_string());
    }
    if item.totp_secret().is_some() {
        fields.push("otp".to_string());
    }
    fields
}

/// What the browser gets after the user allowed `fill`: the values and the
/// rules that say where they may go. `id` names the job on the way back.
pub fn fill_command(item: &Item, url: &str, submit: bool, id: String) -> std::result::Result<FillCommand, AgentError> {
    let page = fill_page(item, Some(url))?;
    let code = match item.totp_secret() {
        Some(secret) => Totp::parse(secret)?.now().0,
        None => String::new(),
    };
    Ok(FillCommand {
        id,
        url: page,
        rules: fill_rules(&item.urls),
        username: item.username().unwrap_or_default().to_string(),
        password: item.password().unwrap_or_default().to_string(),
        code,
        submit,
    })
}

// ---------------------------------------------------------------------------
// The store: paired agents, grants, log
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    /// Ed25519 public key (base64).
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

impl AgentRecord {
    /// The name as the user sees it (see [`AgentIdentity::display`]).
    pub fn display(&self) -> String {
        match (&self.role, &self.browser) {
            (Role::Browser, Some(b)) => format!("{} extension", browser_label(b)),
            _ => self.name.clone(),
        }
    }
}

/// Permission to do `action` with one item without asking, until `expires_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub agent_id: String,
    pub item_id: String,
    pub action: ActionKind,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The user allowed it just now.
    Allowed,
    /// An earlier permission covered it.
    Granted,
    Denied,
    Timeout,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub ts: i64,
    pub agent_id: String,
    pub agent: String,
    pub action: ActionKind,
    /// Titles of the items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub outcome: Outcome,
}

/// Everything the app remembers about agents, encrypted with the account
/// key (associated data [`AgentStore::aad`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentStore {
    pub agents: Vec<AgentRecord>,
    pub grants: Vec<Grant>,
    /// Newest last.
    pub log: Vec<LogEntry>,
}

impl AgentStore {
    pub fn aad(account_id: &str) -> String {
        format!("2secret/v1/agents/{account_id}")
    }

    pub fn seal(&self, account_key: &SymmetricKey, account_id: &str) -> Result<EncString> {
        encrypt_json(account_key, self, Self::aad(account_id).as_bytes())
    }

    pub fn open(enc: &EncString, account_key: &SymmetricKey, account_id: &str) -> Result<Self> {
        let mut store: AgentStore = decrypt_json(account_key, enc, Self::aad(account_id).as_bytes())?;
        store.prune(now());
        Ok(store)
    }

    /// Drop expired grants and old log entries.
    pub fn prune(&mut self, now: i64) {
        self.grants.retain(|g| g.expires_at > now);
        if self.log.len() > MAX_LOG {
            let excess = self.log.len() - MAX_LOG;
            self.log.drain(..excess);
        }
    }

    pub fn agent(&self, agent_id: &str) -> Option<&AgentRecord> {
        self.agents.iter().find(|a| a.id == agent_id)
    }

    /// The agent connected before and was allowed to, with the same key.
    pub fn is_paired(&self, identity: &AgentIdentity) -> bool {
        self.agent(&identity.id).is_some_and(|a| a.public_key == identity.public_key)
    }

    /// Remember a newly allowed agent, or refresh what is known about one.
    pub fn pair(&mut self, identity: &AgentIdentity, now: i64) {
        match self.agents.iter_mut().find(|a| a.id == identity.id) {
            Some(a) => {
                a.name = identity.name.clone();
                a.exe = identity.exe.clone();
                a.parent = identity.parent.clone();
                a.role = identity.role;
                a.browser = identity.browser.clone();
                a.last_seen = now;
            }
            None => self.agents.push(AgentRecord {
                id: identity.id.clone(),
                name: identity.name.clone(),
                public_key: identity.public_key.clone(),
                exe: identity.exe.clone(),
                parent: identity.parent.clone(),
                role: identity.role,
                browser: identity.browser.clone(),
                first_seen: now,
                last_seen: now,
            }),
        }
    }

    pub fn touch(&mut self, agent_id: &str, now: i64) {
        if let Some(a) = self.agents.iter_mut().find(|a| a.id == agent_id) {
            a.last_seen = now;
        }
    }

    /// Forget an agent and its grants; it has to be allowed again to connect.
    pub fn revoke_agent(&mut self, agent_id: &str) {
        self.agents.retain(|a| a.id != agent_id);
        self.grants.retain(|g| g.agent_id != agent_id);
    }

    /// Whether stored grants cover the whole request.
    pub fn covers(&self, agent_id: &str, ask: &Ask, now: i64) -> bool {
        if !ask.action.grantable() || ask.targets.is_empty() {
            return false;
        }
        ask.targets.iter().all(|t| {
            self.grants.iter().any(|g| {
                g.agent_id == agent_id && g.item_id == t.item_id && g.action == ask.action && g.expires_at > now
            })
        })
    }

    /// Store "allow for a while" for every item of the request.
    pub fn grant(&mut self, agent_id: &str, ask: &Ask, now: i64) {
        if !ask.action.grantable() {
            return;
        }
        let expires_at = now + i64::from(GRANT_HOURS) * 3600;
        for t in &ask.targets {
            self.grants.retain(|g| !(g.agent_id == agent_id && g.item_id == t.item_id && g.action == ask.action));
            self.grants.push(Grant {
                agent_id: agent_id.to_string(),
                item_id: t.item_id.clone(),
                action: ask.action,
                expires_at,
            });
        }
    }

    pub fn grants_of(&self, agent_id: &str, now: i64) -> Vec<Grant> {
        self.grants.iter().filter(|g| g.agent_id == agent_id && g.expires_at > now).cloned().collect()
    }

    pub fn revoke_grants(&mut self, agent_id: &str) {
        self.grants.retain(|g| g.agent_id != agent_id);
    }

    pub fn record(&mut self, identity: &AgentIdentity, ask: &Ask, outcome: Outcome, now: i64) {
        self.log.push(LogEntry {
            ts: now,
            agent_id: identity.id.clone(),
            agent: identity.name.clone(),
            action: ask.action,
            items: ask.targets.iter().map(|t| t.title.clone()).collect(),
            detail: ask.detail.clone(),
            outcome,
        });
        if self.log.len() > MAX_LOG {
            self.log.remove(0);
        }
    }

    pub fn clear_log(&mut self) {
        self.log.clear();
    }
}

/// The keys of "allow until 2Secret locks", kept in memory by the app.
#[derive(Clone, Debug, Default)]
pub struct UntilLock(HashSet<(String, String, ActionKind)>);

impl UntilLock {
    pub fn allow(&mut self, agent_id: &str, ask: &Ask) {
        if !ask.action.grantable() {
            return;
        }
        for t in &ask.targets {
            self.0.insert((agent_id.to_string(), t.item_id.clone(), ask.action));
        }
    }

    pub fn covers(&self, agent_id: &str, ask: &Ask) -> bool {
        ask.action.grantable()
            && !ask.targets.is_empty()
            && ask.targets.iter().all(|t| self.0.contains(&(agent_id.to_string(), t.item_id.clone(), ask.action)))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Running requests
// ---------------------------------------------------------------------------

/// Run a request that only reads the unlocked vault. Consent is the
/// caller's job ([`ask_for`]); this only does what was asked. Creating and
/// changing items go through [`execute_mut`].
pub fn execute(session: &Session, request: &Request) -> std::result::Result<Value, AgentError> {
    Ok(match request {
        Request::Ping => Value::Object(Default::default()),
        Request::Grants => Value::Object(Default::default()),
        Request::Generate(p) => {
            let opts = p.options();
            serde_json::to_value(GenerateResult { value: opts.generate(), entropy_bits: opts.entropy_bits().round() })?
        }
        Request::Search(p) => serde_json::to_value(SearchResult { items: search(session, p)? })?,
        Request::Item(p) => {
            let item = resolve_item(session, &p.item)?;
            let vault_id = session.item_vault(&item.id).unwrap_or_default().to_string();
            serde_json::to_value(ItemResult { item: agent_item(session, &vault_id, item) })?
        }
        Request::Read(p) => {
            let (item, field) = resolve_field(session, &p.item, p.field.as_deref())?;
            let reference = SecretRef { vault: None, item: item.id.clone(), field };
            serde_json::to_value(ReadResult { value: reference.resolve(session)?.to_string() })?
        }
        Request::ReadMany(p) => {
            let mut values = BTreeMap::new();
            for r in &p.refs {
                values.insert(r.clone(), secret_ref::resolve(session, r)?.to_string());
            }
            serde_json::to_value(ReadManyResult { values })?
        }
        Request::Otp(p) => {
            let item = resolve_item(session, &p.item)?;
            let secret = item.totp_secret().ok_or_else(|| {
                AgentError::new(AgentError::NOT_FOUND, format!("'{}' has no one-time password", item.title))
            })?;
            let (code, seconds_remaining) = Totp::parse(secret)?.now();
            serde_json::to_value(OtpResult { code, seconds_remaining })?
        }
        Request::CreateItem(_) | Request::UpdateItem(_) => {
            return Err(AgentError::new(AgentError::INTERNAL, "writing needs the vault for writing"))
        }
        Request::Fill(_) | Request::BrowserWait | Request::BrowserResult(_) | Request::Status => {
            return Err(AgentError::new(AgentError::INTERNAL, "handled by the app"))
        }
    })
}

/// Run any request, also one that creates or changes an item.
pub fn execute_mut(session: &mut Session, request: &Request) -> std::result::Result<Value, AgentError> {
    match request {
        Request::CreateItem(p) => Ok(serde_json::to_value(create_item(session, p)?)?),
        Request::UpdateItem(p) => {
            update_item(session, p)?;
            Ok(Value::Object(Default::default()))
        }
        _ => execute(session, request),
    }
}

fn search(session: &Session, p: &SearchParams) -> std::result::Result<Vec<AgentItem>, AgentError> {
    let limit = p.limit.unwrap_or(50).clamp(1, SEARCH_LIMIT);
    let vault_id = match &p.vault {
        Some(v) => Some(session.find_vault(v)?.id),
        None => None,
    };
    let query = p.query.clone().unwrap_or_default();
    let summaries = match &p.url {
        Some(url) if !url.trim().is_empty() => session
            .items_for_url(url)
            .into_iter()
            .filter(|s| vault_id.as_deref().is_none_or(|v| v == s.vault_id))
            .filter(|s| p.category.is_none_or(|c| c == s.category))
            .filter(|s| session.item(&s.id).is_some_and(|i| i.matches(&query)))
            .collect(),
        _ => session.list(&ItemFilter { vault_id, category: p.category, query, ..ItemFilter::default() }),
    };
    let mut names: HashMap<String, String> = HashMap::new();
    Ok(summaries
        .iter()
        .take(limit)
        .filter_map(|s| session.item(&s.id).map(|item| (s, item)))
        .map(|(s, item)| {
            let mut view = agent_item(session, &s.vault_id, item);
            let name = names
                .entry(s.vault_id.clone())
                .or_insert_with(|| session.vault(&s.vault_id).map(|v| v.name).unwrap_or_default());
            view.vault = name.clone();
            view
        })
        .collect())
}

fn apply_fields(item: &mut Item, fields: &[NewField]) {
    for f in fields {
        let label = clean_label(&f.label, 60);
        if label.is_empty() {
            continue;
        }
        if item.field(&label).is_some() {
            item.set_value(&label, &f.value);
            if f.secret {
                if let Some(field) = item.field_mut(&label) {
                    field.kind = FieldKind::Concealed;
                }
            }
        } else {
            let kind = if f.secret { FieldKind::Concealed } else { FieldKind::Text };
            item.fields.push(Field::custom(&label, kind, &f.value));
        }
    }
}

fn set_password(item: &mut Item, password: &str) {
    let key = ["password", "wireless_password", "credential"].into_iter().find(|k| item.field(k).is_some());
    match key {
        Some(k) => item.set_value(k, password),
        None => item.fields.push(Field::new("password", "password", FieldKind::Concealed, password)),
    }
}

fn create_item(session: &mut Session, p: &CreateParams) -> std::result::Result<CreateResult, AgentError> {
    let title = clean_label(&p.title, 200);
    if title.is_empty() {
        return Err(AgentError::invalid("title is required"));
    }
    let vault_id = match &p.vault {
        Some(v) => session.find_vault(v)?.id,
        None => session.default_vault_id().ok_or_else(|| AgentError::invalid("no vault to write to"))?,
    };
    let mut item = Item::new(p.category.unwrap_or(Category::Login), &title);
    if let Some(u) = &p.username {
        item.set_value("username", u);
    }
    let password_generated = p.generate;
    if p.generate {
        set_password(&mut item, &GeneratorOptions::default().generate());
    } else if let Some(pw) = p.password.as_deref().filter(|pw| !pw.is_empty()) {
        set_password(&mut item, pw);
    }
    if let Some(url) = p.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        item.urls.push(url.to_string());
    }
    if let Some(notes) = &p.notes {
        item.notes = notes.clone();
    }
    item.tags.extend(p.tags.iter().map(|t| clean_label(t, 60)).filter(|t| !t.is_empty()));
    apply_fields(&mut item, &p.fields);
    let id = session.add_item(&vault_id, item)?;
    Ok(CreateResult { id, password_generated })
}

fn update_item(session: &mut Session, p: &UpdateParams) -> std::result::Result<(), AgentError> {
    let mut item = resolve_item(session, &p.item)?.clone();
    if let Some(t) = p.set.title.as_deref().map(|t| clean_label(t, 200)).filter(|t| !t.is_empty()) {
        item.title = t;
    }
    if let Some(u) = &p.set.username {
        item.set_value("username", u);
    }
    if let Some(pw) = p.set.password.as_deref().filter(|pw| !pw.is_empty()) {
        set_password(&mut item, pw);
    }
    if let Some(n) = &p.set.notes {
        item.notes = n.clone();
    }
    for url in p.add_urls.iter().map(|u| u.trim()).filter(|u| !u.is_empty()) {
        if !item.urls.iter().any(|u| u == url) {
            item.urls.push(url.to_string());
        }
    }
    apply_fields(&mut item, &p.fields);
    session.update_item(item)?;
    Ok(())
}

/// A nonce for `hello`, base64.
pub fn new_nonce() -> String {
    b64(&crate::util::random_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::tests::new_session;
    use ed25519_dalek::{Signer, SigningKey};

    fn session_with_items() -> (Session, String) {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let mut item = Item::login("GitHub", "octo", "hunter2", Some("https://github.com"));
        item.set_value("totp", "JBSWY3DPEHPK3PXP");
        if let Some(f) = item.field_mut("totp") {
            f.kind = FieldKind::Totp;
        }
        item.notes = "recovery codes: 1234".into();
        item.tags.push("dev".into());
        let id = s.add_item(&v, item).unwrap();
        s.add_item(&v, Item::login("Postgres", "app", "dbpw", Some("db.local"))).unwrap();
        (s, id)
    }

    fn identity(key: &SigningKey) -> AgentIdentity {
        let pk = b64(key.verifying_key().as_bytes());
        let hello = HelloParams {
            protocol: PROTOCOL,
            name: "Claude Code".into(),
            version: "1".into(),
            agent_key: pk.clone(),
            parent: Some("claude".into()),
            role: Role::Agent,
            browser: None,
            extension: None,
        };
        AgentIdentity::new(&agent_id(key.verifying_key().as_bytes()), &hello, Some("/usr/bin/2secret".into()), None)
    }

    #[test]
    fn hello_signature() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = b64(key.verifying_key().as_bytes());
        let nonce = crate::util::random_bytes::<32>();
        let sig = b64(&key.sign(&hello_challenge(&nonce)).to_bytes());
        assert_eq!(verify_hello(&pk, &nonce, &sig).unwrap(), agent_id(key.verifying_key().as_bytes()));
        assert!(verify_hello(&pk, &[1u8; 32], &sig).is_err(), "another nonce");
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let sig2 = b64(&other.sign(&hello_challenge(&nonce)).to_bytes());
        assert!(verify_hello(&pk, &nonce, &sig2).is_err(), "another key");
        assert!(verify_hello("not base64!", &nonce, &sig).is_err());
        assert_eq!(agent_id(key.verifying_key().as_bytes()).len(), 19);
    }

    #[test]
    fn labels_are_cleaned() {
        assert_eq!(clean_label("  Claude\u{202E} Code\u{200B}\n", 80), "Claude Code");
        assert_eq!(clean_label("abcdef", 3), "abc");
        let id = identity(&SigningKey::from_bytes(&[1u8; 32]));
        assert_eq!(id.name, "Claude Code");
        assert_eq!(id.display(), "Claude Code (via 2secret)");
        let hello = HelloParams {
            protocol: 1,
            name: "\u{200B}".into(),
            version: String::new(),
            agent_key: String::new(),
            parent: None,
            role: Role::Agent,
            browser: None,
            extension: None,
        };
        assert_eq!(AgentIdentity::new("x", &hello, None, None).name, "An AI agent");
        let hello = HelloParams {
            role: Role::Browser,
            browser: Some(" Google Chrome! ".into()),
            extension: Some("chrome-extension://abc/".into()),
            ..hello
        };
        let ext =
            AgentIdentity::new("x", &hello, Some("/Applications/2Secret.app/Contents/MacOS/2-secret".into()), None);
        assert_eq!(ext.browser.as_deref(), Some("google-chrome"));
        assert_eq!(ext.name, "Google-chrome extension");
        assert_eq!(ext.display(), "Google-chrome extension");
        let mut ext = ext;
        ext.browser = Some("edge".into());
        assert_eq!(ext.display(), "Microsoft Edge extension");
        assert_eq!(browser_name("Firefox"), "firefox");
        assert_eq!(browser_label("brave"), "Brave");
        // A hello from a 1.10 client has no role: it is an agent.
        let old: HelloParams =
            serde_json::from_str(r#"{"protocol":1,"name":"x","version":"1","agent_key":"k"}"#).unwrap();
        assert_eq!(old.role, Role::Agent);
        let old: AgentRecord =
            serde_json::from_str(r#"{"id":"a","name":"x","public_key":"k","first_seen":1,"last_seen":2}"#).unwrap();
        assert_eq!(old.role, Role::Agent);
        assert_eq!(old.display(), "x");
    }

    #[test]
    fn agent_items_hold_no_secrets() {
        let (s, id) = session_with_items();
        let item = s.item(&id).unwrap();
        let view = agent_item(&s, s.item_vault(&id).unwrap(), item);
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("JBSWY3DP"));
        assert!(!json.contains("recovery"));
        assert!(json.contains("octo") && json.contains("github.com"));
        assert!(view.has_password && view.has_totp && view.has_notes);
        assert_eq!(view.vault, "Personal");
        assert!(view.fields.iter().filter(|f| f.secret).all(|f| f.value.is_none()));
    }

    #[test]
    fn requests_parse_and_execute() {
        let (mut s, id) = session_with_items();
        let req = Request::parse("search", Some(serde_json::json!({"query": "git"}))).unwrap();
        let out = execute_mut(&mut s, &req).unwrap();
        let found: SearchResult = serde_json::from_value(out).unwrap();
        assert_eq!(found.items.len(), 1);
        assert_eq!(found.items[0].id, id);

        let req = Request::parse("search", Some(serde_json::json!({"url": "https://gist.github.com/x"}))).unwrap();
        let found: SearchResult = serde_json::from_value(execute_mut(&mut s, &req).unwrap()).unwrap();
        assert_eq!(found.items.len(), 1, "matched by website");

        let req = Request::parse("read", Some(serde_json::json!({"item": "GitHub", "field": "password"}))).unwrap();
        let read: ReadResult = serde_json::from_value(execute_mut(&mut s, &req).unwrap()).unwrap();
        assert_eq!(read.value, "hunter2");

        let req = Request::parse("read", Some(serde_json::json!({"item": "2s://Personal/Postgres/password"}))).unwrap();
        let read: ReadResult = serde_json::from_value(execute_mut(&mut s, &req).unwrap()).unwrap();
        assert_eq!(read.value, "dbpw");

        let req = Request::parse(
            "read_many",
            Some(serde_json::json!({"refs": ["2s://GitHub/username", "2s://Postgres/password"]})),
        )
        .unwrap();
        let many: ReadManyResult = serde_json::from_value(execute_mut(&mut s, &req).unwrap()).unwrap();
        assert_eq!(many.values["2s://GitHub/username"], "octo");

        let req = Request::parse("otp", Some(serde_json::json!({"item": &id}))).unwrap();
        let otp: OtpResult = serde_json::from_value(execute_mut(&mut s, &req).unwrap()).unwrap();
        assert_eq!(otp.code.len(), 6);
        let req = Request::parse("otp", Some(serde_json::json!({"item": "Postgres"}))).unwrap();
        assert_eq!(ask_for(&s, &req).unwrap_err().code, AgentError::NOT_FOUND);

        let req = Request::parse("generate", Some(serde_json::json!({"length": 32, "symbols": false}))).unwrap();
        let gen: GenerateResult = serde_json::from_value(execute_mut(&mut s, &req).unwrap()).unwrap();
        assert_eq!(gen.value.len(), 32);
        assert!(gen.value.chars().all(|c| c.is_ascii_alphanumeric()));

        let req = Request::parse(
            "create_item",
            Some(
                serde_json::json!({"title": "Acme", "username": "me", "generate": true, "url": "https://acme.example",
                "fields": [{"label": "API key", "value": "k-1", "secret": true}], "tags": ["work"]}),
            ),
        )
        .unwrap();
        let created: CreateResult = serde_json::from_value(execute_mut(&mut s, &req).unwrap()).unwrap();
        assert!(created.password_generated);
        let acme = s.item(&created.id).unwrap();
        assert_eq!(acme.username(), Some("me"));
        assert!(acme.password().is_some_and(|p| p.len() == 20));
        assert_eq!(acme.field("API key").map(|f| f.kind), Some(FieldKind::Concealed));
        assert_eq!(acme.tags, vec!["work"]);

        let req = Request::parse(
            "update_item",
            Some(serde_json::json!({"item": "Acme", "set": {"password": "newpw"}, "add_urls": ["https://login.acme.example"]})),
        )
        .unwrap();
        execute_mut(&mut s, &req).unwrap();
        let acme = s.item(&created.id).unwrap();
        assert_eq!(acme.password(), Some("newpw"));
        assert_eq!(acme.urls.len(), 2);

        assert_eq!(Request::parse("nope", None).unwrap_err().code, AgentError::METHOD_NOT_FOUND);
        assert_eq!(Request::parse("read", Some(serde_json::json!({}))).unwrap_err().code, AgentError::INVALID_PARAMS);
        let req = Request::parse("read", Some(serde_json::json!({"item": "Nope", "field": "password"}))).unwrap();
        assert_eq!(execute_mut(&mut s, &req).unwrap_err().code, AgentError::NOT_FOUND);
    }

    #[test]
    fn asks_name_the_items() {
        let (s, id) = session_with_items();
        let req = Request::parse("search", None).unwrap();
        assert!(ask_for(&s, &req).unwrap().is_none());
        let req = Request::parse(
            "read_many",
            Some(
                serde_json::json!({"refs": ["2s://GitHub/username", "2s://GitHub/password", "2s://Postgres/password"],
                "reason": "run \u{202E}deploy"}),
            ),
        )
        .unwrap();
        let ask = ask_for(&s, &req).unwrap().unwrap();
        assert_eq!(ask.action, ActionKind::Read);
        assert_eq!(ask.targets.len(), 2);
        assert_eq!(ask.targets[0].item_id, id);
        assert_eq!(ask.targets[0].fields, vec!["username", "password"]);
        assert_eq!(ask.reason.as_deref(), Some("run deploy"));
        let req = Request::parse("read", Some(serde_json::json!({"item": "GitHub", "field": "missing"}))).unwrap();
        assert_eq!(ask_for(&s, &req).unwrap_err().code, AgentError::NOT_FOUND);
        let req = Request::parse("create_item", Some(serde_json::json!({"title": "New"}))).unwrap();
        let ask = ask_for(&s, &req).unwrap().unwrap();
        assert_eq!(ask.action, ActionKind::Create);
        assert_eq!(ask.detail.as_deref(), Some("New → Personal"));
        let req = Request::parse("update_item", Some(serde_json::json!({"item": "GitHub"}))).unwrap();
        assert_eq!(ask_for(&s, &req).unwrap_err().code, AgentError::INVALID_PARAMS);
    }

    #[test]
    fn fills_are_asked_and_built() {
        let (mut s, id) = session_with_items();
        for (method, params) in [
            ("fill", serde_json::json!({"item": "GitHub"})),
            ("browser.wait", serde_json::json!({})),
            ("browser.result", serde_json::json!({"id": "f-1", "outcome": "no_tab"})),
            ("status", serde_json::json!({})),
        ] {
            let req = Request::parse(method, Some(params)).unwrap();
            assert_eq!(req.method(), method);
            assert!(Request::METHODS.contains(&method));
            assert_eq!(execute(&s, &req).unwrap_err().code, AgentError::INTERNAL, "the app answers {method}");
        }
        assert_eq!(Request::METHODS.len(), 14);
        let wait = Request::parse("browser.wait", None).unwrap();
        assert!(wait.without_vault() && wait.browser_only());
        assert!(wait.allowed_for(Role::Browser) && !wait.allowed_for(Role::Agent));
        let fill = Request::parse("fill", Some(serde_json::json!({"item": "GitHub", "reason": "deploy"}))).unwrap();
        assert!(!fill.without_vault() && !fill.browser_only());
        assert!(fill.allowed_for(Role::Agent) && !fill.allowed_for(Role::Browser));
        assert!(Request::Status.allowed_for(Role::Browser) && Request::Ping.allowed_for(Role::Browser));
        assert!(!Request::Search(SearchParams::default()).allowed_for(Role::Browser));
        assert_eq!(fill.reason().as_deref(), Some("deploy"));

        let ask = ask_for(&s, &fill).unwrap().unwrap();
        assert_eq!(ask.action, ActionKind::Fill);
        assert!(ask.action.grantable());
        assert_eq!(ask.targets[0].item_id, id);
        assert_eq!(ask.targets[0].fields, vec!["username", "password", "otp"]);
        assert_eq!(ask.detail.as_deref(), Some("github.com"));

        let other_site =
            Request::parse("fill", Some(serde_json::json!({"item": "GitHub", "url": "https://example.com/login"})))
                .unwrap();
        assert_eq!(ask_for(&s, &other_site).unwrap_err().code, AgentError::NOT_FOUND);
        let http =
            Request::parse("fill", Some(serde_json::json!({"item": "GitHub", "url": "http://github.com/"}))).unwrap();
        assert_eq!(ask_for(&s, &http).unwrap_err().code, AgentError::NOT_FOUND, "https item, http page");
        let sub =
            Request::parse("fill", Some(serde_json::json!({"item": "GitHub", "url": "https://gist.github.com/x"})))
                .unwrap();
        assert!(ask_for(&s, &sub).unwrap().is_some());
        let v = s.default_vault_id().unwrap();
        s.add_item(&v, Item::login("No site", "me", "pw", None)).unwrap();
        let nosite = Request::parse("fill", Some(serde_json::json!({"item": "No site"}))).unwrap();
        assert_eq!(ask_for(&s, &nosite).unwrap_err().code, AgentError::INVALID_PARAMS);
        let mut empty = Item::login("Empty", "", "", Some("https://empty.example"));
        empty.set_value("username", "");
        s.add_item(&v, empty).unwrap();
        let nothing = Request::parse("fill", Some(serde_json::json!({"item": "Empty"}))).unwrap();
        assert_eq!(ask_for(&s, &nothing).unwrap_err().code, AgentError::NOT_FOUND);

        let item = s.item(&id).unwrap();
        let cmd = fill_command(item, "https://github.com/login", true, "f-7".into()).unwrap();
        assert_eq!(cmd.username, "octo");
        assert_eq!(cmd.password, "hunter2");
        assert_eq!(cmd.code.len(), 6);
        assert!(cmd.submit);
        assert_eq!(cmd.rules, vec![FillRule { domain: "github.com".into(), https: true, port: None, exact: false }]);
        let json = serde_json::to_string(&WaitResult { job: Some(cmd.clone()) }).unwrap();
        let back: WaitResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.job.as_ref(), Some(&cmd));
        assert_eq!(serde_json::to_string(&WaitResult { job: None }).unwrap(), r#"{"job":null}"#);
        assert!(fill_command(item, "https://example.com", true, "f-8".into()).is_err());

        let outcome: FillOutcomeParams =
            serde_json::from_str(r#"{"id":"f-7","outcome":"filled","submitted":true}"#).unwrap();
        assert_eq!(outcome.outcome, FillOutcome::Filled);
        let err = AgentError::fill_failed(FillOutcome::NoTab, "github.com", "chrome");
        assert_eq!(err.code, AgentError::FILL_FAILED);
        assert!(err.message.contains("github.com") && err.message.contains("chrome"));
        assert_eq!(AgentError::no_browser().code, AgentError::NO_BROWSER);
    }

    #[test]
    fn store_grants_and_seals() {
        let (s, id) = session_with_items();
        let t = now();
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let me = identity(&key);
        let mut store = AgentStore::default();
        assert!(!store.is_paired(&me));
        store.pair(&me, t);
        assert!(store.is_paired(&me));
        let mut other = me.clone();
        other.public_key = "AAAA".into();
        assert!(!store.is_paired(&other), "same id, other key");

        let req = Request::parse("read", Some(serde_json::json!({"item": "GitHub", "field": "password"}))).unwrap();
        let ask = ask_for(&s, &req).unwrap().unwrap();
        assert!(!store.covers(&me.id, &ask, t));
        store.grant(&me.id, &ask, t);
        assert!(store.covers(&me.id, &ask, t));
        assert!(store.covers(&me.id, &ask, t + i64::from(GRANT_HOURS) * 3600 - 1));
        assert!(!store.covers(&me.id, &ask, t + i64::from(GRANT_HOURS) * 3600));
        assert!(!store.covers("other", &ask, t));
        let otp =
            ask_for(&s, &Request::parse("otp", Some(serde_json::json!({"item": &id}))).unwrap()).unwrap().unwrap();
        assert!(!store.covers(&me.id, &otp, t), "another action");
        let create = ask_for(&s, &Request::parse("create_item", Some(serde_json::json!({"title": "x"}))).unwrap())
            .unwrap()
            .unwrap();
        store.grant(&me.id, &create, t);
        assert!(!store.covers(&me.id, &create, t), "creating is never remembered");
        store.record(&me, &ask, Outcome::Allowed, t);
        assert_eq!(store.log.len(), 1);
        assert_eq!(store.log[0].items, vec!["GitHub"]);

        let account_key = SymmetricKey::generate();
        let enc = store.seal(&account_key, "acc").unwrap();
        assert!(!enc.as_str().contains("GitHub"));
        let back = AgentStore::open(&enc, &account_key, "acc").unwrap();
        assert_eq!(back, store);
        assert!(AgentStore::open(&enc, &account_key, "other").is_err());
        assert!(AgentStore::open(&enc, &SymmetricKey::generate(), "acc").is_err());

        let mut expired = store.clone();
        expired.prune(now() + i64::from(GRANT_HOURS) * 3600 + 1);
        assert!(expired.grants.is_empty());
        store.revoke_agent(&me.id);
        assert!(store.agents.is_empty() && store.grants.is_empty());

        let mut until = UntilLock::default();
        assert!(!until.covers(&me.id, &ask));
        until.allow(&me.id, &ask);
        assert!(until.covers(&me.id, &ask));
        until.allow(&me.id, &create);
        assert!(!until.covers(&me.id, &create));
        until.clear();
        assert!(until.is_empty());
    }

    #[test]
    fn log_is_capped() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let me = identity(&key);
        let mut store = AgentStore::default();
        let ask = Ask::connect();
        for i in 0..(MAX_LOG + 5) {
            store.record(&me, &ask, Outcome::Allowed, i as i64);
        }
        assert_eq!(store.log.len(), MAX_LOG);
        assert_eq!(store.log[0].ts, 5);
    }
}
