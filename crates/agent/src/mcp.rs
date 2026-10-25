//! The Model Context Protocol server: JSON-RPC 2.0 over stdin and stdout, one
//! message per line, as every MCP client speaks it (`initialize`,
//! `tools/list`, `tools/call`, `ping`). Written by hand: the five methods
//! need no SDK.
//!
//! In [`Mode::App`] every tool call goes to the running desktop app, which
//! asks the user. The connection is made at the first call, so a client can
//! start this server before 2Secret runs; it introduces itself with the
//! client's own name from `initialize` (Claude Code, Cursor, …), with one
//! key per client name, so the app tells them apart.
//!
//! [`Mode::Standalone`] works on the vault directly (the shell session or
//! the master password) and therefore cannot ask anyone: it only searches,
//! shows items without secrets and generates passwords; `run_command` only
//! with `allow_run`.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use serde_json::{json, Value};
use twosecret_core::agent::{self, AgentError, Request};
use twosecret_core::Session;

use crate::client::{endpoint, AppClient, ClientError};
use crate::key::AgentKey;
use crate::tools::{self, Backend};

/// Protocol versions this server speaks; the newest last.
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];

/// What the model is told at `initialize`.
pub const INSTRUCTIONS: &str = "2Secret is the user's password manager. search_items and get_item show what exists \
    without secrets and need no approval. read_field and get_otp hand a secret to you after the user approves it in \
    the 2Secret app; use them only when you really need the value yourself. When a program needs a secret, use \
    run_command with environment variables set to 2s:// references instead: the program gets the value, you do not. \
    To sign the user in on a website in their own browser, use fill_login: 2Secret fills and submits the sign-in page \
    that is the active tab, and you never see the password. \
    Approvals are given in the 2Secret desktop app; if a call fails because 2Secret is locked or not running, tell the user.";

pub enum Mode {
    /// Through the desktop app for the data directory `home`.
    App {
        home: PathBuf,
        /// The name to introduce the agent with; otherwise the MCP client's.
        name: Option<String>,
    },
    /// Directly on the vault, without approvals.
    Standalone { session: Box<Session>, allow_run: bool },
}

struct AppBackend {
    home: PathBuf,
    name: Option<String>,
    client_info: Option<(String, String)>,
    key: Option<AgentKey>,
    client: Option<AppClient>,
}

impl AppBackend {
    fn agent_name(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.client_info.as_ref().map(|(n, _)| n.clone()))
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "MCP client".to_string())
    }

    fn connect(&mut self) -> Result<&mut AppClient, ClientError> {
        if self.client.is_none() {
            let name = self.agent_name();
            if self.key.is_none() {
                self.key = Some(AgentKey::load_or_create(&self.home, &name).map_err(ClientError::Io)?);
            }
            let key = self.key.as_ref().expect("key loaded");
            let version = self.client_info.as_ref().map(|(_, v)| v.clone()).unwrap_or_default();
            let mut client = AppClient::connect(&self.home)?;
            let parent = crate::parent_process_name();
            client.hello_auth(key, &name, &version, parent.as_deref())?;
            self.client = Some(client);
        }
        Ok(self.client.as_mut().expect("connected"))
    }
}

/// A message for the model about a failed request.
fn describe(e: &ClientError) -> String {
    match e {
        ClientError::Rpc(err) => match err.code {
            AgentError::DENIED => "The user did not allow this in 2Secret.".to_string(),
            AgentError::TIMEOUT => "The user did not answer 2Secret's question in time.".to_string(),
            AgentError::LOCKED => "2Secret is locked. Ask the user to unlock it, then try again.".to_string(),
            AgentError::OFF => {
                "Agent Access is turned off in 2Secret (Settings → Desktop app → AI agents).".to_string()
            }
            _ => err.message.clone(),
        },
        other => other.to_string(),
    }
}

impl Backend for AppBackend {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let client = self.connect().map_err(|e| describe(&e))?;
        match client.call_value(method, params) {
            Ok(v) => Ok(v),
            Err(e) => {
                if matches!(e, ClientError::Io(_) | ClientError::NotRunning(_) | ClientError::Protocol(_)) {
                    // Next call connects again.
                    self.client = None;
                }
                Err(describe(&e))
            }
        }
    }

    fn status(&mut self) -> Value {
        let endpoint = endpoint(&self.home);
        let agent_name = self.agent_name();
        match self.connect() {
            Ok(client) => match client.call_value("ping", json!({})) {
                Ok(_) => {
                    // Browsers connected for fill_login (an older app has no `status`).
                    let status = client.call_value("status", json!({})).unwrap_or(Value::Null);
                    let browsers = status.get("browsers").cloned().unwrap_or_else(|| json!([]));
                    json!({ "mode": "app", "connected": true, "agent_id": client.agent_id, "agent_name": agent_name,
                        "app_version": client.app_version, "browsers": browsers, "endpoint": endpoint })
                }
                Err(e) => {
                    self.client = None;
                    json!({ "mode": "app", "connected": false, "error": describe(&e), "endpoint": endpoint })
                }
            },
            Err(e) => json!({ "mode": "app", "connected": false, "error": describe(&e), "endpoint": endpoint }),
        }
    }

    fn may_run(&self) -> bool {
        true
    }
}

struct StandaloneBackend {
    session: Box<Session>,
    allow_run: bool,
}

impl Backend for StandaloneBackend {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let allowed =
            matches!(method, "search" | "item" | "generate" | "ping") || (method == "read_many" && self.allow_run);
        if !allowed {
            return Err("not available without the 2Secret desktop app, which asks the user for permission: start \
                        2Secret and run `2secret mcp` without --standalone"
                .to_string());
        }
        let request = Request::parse(method, Some(params)).map_err(|e| e.message)?;
        agent::execute_mut(&mut self.session, &request).map_err(|e| e.message)
    }

    fn status(&mut self) -> Value {
        json!({ "mode": "standalone", "connected": false, "allow_run": self.allow_run })
    }

    fn may_run(&self) -> bool {
        self.allow_run
    }
}

/// The two backends behind one type, so [`run`] can hand the app backend
/// the client's name after `initialize`.
enum BackendImpl {
    App(Box<AppBackend>),
    Standalone(Box<StandaloneBackend>),
}

impl Backend for BackendImpl {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        match self {
            BackendImpl::App(b) => b.call(method, params),
            BackendImpl::Standalone(b) => b.call(method, params),
        }
    }
    fn status(&mut self) -> Value {
        match self {
            BackendImpl::App(b) => b.status(),
            BackendImpl::Standalone(b) => b.status(),
        }
    }
    fn may_run(&self) -> bool {
        match self {
            BackendImpl::App(b) => b.may_run(),
            BackendImpl::Standalone(b) => b.may_run(),
        }
    }
}

/// Serve MCP on stdin and stdout until the client closes stdin.
pub fn run(mode: Mode) -> io::Result<()> {
    let mut backend = match mode {
        Mode::App { home, name } => {
            BackendImpl::App(Box::new(AppBackend { home, name, client_info: None, key: None, client: None }))
        }
        Mode::Standalone { session, allow_run } => {
            BackendImpl::Standalone(Box::new(StandaloneBackend { session, allow_run }))
        }
    };
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut server = Server { client_info: None };
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let answer = server.handle(&line, &mut backend);
        // The client's name is known after `initialize`: the app shows it.
        if let (Some(info), BackendImpl::App(app)) = (server.client_info.take(), &mut backend) {
            app.client_info = Some(info);
        }
        if let Some(answer) = answer {
            let mut text = answer.to_string();
            text.push('\n');
            stdout.write_all(text.as_bytes())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

struct Server {
    /// Set by `initialize`, taken by [`run`].
    client_info: Option<(String, String)>,
}

impl Server {
    /// One incoming line; `None` for notifications and unparsable lines.
    fn handle(&mut self, line: &str, backend: &mut dyn Backend) -> Option<Value> {
        let message: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return Some(error(Value::Null, -32700, &format!("parse error: {e}"))),
        };
        let Some(object) = message.as_object() else {
            return Some(error(Value::Null, -32600, "expected a JSON-RPC object"));
        };
        let id = object.get("id").cloned();
        let method = object.get("method").and_then(Value::as_str).unwrap_or_default().to_string();
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        // Notifications (`notifications/initialized`, cancellations) need
        // no answer; neither do answers to requests, which we never send.
        if id.is_none() || id == Some(Value::Null) {
            return None;
        }
        let id = id.expect("checked");
        let result = match method.as_str() {
            "initialize" => {
                let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or_default();
                let version = if PROTOCOL_VERSIONS.contains(&requested) {
                    requested
                } else {
                    PROTOCOL_VERSIONS[PROTOCOL_VERSIONS.len() - 1]
                };
                if let Some(info) = params.get("clientInfo") {
                    let name = info.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
                    let version = info.get("version").and_then(Value::as_str).unwrap_or_default().to_string();
                    if !name.is_empty() {
                        self.client_info = Some((name, version));
                    }
                }
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "2secret", "title": "2Secret", "version": crate::VERSION },
                    "instructions": INSTRUCTIONS,
                })
            }
            "ping" => json!({}),
            "tools/list" => json!({ "tools": tools::definitions() }),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
                if name.is_empty() {
                    return Some(error(id, -32602, "tools/call needs a name"));
                }
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                let out = tools::call_tool(backend, name, arguments);
                json!({ "content": [{ "type": "text", "text": out.text }], "isError": out.is_error })
            }
            "resources/list" => json!({ "resources": [] }),
            "resources/templates/list" => json!({ "resourceTemplates": [] }),
            "prompts/list" => json!({ "prompts": [] }),
            "logging/setLevel" => json!({}),
            other => return Some(error(id, -32601, &format!("method not found: {other}"))),
        };
        Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
