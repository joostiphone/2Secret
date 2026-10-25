//! The client of the desktop app's Agent Access socket: `access.sock` in the
//! data directory (a named pipe per user on Windows), JSON-RPC 2.0 with one
//! object per line. See `twosecret_core::agent` for the messages.

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use twosecret_core::agent::{AgentError, AuthResult, HelloParams, HelloResult, MAX_LINE, PROTOCOL};

use crate::key::AgentKey;

/// How long to wait for an answer: the app gives the user 120 s.
pub const READ_TIMEOUT: Duration = Duration::from_secs(130);

#[cfg(unix)]
pub const SOCKET: &str = "access.sock";

/// Where the app listens for agents, for `home`.
#[cfg(unix)]
pub fn socket_path(home: &Path) -> PathBuf {
    home.join(SOCKET)
}

/// One pipe per data directory, so per user (like the app's link pipe).
#[cfg(windows)]
pub fn pipe_name(home: &Path) -> String {
    format!(r"\\.\pipe\2Secret agent {}", home.to_string_lossy().replace('\\', "/"))
}

/// Where the app listens, as text for messages to people.
pub fn endpoint(home: &Path) -> String {
    #[cfg(unix)]
    {
        socket_path(home).to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        pipe_name(home)
    }
}

#[derive(Debug)]
pub enum ClientError {
    /// The app is not running, or Agent Access is off.
    NotRunning(io::Error),
    Io(io::Error),
    /// The app answered something that is not JSON-RPC.
    Protocol(String),
    /// The app refused or failed the request.
    Rpc(AgentError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::NotRunning(_) => write!(
                f,
                "2Secret is not running, or Agent Access is turned off (2Secret → Settings → Desktop app → AI agents)"
            ),
            ClientError::Io(e) => write!(f, "connection to 2Secret lost: {e}"),
            ClientError::Protocol(m) => write!(f, "unexpected answer from 2Secret: {m}"),
            ClientError::Rpc(e) => write!(f, "{}", e.message),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<AgentError> for ClientError {
    fn from(e: AgentError) -> Self {
        ClientError::Rpc(e)
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(e: serde_json::Error) -> Self {
        ClientError::Protocol(e.to_string())
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// A connection to the app, after `hello` and `auth`.
pub struct AppClient {
    reader: BufReader<Box<dyn Stream>>,
    writer: Box<dyn Stream>,
    next_id: u64,
    /// The id the app gave this agent.
    pub agent_id: Option<String>,
}

impl AppClient {
    /// Connect to the app for the data directory `home`.
    pub fn connect(home: &Path) -> Result<AppClient, ClientError> {
        let (reader, writer) = open(home).map_err(ClientError::NotRunning)?;
        Ok(AppClient { reader: BufReader::new(reader), writer, next_id: 1, agent_id: None })
    }

    /// Introduce the agent and prove its key.
    pub fn hello_auth(
        &mut self,
        key: &AgentKey,
        name: &str,
        version: &str,
        parent: Option<&str>,
    ) -> Result<AuthResult, ClientError> {
        let hello = HelloParams {
            protocol: PROTOCOL,
            name: name.to_string(),
            version: version.to_string(),
            agent_key: key.public_key_b64(),
            parent: parent.map(str::to_string),
        };
        let answer: HelloResult = self.call("hello", serde_json::to_value(&hello)?)?;
        if answer.protocol != PROTOCOL {
            return Err(ClientError::Protocol(format!(
                "2Secret speaks agent protocol {}, this program protocol {PROTOCOL}; update one of them",
                answer.protocol
            )));
        }
        let signature = key.sign_hello(&answer.nonce).map_err(|e| ClientError::Protocol(e.to_string()))?;
        let auth: AuthResult = self.call("auth", json!({ "signature": signature }))?;
        self.agent_id = Some(auth.agent_id.clone());
        Ok(auth)
    }

    /// One request, typed answer.
    pub fn call<T: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<T, ClientError> {
        Ok(serde_json::from_value(self.call_value(method, params)?)?)
    }

    /// One request, the raw `result`.
    pub fn call_value(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line =
            serde_json::to_string(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))?;
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()?;
        let mut answer = String::new();
        loop {
            answer.clear();
            let n = self.reader.read_line(&mut answer)?;
            if n == 0 {
                return Err(ClientError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "2Secret closed the connection",
                )));
            }
            if answer.len() > MAX_LINE {
                return Err(ClientError::Protocol("answer too long".into()));
            }
            if answer.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(&answer)?;
            // Only our own answer counts; the app sends nothing else.
            if value.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = value.get("error") {
                let e: AgentError = serde_json::from_value(error.clone())
                    .unwrap_or_else(|_| AgentError::new(AgentError::INTERNAL, error.to_string()));
                return Err(ClientError::Rpc(e));
            }
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

#[cfg(unix)]
fn open(home: &Path) -> io::Result<(Box<dyn Stream>, Box<dyn Stream>)> {
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(socket_path(home))?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let writer = stream.try_clone()?;
    Ok((Box::new(stream), Box::new(writer)))
}

#[cfg(windows)]
fn open(home: &Path) -> io::Result<(Box<dyn Stream>, Box<dyn Stream>)> {
    let file = std::fs::OpenOptions::new().read(true).write(true).open(pipe_name(home))?;
    let writer = file.try_clone()?;
    Ok((Box::new(file), Box::new(writer)))
}
