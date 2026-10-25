//! # twosecret-agent
//!
//! Agent Access for AI agents: `2secret mcp` speaks the Model Context
//! Protocol (JSON-RPC 2.0 over stdin and stdout) to an AI client such as
//! Claude Code, Claude Desktop, Cursor or Codex, and forwards what the agent
//! wants to the running 2Secret desktop app over a local socket
//! ([`client`]). The app asks the user before any secret leaves the vault
//! (`twosecret_core::agent` has the protocol and the rules).
//!
//! The agent has its own Ed25519 key ([`key`]), so the app recognises it
//! the next time. Secrets that an agent runs a command with are filtered out
//! of the command's output before the model sees it ([`scrub`]).
//!
//! The same crate holds the browser side of agentic autofill: the native
//! messaging host that the 2Secret browser extension starts ([`host`]), which
//! connects to the app as a browser and fills the logins the user allows an
//! agent to use, and where each browser looks for it ([`native_host`]).

pub mod client;
pub mod host;
pub mod key;
pub mod mcp;
pub mod native_host;
pub mod scrub;
pub mod tools;

pub use client::{AppClient, ClientError};
pub use key::AgentKey;
pub use mcp::{run, Mode};

/// Version of this crate (the MCP server's version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name of the program that started this process, as far as it can be
/// told without privileges: the AI client, when it starts `2secret mcp`
/// directly. It is only a claim; the app checks the parent itself.
pub fn parent_process_name() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let ppid = std::os::unix::process::parent_id();
        let name = std::fs::read_to_string(format!("/proc/{ppid}/comm")).ok()?;
        let name = name.trim();
        return (!name.is_empty()).then(|| name.to_string());
    }
    #[cfg(target_os = "macos")]
    {
        let ppid = std::os::unix::process::parent_id();
        let out = std::process::Command::new("/bin/ps").args(["-o", "comm=", "-p", &ppid.to_string()]).output().ok()?;
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        return (!name.is_empty()).then_some(name);
    }
    #[allow(unreachable_code)]
    None
}
