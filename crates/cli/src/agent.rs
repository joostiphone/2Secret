//! `2secret mcp` and `2secret agent …`: Agent Access for AI tools.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use serde_json::json;
use twosecret_agent::client::{endpoint, AppClient};
use twosecret_agent::key::AgentKey;
use twosecret_agent::mcp::{self, Mode};
use twosecret_agent::native_host::{self, Os, Place};
use twosecret_agent::remote::{self, Pairing, RemoteBackend};
use twosecret_client::OFFICIAL_SERVER;
use twosecret_core::agent_remote::PairingCode;

use crate::context::Ctx;
use crate::output::print_json;

#[derive(Subcommand)]
pub enum AgentCmd {
    /// Whether the 2Secret app is reachable for agents, the agents known on this computer, which browsers
    /// are set up to fill logins for agents, and the pairings with 2Secret accounts elsewhere.
    Status,
    /// Pair this computer with a 2Secret account on another computer: paste the code from 2Secret → Settings →
    /// Agents elsewhere → Pair an agent. The owner then confirms the agent there, and AI tools on this computer
    /// use 2Secret with `2secret mcp --remote`.
    Pair {
        /// The pairing code or link, as 2Secret shows it.
        code: String,
        /// How the owner sees this agent (default: this computer's name).
        #[arg(long)]
        name: Option<String>,
        /// The sync server, when the code is not a link and the server is not sync.2secret.app.
        #[arg(long)]
        server: Option<String>,
    },
    /// Forget a pairing on this computer (the owner revokes it in 2Secret under Agents elsewhere).
    Unpair {
        /// The pairing's name; the only one when left out.
        name: Option<String>,
    },
    /// Sign in on a website in the browser on this computer through the relay: the owner allows it in 2Secret,
    /// and the login goes straight into the page through the browser's debugging port.
    Fill {
        /// Item id, exact title or a 2s:// reference.
        #[arg(long)]
        item: String,
        /// The sign-in page that is open in the browser.
        #[arg(long)]
        url: String,
        /// The browser's debugging port (`--remote-debugging-port=9222` → 127.0.0.1:9222).
        #[arg(long, default_value = "127.0.0.1:9222")]
        cdp: String,
        /// Only fill, do not submit the form.
        #[arg(long)]
        no_submit: bool,
        /// The pairing to use; the only one when left out.
        #[arg(long)]
        pairing: Option<String>,
    },
}

/// `2secret mcp`: serve MCP on stdin and stdout.
pub fn mcp(
    ctx: &Ctx,
    standalone: bool,
    allow_run: bool,
    name: Option<String>,
    remote: Option<String>,
    cdp: Option<String>,
) -> Result<()> {
    if let Some(pairing) = remote {
        let pairing = Some(pairing).filter(|p| !p.trim().is_empty());
        // Said once, so a missing pairing is clear before the first tool call.
        if let Err(e) = Pairing::choose(&ctx.home, pairing.as_deref()) {
            eprintln!("2secret mcp --remote: {e}");
        }
        mcp::run(Mode::Remote { home: ctx.home.clone(), name: pairing, cdp })?;
    } else if standalone {
        eprintln!(
            "2secret mcp --standalone: working on the vault directly. Nobody is asked for permission, so only \
             searching, showing items without secrets and generating passwords are available{}.",
            if allow_run { ", plus run_command (--allow-run)" } else { "" }
        );
        let mut session = ctx.unlock()?;
        ctx.refresh(&mut session)?;
        mcp::run(Mode::Standalone { session: Box::new(session), allow_run })?;
    } else {
        mcp::run(Mode::App { home: ctx.home.clone(), name })?;
    }
    Ok(())
}

pub fn run(ctx: &Ctx, cmd: AgentCmd) -> Result<()> {
    match cmd {
        AgentCmd::Status => status(ctx),
        AgentCmd::Pair { code, name, server } => pair(ctx, &code, name, server),
        AgentCmd::Unpair { name } => unpair(ctx, name),
        AgentCmd::Fill { item, url, cdp, no_submit, pairing } => fill(ctx, &item, &url, &cdp, !no_submit, pairing),
    }
}

fn pair(ctx: &Ctx, code: &str, name: Option<String>, server: Option<String>) -> Result<()> {
    let server = server.unwrap_or_else(|| OFFICIAL_SERVER.to_string());
    let code = PairingCode::parse(code, Some(&server)).context("the pairing code is not valid")?;
    let name = name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .or_else(remote::device_name)
        .unwrap_or_else(|| "Agent".to_string());
    let paired = remote::pair(&ctx.home, &name, &code, twosecret_agent::VERSION).map_err(|e| anyhow::anyhow!("{e}"))?;
    if ctx.json {
        print_json(&paired);
        return Ok(());
    }
    println!("Paired with the 2Secret account {} on {}.", paired.account_fingerprint, paired.server);
    println!("Agent:       {} ({})", paired.name, paired.agent_id);
    println!("Fingerprint: {}", paired.fingerprint);
    println!();
    println!("Now confirm the agent in 2Secret (the dialog shows the same fingerprint). Then add 2Secret to your AI");
    println!("tool with the command: 2secret mcp --remote {}", shell_word(&paired.name));
    println!("For fill_login, start the browser here with --remote-debugging-port=9222 and add --cdp 127.0.0.1:9222.");
    Ok(())
}

/// A name as a shell argument.
fn shell_word(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn unpair(ctx: &Ctx, name: Option<String>) -> Result<()> {
    let pairing = Pairing::choose(&ctx.home, name.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))?;
    if !Pairing::remove(&ctx.home, &pairing.name)? {
        bail!("no pairing called '{}'", pairing.name);
    }
    if ctx.json {
        print_json(&json!({ "removed": pairing.name, "agent_id": pairing.agent_id }));
    } else {
        println!("Forgot the pairing '{}' ({}).", pairing.name, pairing.agent_id);
        println!("Revoke the agent in 2Secret as well: Settings → Agents elsewhere.");
    }
    Ok(())
}

fn fill(ctx: &Ctx, item: &str, url: &str, cdp: &str, submit: bool, pairing: Option<String>) -> Result<()> {
    let mut backend = RemoteBackend::new(ctx.home.clone(), pairing, Some(cdp.to_string()))?;
    eprintln!("Waiting for the owner to allow this in 2Secret…");
    let login = backend
        .request("fill", json!({ "item": item, "url": url, "submit": submit }))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let result =
        twosecret_agent::tools::fill_through_browser(&mut backend, login).map_err(|e| anyhow::anyhow!("{e}"))?;
    if ctx.json {
        print_json(&result);
    } else {
        println!(
            "Filled in {}{}.",
            result["browser"].as_str().unwrap_or("the browser"),
            if result["submitted"].as_bool().unwrap_or(false) { " and submitted" } else { "" }
        );
    }
    Ok(())
}

fn status(ctx: &Ctx) -> Result<()> {
    let endpoint = endpoint(&ctx.home);
    let reachable = AppClient::connect(&ctx.home).is_ok();
    let agents: Vec<(String, String)> =
        AgentKey::list(&ctx.home).into_iter().map(|(slug, key)| (slug, key.id())).collect();
    let browsers = registered_browsers();
    let pairings = Pairing::list(&ctx.home);
    if ctx.json {
        print_json(&json!({
            "endpoint": endpoint,
            "app_reachable": reachable,
            "agents": agents.iter().map(|(client, id)| json!({ "client": client, "agent_id": id })).collect::<Vec<_>>(),
            "browsers": browsers,
            "pairings": pairings.iter().map(|(_, p)| json!({ "name": p.name, "server": p.server, "agent_id": p.agent_id,
                "fingerprint": p.fingerprint(), "account_fingerprint": p.account_fingerprint })).collect::<Vec<_>>(),
        }));
        return Ok(());
    }
    println!("2Secret app: {}", if reachable { "reachable for agents" } else { "not reachable" });
    println!("Endpoint:    {endpoint}");
    if !reachable {
        println!("             Start 2Secret and turn on AI agents under Settings → Desktop app.");
    }
    if agents.is_empty() {
        println!("Agents:      none yet (an AI tool gets a key the first time it connects)");
    } else {
        println!("Agents known on this computer (client, agent id as 2Secret shows it):");
        for (client, id) in agents {
            println!("  {client:<24} {id}");
        }
    }
    if browsers.is_empty() {
        println!(
            "Browsers:    none set up to fill logins for agents (2Secret → Settings → Desktop app → Browser connection)"
        );
    } else {
        println!("Browsers:    set up to fill logins for agents: {}", browsers.join(", "));
    }
    if pairings.is_empty() {
        println!("Elsewhere:   not paired with a 2Secret account on another computer (2secret agent pair <code>)");
    } else {
        println!("Paired with 2Secret accounts elsewhere (use with 2secret mcp --remote <name>):");
        for (_, p) in pairings {
            println!("  {:<24} {} on {}", p.name, p.agent_id, p.server);
            println!("  {:<24} fingerprint {} · account {}", "", p.fingerprint(), p.account_fingerprint);
        }
    }
    Ok(())
}

/// The browsers whose native messaging host manifest for 2Secret exists
/// (a file on macOS and Linux, a registry value on Windows).
fn registered_browsers() -> Vec<String> {
    let Some(os) = Os::current() else { return Vec::new() };
    let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(std::path::PathBuf::from)
    else {
        return Vec::new();
    };
    let config =
        std::env::var_os("XDG_CONFIG_HOME").map(std::path::PathBuf::from).unwrap_or_else(|| home.join(".config"));
    native_host::locations(os, &home, &config)
        .into_iter()
        .filter(|l| match &l.place {
            Place::Dir(_) => l.manifest_path().is_some_and(|p| p.is_file()),
            Place::Registry(key) => registry_value_exists(key),
        })
        .map(|l| l.browser.label().to_string())
        .collect()
}

#[cfg(windows)]
fn registry_value_exists(key: &str) -> bool {
    // `reg query` is always there; the default value is listed as `(Default)`.
    std::process::Command::new("reg")
        .args(["query", &format!(r"HKCU\{key}"), "/ve"])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(not(windows))]
fn registry_value_exists(_key: &str) -> bool {
    false
}
