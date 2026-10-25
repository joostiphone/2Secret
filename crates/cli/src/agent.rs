//! `2secret mcp` and `2secret agent …`: Agent Access for AI tools.

use anyhow::Result;
use clap::Subcommand;
use serde_json::json;
use twosecret_agent::client::{endpoint, AppClient};
use twosecret_agent::key::AgentKey;
use twosecret_agent::mcp::{self, Mode};

use crate::context::Ctx;
use crate::output::print_json;

#[derive(Subcommand)]
pub enum AgentCmd {
    /// Whether the 2Secret app is reachable for agents, and the agents known on this computer.
    Status,
}

/// `2secret mcp`: serve MCP on stdin and stdout.
pub fn mcp(ctx: &Ctx, standalone: bool, allow_run: bool, name: Option<String>) -> Result<()> {
    if standalone {
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
    }
}

fn status(ctx: &Ctx) -> Result<()> {
    let endpoint = endpoint(&ctx.home);
    let reachable = AppClient::connect(&ctx.home).is_ok();
    let agents: Vec<(String, String)> =
        AgentKey::list(&ctx.home).into_iter().map(|(slug, key)| (slug, key.id())).collect();
    if ctx.json {
        print_json(&json!({
            "endpoint": endpoint,
            "app_reachable": reachable,
            "agents": agents.iter().map(|(client, id)| json!({ "client": client, "agent_id": id })).collect::<Vec<_>>(),
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
    Ok(())
}
