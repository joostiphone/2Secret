//! Vault commands.

use anyhow::{anyhow, bail, Result};
use clap::Subcommand;
use serde_json::json;
use twosecret_core::profile::Role;

use crate::context::{confirm, Ctx};
use crate::output::{print_json, table};

#[derive(Subcommand)]
pub enum VaultCmd {
    /// List vaults.
    #[command(alias = "ls")]
    List,
    /// Create a vault.
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Rename a vault.
    Rename { vault: String, name: String },
    /// Delete a vault you own (or leave a vault shared with you).
    Delete {
        vault: String,
        #[arg(long)]
        yes: bool,
    },
    /// Share a vault with someone on the same server.
    Share {
        vault: String,
        email: String,
        /// viewer, editor or manager
        #[arg(long, default_value = "editor")]
        role: String,
    },
    /// Show who has access to a vault.
    Members { vault: String },
    /// Change the role of a member.
    SetRole { vault: String, email: String, role: String },
    /// Remove someone's access to a vault.
    Unshare { vault: String, email: String },
}

fn role(s: &str) -> Result<Role> {
    match Role::parse(s) {
        Some(Role::Owner) | None => bail!("role must be viewer, editor or manager"),
        Some(r) => Ok(r),
    }
}

pub fn run(ctx: &Ctx, cmd: VaultCmd) -> Result<()> {
    match cmd {
        VaultCmd::List => {
            let mut session = ctx.unlock()?;
            ctx.refresh(&mut session)?;
            let vaults = session.vaults();
            if ctx.json {
                print_json(&vaults);
                return Ok(());
            }
            let rows: Vec<Vec<String>> = vaults
                .iter()
                .map(|v| {
                    vec![
                        v.id[..8].to_string(),
                        v.name.clone(),
                        v.item_count.to_string(),
                        v.role.id().to_string(),
                        if v.is_shared() { format!("{} members", v.member_count) } else { "private".into() },
                    ]
                })
                .collect();
            table(&["id", "name", "items", "role", "sharing"], &rows);
            Ok(())
        }
        VaultCmd::Create { name, description } => {
            let mut session = ctx.unlock()?;
            let id = session.create_vault(&name, &description)?;
            ctx.after_write(&mut session)?;
            if ctx.json {
                print_json(&json!({"id": id}));
            } else {
                eprintln!("Created vault '{name}'.");
            }
            Ok(())
        }
        VaultCmd::Rename { vault, name } => {
            let mut session = ctx.unlock()?;
            let v = session.find_vault(&vault)?;
            session.update_vault(&v.id, &name, &v.description, None)?;
            ctx.after_write(&mut session)?;
            eprintln!("Renamed '{}' to '{name}'.", v.name);
            Ok(())
        }
        VaultCmd::Delete { vault, yes } => {
            let mut session = ctx.unlock()?;
            let v = session.find_vault(&vault)?;
            if !yes {
                let what = if v.is_owner {
                    format!("Delete vault '{}' and its {} items for everyone?", v.name, v.item_count)
                } else {
                    format!("Leave the shared vault '{}'?", v.name)
                };
                if !confirm(&what)? {
                    bail!("aborted");
                }
            }
            session.delete_vault(&v.id)?;
            ctx.after_write(&mut session)?;
            eprintln!("Done.");
            Ok(())
        }
        VaultCmd::Share { vault, email, role: r } => {
            let mut session = ctx.unlock()?;
            let v = session.find_vault(&vault)?;
            let r = role(&r)?;
            let user = ctx.block_on(twosecret_client::share_vault(&mut session, &v.id, &email, r))?;
            ctx.save(&session)?;
            eprintln!(
                "Shared '{}' with {} <{}> as {}.\nVerify their key fingerprint out of band: {}",
                v.name,
                user.name,
                user.email,
                r.id(),
                twosecret_core::crypto::PublicKey::from_b64(&user.public_key)?.fingerprint()
            );
            Ok(())
        }
        VaultCmd::Members { vault } => {
            let session = ctx.unlock()?;
            let v = session.find_vault(&vault)?;
            let members = ctx.block_on(twosecret_client::vault_members(&session, &v.id))?;
            if ctx.json {
                print_json(&members);
                return Ok(());
            }
            let rows: Vec<Vec<String>> = members
                .iter()
                .map(|m| {
                    vec![
                        m.name.clone(),
                        m.email.clone(),
                        m.role.id().to_string(),
                        twosecret_core::crypto::PublicKey::from_b64(&m.public_key)
                            .map(|k| k.fingerprint())
                            .unwrap_or_default(),
                    ]
                })
                .collect();
            table(&["name", "email", "role", "fingerprint"], &rows);
            Ok(())
        }
        VaultCmd::SetRole { vault, email, role: r } => {
            let mut session = ctx.unlock()?;
            let v = session.find_vault(&vault)?;
            let members = ctx.block_on(twosecret_client::vault_members(&session, &v.id))?;
            let m = members
                .iter()
                .find(|m| m.email.eq_ignore_ascii_case(email.trim()))
                .ok_or_else(|| anyhow!("{email} is not a member of '{}'", v.name))?;
            ctx.block_on(twosecret_client::set_member_role(&mut session, &v.id, &m.account_id, role(&r)?))?;
            ctx.save(&session)?;
            eprintln!("Updated.");
            Ok(())
        }
        VaultCmd::Unshare { vault, email } => {
            let mut session = ctx.unlock()?;
            let v = session.find_vault(&vault)?;
            let members = ctx.block_on(twosecret_client::vault_members(&session, &v.id))?;
            let m = members
                .iter()
                .find(|m| m.email.eq_ignore_ascii_case(email.trim()))
                .ok_or_else(|| anyhow!("{email} is not a member of '{}'", v.name))?;
            ctx.block_on(twosecret_client::remove_member(&mut session, &v.id, &m.account_id))?;
            ctx.save(&session)?;
            eprintln!(
                "Removed {email}. Note: they may still know secrets they saw before; change important passwords."
            );
            Ok(())
        }
    }
}
