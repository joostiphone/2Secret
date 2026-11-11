//! Vault commands.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};
use clap::Subcommand;
use serde_json::json;
use twosecret_client::folder::{self, MoveTo};
use twosecret_core::crypto::AccountPublicKeys;
use twosecret_core::folder::{Availability, Platform};
use twosecret_core::profile::{FolderService, MoveTarget, Role, VaultLocation};
use twosecret_core::session::{Session, VaultInfo};

use crate::context::{confirm, prompt_secret, Ctx};
use crate::output::{print_json, table};

#[derive(Subcommand)]
pub enum VaultCmd {
    /// List vaults.
    #[command(alias = "ls")]
    List,
    /// Create a vault: on the account's server, or with --device only on
    /// this device, or with --folder in a folder a storage app syncs.
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        /// Keep it only on this device, also when the account has a server.
        #[arg(long, conflicts_with_all = ["folder", "webdav"])]
        device: bool,
        /// Keep it in this folder (iCloud Drive, Dropbox, Google Drive,
        /// OneDrive, Syncthing, a network share): in <folder>/2Secret.
        #[arg(long)]
        folder: Option<PathBuf>,
        /// icloud, dropbox, gdrive, onedrive or other (found from the folder
        /// when left out).
        #[arg(long, requires = "folder")]
        service: Option<String>,
        /// Keep it on a WebDAV server (Nextcloud, ownCloud, a NAS): its
        /// address, or that of a folder on it. The password is asked for, or
        /// read from TWOSECRET_WEBDAV_PASSWORD.
        #[arg(long, conflicts_with = "folder", requires = "user")]
        webdav: Option<String>,
        /// The WebDAV user name.
        #[arg(long)]
        user: Option<String>,
    },
    /// Move a vault: to the server, to this device only, to a folder or to a
    /// WebDAV server.
    Move {
        vault: String,
        /// server, device, folder or webdav
        #[arg(long)]
        to: String,
        /// The folder (with --to folder) or the WebDAV address (with --to
        /// webdav).
        place: Option<String>,
        #[arg(long)]
        service: Option<String>,
        /// The WebDAV user name.
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Add a vault that is in a storage folder or on a WebDAV server (made on
    /// another device).
    Attach {
        /// The vault's folder, or a folder holding it.
        #[arg(required_unless_present = "webdav")]
        folder: Option<PathBuf>,
        #[arg(long)]
        service: Option<String>,
        /// The WebDAV address (of the vault's folder, a folder holding it,
        /// or the server).
        #[arg(long, conflicts_with = "folder", requires = "user")]
        webdav: Option<String>,
        #[arg(long)]
        user: Option<String>,
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
    /// Vaults others shared with you, waiting for you to accept or decline.
    Invitations,
    /// Accept a vault someone shared with you (by name or id).
    Accept { vault: String },
    /// Decline a vault someone shared with you: you leave it.
    Decline { vault: String },
    /// Change the role of a member.
    SetRole { vault: String, email: String, role: String },
    /// Remove someone's access to a vault (the vault gets a new key).
    Unshare { vault: String, email: String },
    /// Give a vault a new key, e.g. after someone left it.
    RotateKey { vault: String },
}

/// Where a vault is, for `vault list`.
fn location(session: &Session, v: &VaultInfo) -> String {
    if let Some(moved) = &v.moved {
        return match &moved.to {
            MoveTarget::Folder { service, .. } => format!("{} (not on this device)", service.name()),
            other => format!("moved to {other}"),
        };
    }
    match &v.location {
        VaultLocation::Account if session.server().is_some() => "server".into(),
        VaultLocation::Account => "this device".into(),
        VaultLocation::Device => "this device only".into(),
        VaultLocation::Folder { service, .. } => service.name().into(),
        VaultLocation::WebDav { url, .. } => format!("WebDAV ({})", twosecret_core::profile::webdav_host(url)),
    }
}

/// An invitation by vault name or id.
fn find_invitation(session: &Session, query: &str) -> Result<twosecret_core::session::Invitation> {
    let all = session.invitations();
    if let Some(inv) = all.iter().find(|i| i.vault_id == query) {
        return Ok(inv.clone());
    }
    let named: Vec<_> = all.iter().filter(|i| i.name.eq_ignore_ascii_case(query)).collect();
    match named.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(anyhow!("no invitation for '{query}' (2secret vault invitations lists them)")),
        _ => Err(anyhow!("several invitations are called '{query}': use the id")),
    }
}

/// The WebDAV password: from TWOSECRET_WEBDAV_PASSWORD, or asked for.
fn webdav_password() -> Result<String> {
    match std::env::var("TWOSECRET_WEBDAV_PASSWORD") {
        Ok(pw) if !pw.is_empty() => Ok(pw),
        _ => prompt_secret("WebDAV password (an app password is best): "),
    }
}

const WEBDAV_NOTE: &str =
    "Vaults on a WebDAV server work in the desktop apps, on iPhone, iPad and Android and on the command line; not in the web vault/browser extension.";

fn service(name: Option<&str>, folder: &std::path::Path) -> Result<FolderService> {
    match name {
        Some(n) => FolderService::parse(n)
            .ok_or_else(|| anyhow!("--service must be icloud, dropbox, gdrive, onedrive or other")),
        None => Ok(folder::service_of(folder).unwrap_or_default()),
    }
}

/// Where a vault in this service's folder will not show up.
pub fn availability_note(service: FolderService) -> String {
    let names = |ps: Vec<Platform>| {
        let names: Vec<&str> = ps.iter().map(|p| p.name()).collect();
        match names.split_last() {
            Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
            _ => names.join(""),
        }
    };
    let missing = service.missing_on();
    let later: Vec<Platform> =
        service.availability().iter().filter(|(_, a)| *a == Availability::Later).map(|(p, _)| *p).collect();
    let mut note = String::new();
    if !missing.is_empty() {
        note.push_str(&format!(
            "{} has no app for {}: this vault will not show up there.",
            service.name(),
            names(missing)
        ));
    }
    if !later.is_empty() {
        if !note.is_empty() {
            note.push(' ');
        }
        note.push_str(&format!(
            "On {} the {} app does not let other apps choose a folder: this vault shows up there once 2Secret connects to {} itself (a later version).",
            names(later),
            service.name(),
            service.name()
        ));
    }
    note
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
                        location(&session, v),
                    ]
                })
                .collect();
            table(&["id", "name", "items", "role", "sharing", "location"], &rows);
            Ok(())
        }
        VaultCmd::Create { name, description, device, folder: dir, service: svc, webdav, user } => {
            let mut session = ctx.unlock()?;
            let id = if let Some(url) = &webdav {
                let to =
                    MoveTo::WebDav { url: url.clone(), user: user.unwrap_or_default(), password: webdav_password()? };
                let id = ctx.block_on(folder::create_vault_in(&mut session, &name, &description, &to))?;
                if !ctx.json {
                    let at = session.vault(&id).map(|v| location(&session, &v)).unwrap_or_default();
                    eprintln!("Created vault '{name}' on {at}.");
                    eprintln!("{WEBDAV_NOTE}");
                }
                id
            } else if let Some(dir) = &dir {
                let svc = service(svc.as_deref(), dir)?;
                let id = ctx.block_on(folder::create_folder_vault(&mut session, &name, &description, dir, svc))?;
                if !ctx.json {
                    let path = session.profile().vault(&id).and_then(|v| v.location.folder().map(String::from));
                    eprintln!("Created vault '{name}' in {}.", path.unwrap_or_default());
                    eprintln!("{}", availability_note(svc));
                }
                id
            } else {
                let location = if device { VaultLocation::Device } else { VaultLocation::Account };
                let id = session.create_vault_at(&name, &description, location)?;
                if !ctx.json {
                    eprintln!("Created vault '{name}'{}.", if device { " on this device only" } else { "" });
                }
                id
            };
            ctx.after_write(&mut session)?;
            if ctx.json {
                print_json(&json!({"id": id}));
            }
            Ok(())
        }
        VaultCmd::Move { vault, to, place, service: svc, user, yes } => {
            let mut session = ctx.unlock()?;
            if ctx.offline {
                bail!("--offline was given");
            }
            let v = session.find_vault(&vault)?;
            let target = match to.trim().to_lowercase().as_str() {
                "server" | "account" => {
                    if session.server().is_none() && v.location.is_account() {
                        bail!("this account has no server; the vault is on this device already");
                    }
                    MoveTo::Account
                }
                "device" | "local" | "here" => MoveTo::Device,
                "folder" => {
                    let dir = PathBuf::from(
                        place.ok_or_else(|| anyhow!("give the folder: vault move <vault> --to folder <folder>"))?,
                    );
                    let svc = service(svc.as_deref(), &dir)?;
                    MoveTo::Folder { parent: dir, service: svc }
                }
                "webdav" => {
                    let url = place.ok_or_else(|| {
                        anyhow!("give the address: vault move <vault> --to webdav <url> --user <name>")
                    })?;
                    let user = user.ok_or_else(|| anyhow!("give the WebDAV user name with --user"))?;
                    MoveTo::WebDav { url, user, password: webdav_password()? }
                }
                _ => bail!("--to must be server, device, folder or webdav"),
            };
            if !yes {
                let mut what = format!("Move vault '{}' ({} items)", v.name, v.item_count);
                match &target {
                    MoveTo::Account => what.push_str(" to the server?"),
                    MoveTo::Device if session.server().is_some() => {
                        what.push_str(" to this device only? Your other devices lose it.")
                    }
                    MoveTo::Device => what.push_str(" to this device only?"),
                    MoveTo::Folder { parent, service } => what.push_str(&format!(
                        " to {} ({})? {}",
                        service.name(),
                        parent.display(),
                        availability_note(*service)
                    )),
                    MoveTo::WebDav { url, .. } => what.push_str(&format!(" to the WebDAV server {url}? {WEBDAV_NOTE}")),
                    MoveTo::Picked { service, .. } => what.push_str(&format!(" to {}?", service.name())),
                }
                if !confirm(&what)? {
                    bail!("aborted");
                }
            }
            let result = ctx.block_on(folder::move_vault(&mut session, &v.id, target));
            ctx.save(&session)?;
            result?;
            let moved = session.vault(&v.id).map(|v| location(&session, &v)).unwrap_or_default();
            eprintln!("Moved '{}': {moved}.", v.name);
            Ok(())
        }
        VaultCmd::Attach { folder: dir, service: svc, webdav, user } => {
            let mut session = ctx.unlock()?;
            let id = match (webdav, dir) {
                (Some(url), _) => {
                    let user = user.unwrap_or_default();
                    ctx.block_on(folder::attach_webdav(&mut session, &url, &user, &webdav_password()?))?
                }
                (None, Some(dir)) => {
                    let svc = svc.as_deref().map(|n| service(Some(n), &dir)).transpose()?;
                    ctx.block_on(folder::attach_folder(&mut session, &dir, svc))?
                }
                (None, None) => bail!("give the folder, or --webdav <url> --user <name>"),
            };
            ctx.save(&session)?;
            let v = session.vault(&id).ok_or_else(|| anyhow!("vault {id}"))?;
            if ctx.json {
                print_json(&json!({"id": id}));
            } else {
                eprintln!("Added vault '{}' ({} items).", v.name, v.item_count);
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
                let what = if v.location.is_folder() {
                    format!(
                        "Delete vault '{}' and its {} items everywhere, with its files in the folder?",
                        v.name, v.item_count
                    )
                } else if v.is_owner {
                    format!("Delete vault '{}' and its {} items for everyone?", v.name, v.item_count)
                } else {
                    format!("Leave the shared vault '{}'?", v.name)
                };
                if !confirm(&what)? {
                    bail!("aborted");
                }
            }
            if v.location.is_folder() {
                ctx.block_on(folder::delete_folder_vault(&mut session, &v.id))?;
            } else {
                session.delete_vault(&v.id)?;
            }
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
                AccountPublicKeys::from_b64(&user.public_key, user.pq_public_key.as_deref())?.fingerprint()
            );
            Ok(())
        }
        VaultCmd::Invitations => {
            let mut session = ctx.unlock()?;
            ctx.block_on(twosecret_client::sync(&mut session))?;
            ctx.save(&session)?;
            let mut rows = Vec::new();
            let mut list = Vec::new();
            for inv in session.invitations() {
                let owner = ctx.block_on(twosecret_client::invitation_owner(&session, &inv.vault_id))?;
                let (who, fingerprint) = owner
                    .map(|m| {
                        let fp = AccountPublicKeys::from_b64(&m.public_key, m.pq_public_key.as_deref())
                            .map(|k| k.fingerprint())
                            .unwrap_or_default();
                        (format!("{} <{}>", m.name, m.email), fp)
                    })
                    .unwrap_or_default();
                rows.push(vec![
                    inv.name.clone(),
                    who.clone(),
                    inv.role.id().to_string(),
                    fingerprint.clone(),
                    inv.vault_id.clone(),
                ]);
                list.push(serde_json::json!({
                    "vault_id": inv.vault_id, "name": inv.name, "role": inv.role.id(),
                    "from": who, "fingerprint": fingerprint,
                }));
            }
            if ctx.json {
                print_json(&list);
            } else if rows.is_empty() {
                eprintln!("No invitations.");
            } else {
                table(&["vault", "from", "role", "fingerprint", "id"], &rows);
                eprintln!("Compare the fingerprint with the person before you accept: 2secret vault accept <vault>");
            }
            Ok(())
        }
        VaultCmd::Accept { vault } => {
            let mut session = ctx.unlock()?;
            let inv = find_invitation(&session, &vault)?;
            ctx.block_on(twosecret_client::accept_invitation(&mut session, &inv.vault_id))?;
            ctx.save(&session)?;
            eprintln!("Accepted '{}'.", inv.name);
            Ok(())
        }
        VaultCmd::Decline { vault } => {
            let mut session = ctx.unlock()?;
            let inv = find_invitation(&session, &vault)?;
            ctx.block_on(twosecret_client::decline_invitation(&mut session, &inv.vault_id))?;
            ctx.save(&session)?;
            eprintln!("Declined '{}'.", inv.name);
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
                        AccountPublicKeys::from_b64(&m.public_key, m.pq_public_key.as_deref())
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
                "Removed {email} and gave '{}' a new key. They may still know secrets they saw before; \
                 change important passwords.",
                v.name
            );
            Ok(())
        }
        VaultCmd::RotateKey { vault } => {
            let mut session = ctx.unlock()?;
            let v = session.find_vault(&vault)?;
            ctx.block_on(twosecret_client::rotate_vault_key(&mut session, &v.id))?;
            ctx.save(&session)?;
            eprintln!("'{}' has a new key; members get it on their next sync.", v.name);
            Ok(())
        }
    }
}
