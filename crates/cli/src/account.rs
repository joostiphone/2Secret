//! `2secret account …` and `2secret status`.

use anyhow::{bail, Result};
use clap::Subcommand;
use serde_json::json;
use twosecret_core::crypto::SecretKey;
use twosecret_core::session::{Session, MIN_PASSWORD_LEN};
use twosecret_core::storage::Storage;
use twosecret_core::strength::{estimate, StrengthLevel};
use twosecret_core::util::format_timestamp;
use twosecret_core::{emergency_kit, profile::DEVICE_KEY, profile::PROFILE_KEY};

use crate::context::{confirm, device_name, prompt, prompt_secret, value_or_prompt, Ctx};
use crate::output::{print_json, table};

#[derive(Subcommand)]
pub enum AccountCmd {
    /// Create a new account (local-only, or on a sync server with --server).
    Create {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        email: Option<String>,
        /// Sync server address, e.g. https://vault.example.com
        #[arg(long)]
        server: Option<String>,
        /// Invite code, when the server requires one.
        #[arg(long)]
        invite: Option<String>,
    },
    /// Sign in to an existing server account on this device.
    Signin {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        email: Option<String>,
        /// Secret Key from your Emergency Kit.
        #[arg(long)]
        secret_key: Option<String>,
    },
    /// Upload this local account to a sync server.
    Connect {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        invite: Option<String>,
    },
    /// Show account details.
    Info,
    /// Change the master password.
    ChangePassword,
    /// Show the Secret Key (requires the master password).
    SecretKey,
    /// Write a printable Emergency Kit (HTML).
    EmergencyKit {
        #[arg(short, long, default_value = "2Secret-Emergency-Kit.html")]
        output: std::path::PathBuf,
    },
    /// List devices signed in to the server.
    Devices,
    /// Sign a device out of the server.
    RevokeDevice { id: String },
    /// Sign this device out of the server (local data is kept).
    Signout,
    /// Sign in to the server again after the session expired.
    Reauth,
    /// Permanently delete the account from the server (local copy is kept).
    DeleteServerAccount,
    /// Remove all 2Secret data from this device.
    Forget {
        #[arg(long)]
        yes: bool,
    },
}

fn new_password() -> Result<String> {
    loop {
        let pw = prompt_secret("Choose a master password: ")?;
        if pw.chars().count() < MIN_PASSWORD_LEN {
            eprintln!("The master password must be at least {MIN_PASSWORD_LEN} characters.");
            continue;
        }
        let s = estimate(&pw, &[]);
        eprintln!("Strength: {} (estimated cracking time: {})", s.level.label(), s.crack_time);
        if let Some(w) = &s.warning {
            eprintln!("  {w}");
        }
        if s.level < StrengthLevel::Fair && !confirm("This password is weak. Use it anyway?")? {
            continue;
        }
        let again = prompt_secret("Repeat the master password: ")?;
        if again != pw {
            eprintln!("The passwords do not match, try again.");
            continue;
        }
        return Ok(pw);
    }
}

fn print_secret_key_notice(session: &Session, sk: &SecretKey) {
    let acc = session.account();
    eprintln!();
    eprintln!("Your account has been created.");
    eprintln!();
    eprintln!("    Secret Key: {}", sk.formatted());
    eprintln!();
    eprintln!("You need this Secret Key together with your master password to sign in on a");
    eprintln!("new device. Save your Emergency Kit now:");
    eprintln!("    2secret account emergency-kit");
    eprintln!();
    let _ = acc;
}

pub fn run(ctx: &Ctx, cmd: AccountCmd) -> Result<()> {
    match cmd {
        AccountCmd::Create { name, email, server, invite } => {
            if ctx.has_profile() {
                bail!("there already is an account on this device (data directory {})", ctx.home.display());
            }
            let name = value_or_prompt(name, "Your name")?;
            let email = value_or_prompt(email, "E-mail address")?;
            let password = new_password()?;
            eprintln!("Creating your account…");
            let (session, sk) = match server {
                Some(url) => ctx.block_on(twosecret_client::signup(
                    &url,
                    &name,
                    &email,
                    &password,
                    invite.as_deref(),
                    &device_name(),
                    "Personal",
                    Ctx::kdf_for_new_accounts(),
                ))?,
                None => Session::create_account(&name, &email, &password, Ctx::kdf_for_new_accounts(), "Personal")?,
            };
            ctx.save_new(&session, &sk)?;
            if ctx.json {
                print_json(&json!({"account_id": session.account().id, "secret_key": sk.formatted()}));
            } else {
                print_secret_key_notice(&session, &sk);
            }
            Ok(())
        }
        AccountCmd::Signin { server, email, secret_key } => {
            if ctx.has_profile() {
                bail!("there already is an account on this device; run `2secret account forget` first");
            }
            let server = value_or_prompt(server, "Server address")?;
            let email = value_or_prompt(email, "E-mail address")?;
            let sk_text = match secret_key {
                Some(s) => s,
                None => prompt_secret("Secret Key: ")?,
            };
            let sk = SecretKey::parse(&sk_text)?;
            let password = ctx.master_password("Master password: ")?;
            eprintln!("Signing in…");
            let session = ctx.block_on(twosecret_client::signin(&server, &email, &password, &sk, &device_name()))?;
            ctx.save_new(&session, &sk)?;
            eprintln!(
                "Signed in as {}. {} vaults, {} items.",
                session.account().email,
                session.vaults().len(),
                session.item_count()
            );
            Ok(())
        }
        AccountCmd::Connect { server, invite } => {
            let (mut session, password, sk) = ctx.unlock_with_password()?;
            if session.server().is_some() {
                bail!(
                    "this account is already connected to {}",
                    session.server().map(|s| s.url.as_str()).unwrap_or("")
                );
            }
            let server = value_or_prompt(server, "Server address")?;
            let report = ctx.block_on(twosecret_client::connect(
                &mut session,
                &server,
                &password,
                &sk,
                invite.as_deref(),
                &device_name(),
            ))?;
            ctx.save(&session)?;
            eprintln!("Connected. Uploaded {} items.", report.uploaded);
            Ok(())
        }
        AccountCmd::Info => {
            let session = ctx.unlock()?;
            let acc = session.account();
            let sk = ctx.secret_key()?;
            if ctx.json {
                print_json(&json!({
                    "account_id": acc.id,
                    "name": acc.name,
                    "email": acc.email,
                    "created_at": acc.created_at,
                    "server": session.server().map(|s| &s.url),
                    "public_key_fingerprint": session.public_keys().fingerprint(),
                    "kdf": acc.kdf,
                }));
            } else {
                println!("Name:         {}", acc.name);
                println!("E-mail:       {}", acc.email);
                println!("Account ID:   {}", acc.id);
                println!("Created:      {}", format_timestamp(acc.created_at));
                println!("Secret Key:   {}", sk.masked());
                println!("Server:       {}", session.server().map(|s| s.url.as_str()).unwrap_or("local only"));
                println!("Fingerprint:  {}", session.public_keys().fingerprint());
                println!(
                    "KDF:          Argon2id, {} MiB, {} iterations, {} lanes",
                    acc.kdf.memory_kib / 1024,
                    acc.kdf.iterations,
                    acc.kdf.parallelism
                );
            }
            Ok(())
        }
        AccountCmd::ChangePassword => {
            let (mut session, current, sk) = ctx.unlock_with_password()?;
            let new = new_password()?;
            if session.server().is_some() && !ctx.offline {
                ctx.block_on(twosecret_client::change_password(&mut session, &current, &new, &sk))?;
            } else if session.server().is_some() {
                bail!("changing the password of a server account requires a connection");
            } else {
                let change = session.prepare_password_change(&current, &new, &sk)?;
                session.commit_password_change(&change);
            }
            ctx.save(&session)?;
            ctx.destroy_cli_session()?;
            eprintln!("Master password changed. Other devices have been signed out and need the new password.");
            Ok(())
        }
        AccountCmd::SecretKey => {
            let (_session, _pw, sk) = ctx.unlock_with_password()?;
            println!("{}", sk.formatted());
            Ok(())
        }
        AccountCmd::EmergencyKit { output } => {
            let (session, _pw, sk) = ctx.unlock_with_password()?;
            let acc = session.account();
            let html = emergency_kit::html(&acc.name, &acc.email, session.server().map(|s| s.url.as_str()), &sk);
            std::fs::write(&output, html)?;
            eprintln!("Emergency Kit written to {}. Print it, store it safely and delete the file.", output.display());
            Ok(())
        }
        AccountCmd::Devices => {
            let session = ctx.unlock()?;
            let devices = ctx.block_on(twosecret_client::client_for(&session)?.devices())?;
            if ctx.json {
                print_json(&devices);
            } else {
                let rows: Vec<Vec<String>> = devices
                    .iter()
                    .map(|d| {
                        vec![
                            d.id.clone(),
                            format!("{}{}", d.name, if d.current { " (this device)" } else { "" }),
                            format_timestamp(d.last_used_at),
                        ]
                    })
                    .collect();
                table(&["id", "device", "last used"], &rows);
            }
            Ok(())
        }
        AccountCmd::RevokeDevice { id } => {
            let session = ctx.unlock()?;
            ctx.block_on(twosecret_client::client_for(&session)?.revoke_device(&id))?;
            eprintln!("Device signed out.");
            Ok(())
        }
        AccountCmd::Signout => {
            let mut session = ctx.unlock()?;
            ctx.block_on(twosecret_client::sign_out(&mut session))?;
            ctx.save(&session)?;
            eprintln!("Signed out of the server. Your data stays available offline.");
            Ok(())
        }
        AccountCmd::Reauth => {
            let (mut session, pw, sk) = ctx.unlock_with_password()?;
            ctx.block_on(twosecret_client::reauthenticate(&mut session, &pw, &sk, &device_name()))?;
            ctx.block_on(twosecret_client::sync(&mut session))?;
            ctx.save(&session)?;
            eprintln!("Signed in again.");
            Ok(())
        }
        AccountCmd::DeleteServerAccount => {
            let (mut session, pw, sk) = ctx.unlock_with_password()?;
            eprintln!("This permanently deletes your account and all vaults you own from the server.");
            eprintln!("Vaults shared with others are deleted for them too. Your local copy is kept.");
            let typed = prompt(&format!("Type your e-mail address ({}) to confirm: ", session.account().email))?;
            if typed.trim().to_lowercase() != session.account().email {
                bail!("aborted");
            }
            ctx.block_on(twosecret_client::delete_server_account(&mut session, &pw, &sk))?;
            ctx.save(&session)?;
            eprintln!("The server account has been deleted. This device now holds a local-only account.");
            Ok(())
        }
        AccountCmd::Forget { yes } => {
            if !ctx.has_profile() {
                eprintln!("Nothing to forget.");
                return Ok(());
            }
            if !yes {
                let profile = ctx.load_profile()?;
                eprintln!("This removes {} and all its vaults from this device.", profile.account.email);
                if profile.server.is_none() {
                    eprintln!("WARNING: this is a local-only account. Without an export, the data is gone forever.");
                }
                if !confirm("Continue?")? {
                    bail!("aborted");
                }
            }
            ctx.destroy_cli_session()?;
            ctx.storage.delete(PROFILE_KEY)?;
            ctx.storage.delete(DEVICE_KEY)?;
            eprintln!("All 2Secret data was removed from this device.");
            Ok(())
        }
    }
}

pub fn status(ctx: &Ctx) -> Result<()> {
    if !ctx.has_profile() {
        if ctx.json {
            print_json(&json!({"account": null}));
        } else {
            println!("No account on this device. Run `2secret account create` or `2secret account signin`.");
        }
        return Ok(());
    }
    let p = ctx.load_profile()?;
    let pending = p.items.iter().filter(|i| i.dirty).count();
    if ctx.json {
        print_json(&json!({
            "account": p.account.email,
            "server": p.server.as_ref().map(|s| &s.url),
            "signed_in": p.server.as_ref().map(|s| s.token.is_some()),
            "last_sync_at": p.server.as_ref().and_then(|s| s.last_sync_at),
            "vaults": p.vaults.len(),
            "items": p.items.iter().filter(|i| i.data.is_some()).count(),
            "pending_changes": pending,
            "shell_session": ctx.has_cli_session() && std::env::var(crate::context::SESSION_ENV).is_ok(),
            "data_dir": ctx.home,
        }));
        return Ok(());
    }
    println!("Account:   {} ({})", p.account.email, p.account.name);
    match &p.server {
        Some(s) => {
            println!(
                "Server:    {}{}",
                s.url,
                if s.token.is_some() { "" } else { " (signed out – run `2secret account reauth`)" }
            );
            println!("Last sync: {}", s.last_sync_at.map(format_timestamp).unwrap_or_else(|| "never".into()));
        }
        None => println!("Server:    none (local-only account)"),
    }
    print!("Vaults:    {}   Items: {}", p.vaults.len(), p.items.iter().filter(|i| i.data.is_some()).count());
    if p.server.is_some() {
        print!("   Unsynced changes: {pending}");
    }
    println!();
    println!(
        "Unlocked:  {}",
        if ctx.has_cli_session() && std::env::var(crate::context::SESSION_ENV).is_ok() {
            "yes (shell session)"
        } else {
            "no"
        }
    );
    println!("Data dir:  {}", ctx.home.display());
    Ok(())
}
