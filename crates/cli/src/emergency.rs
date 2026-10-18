//! Emergency access commands.

use anyhow::{anyhow, bail, Result};
use clap::Subcommand;
use twosecret_core::api::{EmergencyContactDto, EmergencyOverview};
use twosecret_core::crypto::AccountPublicKeys;
use twosecret_core::util::format_timestamp;

use crate::context::Ctx;
use crate::output::{print_json, table};

#[derive(Subcommand)]
pub enum EmergencyCmd {
    /// Who you trust, and who trusts you.
    #[command(alias = "ls")]
    List,
    /// Trust someone on the same server: they can ask for read access to the
    /// vaults you own, and get it after the waiting period unless you deny.
    Add {
        email: String,
        /// Days between their request and their access (1 to 90).
        #[arg(long, default_value_t = 7)]
        wait: u32,
    },
    /// Stop trusting someone, or stop being someone's contact (access they
    /// had ends and the vaults get new keys).
    Remove { email: String },
    /// Ask someone who trusts you for access.
    Request { email: String },
    /// Withdraw your request.
    Cancel { email: String },
    /// Give a contact who asked access now.
    Approve { email: String },
    /// Deny a contact's request (access they had ends).
    Deny { email: String },
    /// Open the vaults of someone who granted you access.
    Open { email: String },
}

fn find<'a>(list: &'a [EmergencyContactDto], email: &str, what: &str) -> Result<&'a EmergencyContactDto> {
    list.iter().find(|c| c.email.eq_ignore_ascii_case(email.trim())).ok_or_else(|| anyhow!("{email} {what}"))
}

fn status(c: &EmergencyContactDto) -> String {
    match (c.requested_at, c.grants_at) {
        (None, _) => "ready".into(),
        (Some(_), _) if c.opened => "access opened".into(),
        (Some(_), _) if c.granted => "access granted".into(),
        (Some(_), Some(at)) => format!("asked; access on {}", format_timestamp(at)),
        (Some(_), None) => "asked".into(),
    }
}

pub fn run(ctx: &Ctx, cmd: EmergencyCmd) -> Result<()> {
    let mut session = ctx.unlock()?;
    if session.server().is_none() {
        bail!("emergency access needs a sync server; connect this account with `2secret account connect`");
    }
    let overview: EmergencyOverview = ctx.block_on(twosecret_client::emergency_overview(&session))?;
    let not_contact = "is not one of your emergency contacts";
    let not_trusting = "does not trust you with emergency access";
    match cmd {
        EmergencyCmd::List => {
            if ctx.json {
                print_json(&overview);
                return Ok(());
            }
            let rows = |list: &[EmergencyContactDto]| -> Vec<Vec<String>> {
                list.iter()
                    .map(|c| vec![c.name.clone(), c.email.clone(), format!("{} days", c.wait_days), status(c)])
                    .collect()
            };
            println!("You trust:");
            table(&["name", "email", "waiting period", "status"], &rows(&overview.contacts));
            println!("\nYou are trusted by:");
            table(&["name", "email", "waiting period", "status"], &rows(&overview.trusted_by));
        }
        EmergencyCmd::Add { email, wait } => {
            let user = ctx.block_on(twosecret_client::add_emergency_contact(&mut session, &email, wait))?;
            ctx.save(&session)?;
            eprintln!(
                "{} <{}> can now ask for read access to the vaults you own; they get it {wait} days after \
                 asking unless you deny it.\nVerify their key fingerprint out of band: {}",
                user.name,
                user.email,
                AccountPublicKeys::from_b64(&user.public_key, user.pq_public_key.as_deref())?.fingerprint()
            );
        }
        EmergencyCmd::Remove { email } => {
            let c = find(&overview.contacts, &email, not_contact)
                .or_else(|_| find(&overview.trusted_by, &email, not_trusting))?;
            ctx.block_on(twosecret_client::remove_emergency_contact(&mut session, &c.id))?;
            ctx.save(&session)?;
            eprintln!("Removed.");
        }
        EmergencyCmd::Request { email } => {
            let c = find(&overview.trusted_by, &email, not_trusting)?;
            ctx.block_on(twosecret_client::request_emergency_access(&session, &c.id))?;
            eprintln!(
                "Asked. You get access in {} days unless {} denies it; then run `2secret emergency open {}`.",
                c.wait_days, c.name, c.email
            );
        }
        EmergencyCmd::Cancel { email } => {
            let c = find(&overview.trusted_by, &email, not_trusting)?;
            ctx.block_on(twosecret_client::reject_emergency_access(&mut session, &c.id))?;
            ctx.save(&session)?;
            eprintln!("Withdrawn.");
        }
        EmergencyCmd::Approve { email } => {
            let c = find(&overview.contacts, &email, not_contact)?;
            ctx.block_on(twosecret_client::approve_emergency_access(&session, &c.id))?;
            eprintln!("{} has access now.", c.name);
        }
        EmergencyCmd::Deny { email } => {
            let c = find(&overview.contacts, &email, not_contact)?;
            ctx.block_on(twosecret_client::reject_emergency_access(&mut session, &c.id))?;
            ctx.save(&session)?;
            eprintln!("Denied.");
        }
        EmergencyCmd::Open { email } => {
            let c = find(&overview.trusted_by, &email, not_trusting)?;
            if !c.granted {
                bail!("{} has not granted you access (yet): {}", c.name, status(c));
            }
            ctx.block_on(twosecret_client::open_emergency_access(&mut session, &c.id))?;
            ctx.save(&session)?;
            eprintln!("The vaults of {} are in `2secret vault list` now (read-only).", c.name);
        }
    }
    Ok(())
}
