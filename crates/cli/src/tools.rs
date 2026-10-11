//! Generator, Watchtower, import/export and secrets automation commands.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use clap::Args;
use serde_json::json;
use twosecret_core::generator::{GeneratorKind, GeneratorOptions};
use twosecret_core::import::{self, ImportFormat};
use twosecret_core::secret_ref;
use twosecret_core::strength::estimate;
use twosecret_core::watchtower::{self, IssueKind};

use crate::context::{confirm, prompt_secret, Ctx};
use crate::output::print_json;
use crate::ExportFormat;

#[derive(Args)]
pub struct GenerateArgs {
    /// Number of characters.
    #[arg(long, short, default_value_t = 20)]
    length: usize,
    /// Generate a memorable passphrase with this many words.
    #[arg(long, conflicts_with = "pin")]
    words: Option<usize>,
    /// Generate a numeric PIN with this many digits.
    #[arg(long)]
    pin: Option<usize>,
    #[arg(long)]
    no_uppercase: bool,
    #[arg(long)]
    no_lowercase: bool,
    #[arg(long)]
    no_digits: bool,
    #[arg(long)]
    no_symbols: bool,
    /// Avoid look-alike characters (l, 1, O, 0, …).
    #[arg(long)]
    avoid_ambiguous: bool,
    /// Word separator for passphrases.
    #[arg(long, default_value = "-")]
    separator: String,
    /// Capitalise passphrase words.
    #[arg(long)]
    capitalize: bool,
    /// Add a digit to a passphrase.
    #[arg(long)]
    number: bool,
    /// How many to generate.
    #[arg(long, short, default_value_t = 1)]
    count: usize,
}

pub fn generate(ctx: &Ctx, a: GenerateArgs) -> Result<()> {
    let opts = GeneratorOptions {
        kind: if a.pin.is_some() {
            GeneratorKind::Pin
        } else if a.words.is_some() {
            GeneratorKind::Memorable
        } else {
            GeneratorKind::Random
        },
        length: a.length,
        words: a.words.unwrap_or(5),
        pin_length: a.pin.unwrap_or(6),
        lowercase: !a.no_lowercase,
        uppercase: !a.no_uppercase,
        digits: !a.no_digits,
        symbols: !a.no_symbols,
        avoid_ambiguous: a.avoid_ambiguous,
        separator: a.separator,
        capitalize: a.capitalize,
        include_number: a.number,
    };
    let values: Vec<String> = (0..a.count.clamp(1, 1000)).map(|_| opts.generate()).collect();
    if ctx.json {
        print_json(&json!({"values": values, "entropy_bits": opts.entropy_bits().round()}));
    } else {
        for v in values {
            println!("{v}");
        }
        if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            eprintln!("({} bits of entropy)", opts.entropy_bits().round());
        }
    }
    Ok(())
}

pub fn strength(ctx: &Ctx, password: Option<String>) -> Result<()> {
    let pw = match password {
        Some(p) => p,
        None => {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                prompt_secret("Password: ")?
            } else {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim_end_matches(['\r', '\n']).to_string()
            }
        }
    };
    let s = estimate(&pw, &[]);
    if ctx.json {
        print_json(&s);
    } else {
        println!("{} ({}/4)", s.level.label(), s.level.score());
        println!("~{:.0} bits, offline cracking time: {}", s.bits, s.crack_time);
        if let Some(w) = &s.warning {
            println!("warning: {w}");
        }
        for sug in &s.suggestions {
            println!("tip: {sug}");
        }
    }
    Ok(())
}

pub fn watchtower(ctx: &Ctx, breach_check: bool) -> Result<()> {
    let mut session = ctx.unlock()?;
    ctx.refresh(&mut session)?;
    let breached = if breach_check {
        eprintln!("Checking passwords against Have I Been Pwned (only hash prefixes are sent)…");
        ctx.block_on(twosecret_client::breach_check(&session))?
    } else {
        HashMap::new()
    };
    let report = watchtower::analyze(session.all_items(), &breached, None);
    if ctx.json {
        print_json(&report);
        return Ok(());
    }
    println!("Watchtower score: {}/1000 ({})", report.score, report.rating().replace('_', " "));
    println!(
        "{} items checked, {} passwords{}",
        report.items_checked,
        report.passwords_checked,
        if breach_check { ", breach check done" } else { " (add --breach-check to check for breaches)" }
    );
    for kind in IssueKind::ALL {
        let issues = report.of_kind(kind);
        if issues.is_empty() {
            continue;
        }
        println!("\n{} ({})", kind.title(), issues.len());
        for i in issues {
            println!("  • {} – {}", i.title, i.detail);
        }
    }
    if report.issues.is_empty() {
        println!("\nNo problems found. 🎉");
    }
    Ok(())
}

pub fn import(ctx: &Ctx, file: &Path, format: Option<String>, vault: Option<String>) -> Result<()> {
    let data = std::fs::read(file)?;
    let filename = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let format = match format {
        Some(f) => ImportFormat::parse(&f).ok_or_else(|| anyhow!("unknown format '{f}'"))?,
        None => {
            import::detect(filename, &data).ok_or_else(|| anyhow!("could not detect the file format; pass --format"))?
        }
    };
    let mut session = ctx.unlock()?;
    let text = String::from_utf8_lossy(&data[..data.len().min(4096)]).to_string();
    let password = if format == ImportFormat::TwoSecret && twosecret_core::crypto::PasswordEnvelope::is_envelope(&text)
    {
        Some(prompt_secret("Export password: ")?)
    } else {
        None
    };
    let result = import::import(&data, format, password.as_deref())?;
    for w in &result.warnings {
        eprintln!("warning: {w}");
    }
    let found = result.item_count();
    let summary = session.import(result, vault.as_deref())?;
    ctx.after_write(&mut session)?;
    if ctx.json {
        print_json(&summary);
    } else {
        eprintln!(
            "Imported {} of {found} items ({} duplicates skipped, {} vaults created) from {}.",
            summary.imported,
            summary.skipped_duplicates,
            summary.vaults_created,
            format.name()
        );
        eprintln!("Remember to securely delete the unencrypted export file: {}", file.display());
    }
    Ok(())
}

pub fn export(ctx: &Ctx, file: &Path, format: ExportFormat, vaults: &[String], include_trash: bool) -> Result<()> {
    if file.exists() {
        bail!("{} already exists", file.display());
    }
    let session = ctx.unlock()?;
    let ids: Option<Vec<String>> = if vaults.is_empty() {
        None
    } else {
        Some(vaults.iter().map(|v| session.find_vault(v).map(|v| v.id)).collect::<Result<_, _>>()?)
    };
    let data = session.export(ids.as_deref(), include_trash);
    let content = match format {
        ExportFormat::Encrypted => {
            let pw = prompt_secret("Choose a password for the export: ")?;
            if pw.len() < 8 {
                bail!("use at least 8 characters");
            }
            if prompt_secret("Repeat the password: ")? != pw {
                bail!("the passwords do not match");
            }
            data.to_encrypted(&pw)?
        }
        ExportFormat::Json | ExportFormat::Csv => {
            eprintln!("WARNING: this export contains all your secrets in plain text.");
            if !confirm("Continue?")? {
                bail!("aborted");
            }
            if format == ExportFormat::Json {
                data.to_json()
            } else {
                data.to_csv()?
            }
        }
    };
    write_private(file, content.as_bytes())?;
    eprintln!("Exported {} items to {}.", data.item_count(), file.display());
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)?;
    Ok(())
}

pub fn sync(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("--offline was given");
    }
    let mut session = ctx.unlock()?;
    if session.server().is_none() {
        bail!("this is a local-only account; connect it with `2secret account connect`");
    }
    let report = ctx.block_on(twosecret_client::sync(&mut session))?;
    ctx.save(&session)?;
    if ctx.json {
        print_json(&report);
    } else {
        eprintln!(
            "Synced: {} uploaded, {} downloaded, {} deleted, {} conflicts resolved.",
            report.uploaded, report.downloaded, report.deleted, report.conflicts
        );
    }
    Ok(())
}

pub fn read(ctx: &Ctx, reference: &str, no_newline: bool) -> Result<()> {
    let mut session = ctx.unlock()?;
    ctx.refresh(&mut session)?;
    let value = secret_ref::resolve(&session, reference)?;
    let mut out = std::io::stdout().lock();
    out.write_all(value.as_bytes())?;
    if !no_newline {
        out.write_all(b"\n")?;
    }
    Ok(())
}

pub fn inject(ctx: &Ctx, input: Option<PathBuf>, output: Option<PathBuf>) -> Result<()> {
    let template = match &input {
        Some(p) => std::fs::read_to_string(p)?,
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s
        }
    };
    let mut session = ctx.unlock()?;
    ctx.refresh(&mut session)?;
    let result = secret_ref::inject(&session, &template)?;
    match output {
        Some(p) => {
            if p.exists() {
                std::fs::remove_file(&p)?;
            }
            write_private(&p, result.as_bytes())?;
        }
        None => std::io::stdout().write_all(result.as_bytes())?,
    }
    Ok(())
}

fn parse_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (k, v) = line.split_once('=').ok_or_else(|| anyhow!("{}:{}: expected KEY=value", path.display(), n + 1))?;
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(v);
        out.push((k.trim().to_string(), v.to_string()));
    }
    Ok(out)
}

pub fn run_command(ctx: &Ctx, env_files: &[PathBuf], command: &[String]) -> Result<()> {
    let mut vars: Vec<(String, String)> = Vec::new();
    for f in env_files {
        vars.extend(parse_env_file(f)?);
    }
    let needs_secrets = vars.iter().any(|(_, v)| secret_ref::is_reference(v))
        || std::env::vars().any(|(_, v)| secret_ref::is_reference(&v));
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    if needs_secrets {
        let mut session = ctx.unlock()?;
        ctx.refresh(&mut session)?;
        for (k, v) in std::env::vars() {
            if secret_ref::is_reference(&v) {
                cmd.env(k, &*secret_ref::resolve(&session, &v)?);
            }
        }
        for (k, v) in &vars {
            if secret_ref::is_reference(v) {
                cmd.env(k, &*secret_ref::resolve(&session, v)?);
            } else {
                cmd.env(k, v);
            }
        }
    } else {
        for (k, v) in &vars {
            cmd.env(k, v);
        }
    }
    cmd.env_remove("TWOSECRET_PASSWORD");
    let status = cmd.status().map_err(|e| anyhow!("could not run '{}': {e}", command[0]))?;
    std::process::exit(status.code().unwrap_or(1));
}
