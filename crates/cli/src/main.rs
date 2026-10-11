//! `2secret` – the 2Secret command line interface.

mod account;
mod clipboard;
mod context;
mod items;
mod output;
mod tools;
mod vaults;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// 2Secret – a free, open-source password manager.
///
/// Secrets are encrypted on your device with your master password and Secret
/// Key. Run `2secret account create` to get started.
#[derive(Parser)]
#[command(name = "2secret", version, about, long_about, propagate_version = true)]
struct Cli {
    /// Data directory (default: the platform's application data directory).
    #[arg(long, global = true, env = "TWOSECRET_HOME")]
    home: Option<PathBuf>,

    /// Print machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,

    /// Never contact the sync server.
    #[arg(long, global = true)]
    offline: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create, sign in to and manage your account.
    #[command(subcommand)]
    Account(account::AccountCmd),

    /// Unlock once for this shell: `eval "$(2secret unlock)"`.
    Unlock {
        /// Shell syntax for the printed export statement.
        #[arg(long, value_enum, default_value_t = Shell::Sh)]
        shell: Shell,
        /// Lock again after this many minutes of inactivity.
        #[arg(long, default_value_t = 30)]
        minutes: i64,
    },

    /// Forget the shell session created by `unlock`.
    Lock,

    /// Show account, sync and session status.
    Status,

    /// List items.
    #[command(alias = "ls")]
    List(items::ListArgs),

    /// Show an item.
    #[command(alias = "show")]
    Get(items::GetArgs),

    /// Create an item, e.g. `2secret add login --title GitHub --username me --generate --url github.com`.
    Add(items::AddArgs),

    /// Change an item.
    Edit(items::EditArgs),

    /// Move an item to the trash (or delete it permanently).
    #[command(alias = "rm")]
    Delete {
        item: String,
        /// Delete permanently instead of moving to the trash.
        #[arg(long)]
        permanent: bool,
    },

    /// Restore an item from the trash.
    Restore { item: String },

    /// Permanently delete everything in the trash.
    EmptyTrash,

    /// Move an item to another vault.
    Move {
        item: String,
        #[arg(long)]
        to: String,
    },

    /// Mark an item as favorite.
    Favorite {
        item: String,
        #[arg(long)]
        off: bool,
    },

    /// Show the password history of an item.
    History { item: String },

    /// Print the current one-time password of an item.
    Totp { item: String },

    /// Copy a field to the clipboard (cleared automatically).
    Copy {
        item: String,
        /// Field to copy (password, username, otp, or any field label).
        #[arg(long, short, default_value = "password")]
        field: String,
        /// Seconds until the clipboard is cleared.
        #[arg(long, default_value_t = 45)]
        clear_after: u64,
    },

    /// Attach a file (max. 5 MB) to an item.
    Attach { item: String, file: PathBuf },

    /// Save an attachment of an item to a file.
    Attachment {
        item: String,
        name: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Manage vaults and sharing.
    #[command(subcommand)]
    Vault(vaults::VaultCmd),

    /// Print a secret by reference: `2secret read 2s://Personal/GitHub/password`.
    Read {
        reference: String,
        /// Do not print a trailing newline.
        #[arg(short = 'n', long)]
        no_newline: bool,
    },

    /// Replace `{{ 2s://… }}` references in a template (stdin → stdout).
    Inject {
        #[arg(short, long)]
        input: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Run a command with secrets from `2s://` references in its environment.
    Run {
        /// Load variables (KEY=value or KEY=2s://…) from these files.
        #[arg(long)]
        env_file: Vec<PathBuf>,
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Generate a password, passphrase or PIN.
    #[command(alias = "gen")]
    Generate(tools::GenerateArgs),

    /// Estimate the strength of a password (read from stdin when omitted).
    Strength { password: Option<String> },

    /// Security audit: weak, reused, old and breached passwords.
    Watchtower {
        /// Also check passwords against Have I Been Pwned (k-anonymity).
        #[arg(long)]
        breach_check: bool,
    },

    /// Import from 1Password, Bitwarden, LastPass, Chrome, Firefox, KeePass, …
    Import {
        file: PathBuf,
        /// 2secret, 1pux, bitwarden, keepass or csv (detected automatically).
        #[arg(long)]
        format: Option<String>,
        /// Put everything into this vault.
        #[arg(long)]
        vault: Option<String>,
    },

    /// Export vaults.
    Export {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = ExportFormat::Encrypted)]
        format: ExportFormat,
        /// Only these vaults (default: all).
        #[arg(long)]
        vault: Vec<String>,
        #[arg(long)]
        include_trash: bool,
    },

    /// Synchronise with the sync server now.
    Sync,

    #[command(hide = true)]
    ClipboardDaemon { seconds: u64 },
}

#[derive(Clone, Copy, ValueEnum)]
enum Shell {
    Sh,
    Fish,
    Powershell,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Password-protected 2Secret JSON (recommended).
    Encrypted,
    /// Unencrypted 2Secret JSON.
    Json,
    /// Unencrypted CSV.
    Csv,
}

#[derive(Args, Clone, Default)]
pub struct ItemOpts {
    /// Title of the item.
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    /// Password (use `-` to be prompted without echo).
    #[arg(long)]
    pub password: Option<String>,
    /// Generate a new random password.
    #[arg(long)]
    pub generate: bool,
    /// Length of the generated password.
    #[arg(long, default_value_t = 24)]
    pub length: usize,
    /// Website address (repeatable).
    #[arg(long = "url")]
    pub urls: Vec<String>,
    #[arg(long)]
    pub notes: Option<String>,
    /// Tag (repeatable).
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    /// One-time password secret or otpauth:// URI.
    #[arg(long)]
    pub totp: Option<String>,
    /// Set a field: `label=value` (repeatable). Template fields such as
    /// `number`, `cvv` or `iban` are matched by name.
    #[arg(long = "field")]
    pub fields: Vec<String>,
    /// Set a concealed field: `label=value` (repeatable).
    #[arg(long = "secret-field")]
    pub secret_fields: Vec<String>,
    /// Mark as favorite.
    #[arg(long)]
    pub favorite: bool,
}

fn main() {
    let cli = Cli::parse();
    if let Command::ClipboardDaemon { seconds } = cli.command {
        let _ = clipboard::daemon(seconds);
        return;
    }
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let ctx = context::Ctx::new(cli.home, cli.json, cli.offline)?;
    match cli.command {
        Command::Account(cmd) => account::run(&ctx, cmd),
        Command::Unlock { shell, minutes } => {
            let session = ctx.unlock()?;
            let token = ctx.create_cli_session(&session, minutes)?;
            match shell {
                Shell::Sh => println!("export {}=\"{token}\"", context::SESSION_ENV),
                Shell::Fish => println!("set -gx {} \"{token}\"", context::SESSION_ENV),
                Shell::Powershell => println!("$env:{} = \"{token}\"", context::SESSION_ENV),
            }
            if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                eprintln!("# Run `eval \"$(2secret unlock)\"` to keep this shell unlocked for {minutes} minutes of inactivity.");
            }
            Ok(())
        }
        Command::Lock => {
            ctx.destroy_cli_session()?;
            eprintln!("Locked.");
            Ok(())
        }
        Command::Status => account::status(&ctx),
        Command::List(args) => items::list(&ctx, args),
        Command::Get(args) => items::get(&ctx, args),
        Command::Add(args) => items::add(&ctx, args),
        Command::Edit(args) => items::edit(&ctx, args),
        Command::Delete { item, permanent } => items::delete(&ctx, &item, permanent),
        Command::Restore { item } => items::restore(&ctx, &item),
        Command::EmptyTrash => items::empty_trash(&ctx),
        Command::Move { item, to } => items::move_item(&ctx, &item, &to),
        Command::Favorite { item, off } => items::favorite(&ctx, &item, !off),
        Command::History { item } => items::history(&ctx, &item),
        Command::Totp { item } => items::totp(&ctx, &item),
        Command::Copy {
            item,
            field,
            clear_after,
        } => items::copy(&ctx, &item, &field, clear_after),
        Command::Attach { item, file } => items::attach(&ctx, &item, &file),
        Command::Attachment { item, name, output } => items::save_attachment(&ctx, &item, &name, output),
        Command::Vault(cmd) => vaults::run(&ctx, cmd),
        Command::Read { reference, no_newline } => tools::read(&ctx, &reference, no_newline),
        Command::Inject { input, output } => tools::inject(&ctx, input, output),
        Command::Run { env_file, command } => tools::run_command(&ctx, &env_file, &command),
        Command::Generate(args) => tools::generate(&ctx, args),
        Command::Strength { password } => tools::strength(&ctx, password),
        Command::Watchtower { breach_check } => tools::watchtower(&ctx, breach_check),
        Command::Import { file, format, vault } => tools::import(&ctx, &file, format, vault),
        Command::Export {
            file,
            format,
            vault,
            include_trash,
        } => tools::export(&ctx, &file, format, &vault, include_trash),
        Command::Sync => tools::sync(&ctx),
        Command::ClipboardDaemon { .. } => Ok(()),
    }
}
