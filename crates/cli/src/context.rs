//! Shared CLI state: data directory, unlocking and persistence.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use twosecret_core::crypto::{decrypt, encrypt, EncString, KdfParams, SecretKey, SymmetricKey};
use twosecret_core::profile::{DeviceSecrets, Profile, DEVICE_KEY, PROFILE_KEY};
use twosecret_core::session::Session;
use twosecret_core::storage::{default_data_dir, FileStorage, Storage};
use twosecret_core::util::now;

const CLI_SESSION_KEY: &str = "cli-session";
pub const SESSION_ENV: &str = "TWOSECRET_SESSION";

/// Cached unlock for `2secret unlock`: the account key encrypted with a
/// random key that only lives in the shell's environment.
#[derive(Serialize, Deserialize)]
struct CliSession {
    account_id: String,
    expires_at: i64,
    idle_secs: i64,
    account_key: EncString,
}

pub struct Ctx {
    pub home: PathBuf,
    pub storage: FileStorage,
    pub json: bool,
    pub offline: bool,
    rt: tokio::runtime::Runtime,
}

impl Ctx {
    pub fn new(home: Option<PathBuf>, json: bool, offline: bool) -> Result<Self> {
        let home = home.unwrap_or_else(default_data_dir);
        let storage =
            FileStorage::new(&home).with_context(|| format!("cannot use data directory {}", home.display()))?;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        Ok(Self { home, storage, json, offline, rt })
    }

    pub fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    pub fn has_profile(&self) -> bool {
        matches!(self.storage.read(PROFILE_KEY), Ok(Some(_)))
    }

    pub fn load_profile(&self) -> Result<Profile> {
        let json = self.storage.read(PROFILE_KEY)?.ok_or_else(|| {
            anyhow!("no 2Secret account on this device yet – run `2secret account create` or `2secret account signin`")
        })?;
        Ok(Profile::from_json(&json)?)
    }

    pub fn device(&self) -> Result<DeviceSecrets> {
        let json = self
            .storage
            .read(DEVICE_KEY)?
            .ok_or_else(|| anyhow!("the Secret Key for this account is missing on this device"))?;
        Ok(DeviceSecrets::from_json(&json)?)
    }

    pub fn secret_key(&self) -> Result<SecretKey> {
        Ok(self.device()?.secret_key()?)
    }

    pub fn save(&self, session: &Session) -> Result<()> {
        self.storage.write(PROFILE_KEY, &session.profile().to_json())?;
        Ok(())
    }

    pub fn save_new(&self, session: &Session, secret_key: &SecretKey) -> Result<()> {
        let acc = session.account();
        self.storage.write(DEVICE_KEY, &DeviceSecrets::new(&acc.id, &acc.email, secret_key).to_json())?;
        self.save(session)
    }

    pub fn kdf_for_new_accounts() -> KdfParams {
        if std::env::var("TWOSECRET_INSECURE_TEST_KDF").as_deref() == Ok("1") {
            KdfParams::insecure_for_tests()
        } else {
            KdfParams::default()
        }
    }

    /// Ask for the master password (or take it from `TWOSECRET_PASSWORD`).
    pub fn master_password(&self, prompt: &str) -> Result<String> {
        if let Ok(pw) = std::env::var("TWOSECRET_PASSWORD") {
            if !pw.is_empty() {
                return Ok(pw);
            }
        }
        prompt_secret(prompt)
    }

    /// Unlock with the cached shell session, or by asking for the password.
    pub fn unlock(&self) -> Result<Session> {
        let profile = self.load_profile()?;
        if let Some(session) = self.try_cached_session(&profile)? {
            return Ok(session);
        }
        let sk = self.secret_key()?;
        let password = self.master_password("Master password: ")?;
        let tty = std::io::stderr().is_terminal();
        if tty {
            eprint!("Unlocking… ");
        }
        let session = self.open_session(profile, &password, &sk);
        if tty {
            eprint!("\r            \r");
        }
        session
    }

    /// Unlock locally; for linked accounts fall back to the server, which
    /// knows about master password changes made on other devices.
    fn open_session(&self, profile: Profile, password: &str, sk: &SecretKey) -> Result<Session> {
        match Session::unlock(profile.clone(), password, sk) {
            Err(twosecret_core::Error::WrongPassword) if profile.server.is_some() && !self.offline => {
                let session = self.block_on(twosecret_client::unlock_online(profile, password, sk, &device_name()))?;
                self.save(&session)?;
                Ok(session)
            }
            other => Ok(other?),
        }
    }

    /// Unlock and also return the verified password (for sensitive commands).
    pub fn unlock_with_password(&self) -> Result<(Session, String, SecretKey)> {
        let profile = self.load_profile()?;
        let sk = self.secret_key()?;
        let password = self.master_password("Master password: ")?;
        let session = self.open_session(profile, &password, &sk)?;
        Ok((session, password, sk))
    }

    fn try_cached_session(&self, profile: &Profile) -> Result<Option<Session>> {
        let Ok(token) = std::env::var(SESSION_ENV) else {
            return Ok(None);
        };
        let Some(json) = self.storage.read(CLI_SESSION_KEY)? else {
            return Ok(None);
        };
        let Ok(mut cached) = serde_json::from_str::<CliSession>(&json) else {
            return Ok(None);
        };
        if cached.account_id != profile.account.id || cached.expires_at < now() {
            let _ = self.storage.delete(CLI_SESSION_KEY);
            return Ok(None);
        }
        let Ok(key) = SymmetricKey::from_b64(&token) else {
            return Ok(None);
        };
        let Ok(raw) = decrypt(&key, &cached.account_key, aad(&cached.account_id).as_bytes()) else {
            return Ok(None);
        };
        let account_key = SymmetricKey::from_slice(&raw)?;
        let session = match Session::open_with_account_key(profile.clone(), account_key) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        cached.expires_at = now() + cached.idle_secs;
        self.storage.write(CLI_SESSION_KEY, &serde_json::to_string(&cached)?)?;
        Ok(Some(session))
    }

    /// Create a shell session; returns the token to export.
    pub fn create_cli_session(&self, session: &Session, idle_minutes: i64) -> Result<String> {
        let key = SymmetricKey::generate();
        let account_id = session.account().id.clone();
        let cached = CliSession {
            account_key: encrypt(&key, session.account_key().as_bytes(), aad(&account_id).as_bytes()),
            account_id,
            idle_secs: idle_minutes.max(1) * 60,
            expires_at: now() + idle_minutes.max(1) * 60,
        };
        self.storage.write(CLI_SESSION_KEY, &serde_json::to_string(&cached)?)?;
        Ok(key.to_b64())
    }

    pub fn destroy_cli_session(&self) -> Result<()> {
        self.storage.delete(CLI_SESSION_KEY)?;
        Ok(())
    }

    pub fn has_cli_session(&self) -> bool {
        matches!(self.storage.read(CLI_SESSION_KEY), Ok(Some(_)))
    }

    /// Save, then push the change to the server when linked.
    pub fn after_write(&self, session: &mut Session) -> Result<()> {
        self.save(session)?;
        if session.server().is_some() && !self.offline {
            match self.block_on(twosecret_client::sync(session)) {
                Ok(_) => self.save(session)?,
                Err(e) => eprintln!("warning: saved locally but sync failed: {e}"),
            }
        }
        Ok(())
    }

    /// Refresh from the server when the last sync is older than five minutes.
    pub fn refresh(&self, session: &mut Session) -> Result<()> {
        let Some(link) = session.server() else {
            return Ok(());
        };
        if self.offline || link.last_sync_at.is_some_and(|t| now() - t < 300) || link.token.is_none() {
            return Ok(());
        }
        match self.block_on(twosecret_client::sync(session)) {
            Ok(_) => self.save(session)?,
            Err(e) => eprintln!("warning: could not sync, showing local data: {e}"),
        }
        Ok(())
    }
}

fn aad(account_id: &str) -> String {
    format!("2secret/v1/cli-session/{account_id}")
}

/// Read a secret without echo. Falls back to a plain line from stdin when no
/// terminal is attached (scripts).
pub fn prompt_secret(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() || cfg!(unix) && std::fs::metadata("/dev/tty").is_ok() {
        if let Ok(pw) = rpassword::prompt_password(prompt) {
            return Ok(pw);
        }
    }
    eprint!("{prompt}");
    let mut line = String::new();
    // Without input left a question asked again (a weak or mismatched
    // password) would loop forever.
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("no input");
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Read a line of visible input.
pub fn prompt(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Ask for a value unless one was given on the command line.
pub fn value_or_prompt(value: Option<String>, label: &str) -> Result<String> {
    match value {
        Some(v) if !v.trim().is_empty() => Ok(v),
        _ => {
            let v = prompt(&format!("{label}: "))?;
            if v.is_empty() {
                bail!("{label} is required");
            }
            Ok(v)
        }
    }
}

pub fn confirm(question: &str) -> Result<bool> {
    let answer = prompt(&format!("{question} [y/N] "))?;
    Ok(matches!(answer.to_lowercase().as_str(), "y" | "yes" | "j" | "ja"))
}

/// A readable name for this device.
pub fn device_name() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "computer".into());
    format!("2Secret CLI on {host}")
}
