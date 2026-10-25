//! The agent's identity: an Ed25519 key, made on first use and kept in the
//! data directory (`agent-key.json`, readable only by the user). Its
//! fingerprint is the agent id the app shows and remembers.

use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use twosecret_core::agent::{agent_id, hello_challenge};
use twosecret_core::util::{b64, unb64};
use zeroize::Zeroizing;

/// `agent-key-<client>.json`: one key per AI client, so the app tells them apart.
pub const FILE_PREFIX: &str = "agent-key-";

/// The file name part for a client name: letters, digits and dashes.
pub fn slug(client: &str) -> String {
    let mut out: String = client
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    out.truncate(40);
    if out.is_empty() {
        out.push_str("default");
    }
    out
}

#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    /// The 32-byte seed (base64).
    seed: String,
}

pub struct AgentKey {
    signing: SigningKey,
}

impl AgentKey {
    pub fn path(home: &Path, client: &str) -> PathBuf {
        home.join(format!("{FILE_PREFIX}{}.json", slug(client)))
    }

    /// The key of `client` in `home`, or a new one written there.
    pub fn load_or_create(home: &Path, client: &str) -> io::Result<Self> {
        let path = Self::path(home, client);
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Some(key) = Self::parse(&text) {
                return Ok(key);
            }
        }
        std::fs::create_dir_all(home)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700));
        }
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(twosecret_core::util::random_bytes());
        let key = Self { signing: SigningKey::from_bytes(&seed) };
        let json = serde_json::to_string(&Stored { version: 1, seed: b64(&*seed) })?;
        write_private(&path, json.as_bytes())?;
        Ok(key)
    }

    /// A key that is not stored (tests, one-off use).
    pub fn ephemeral() -> Self {
        Self { signing: SigningKey::from_bytes(&twosecret_core::util::random_bytes()) }
    }

    /// The key stored in `path`, if the file holds one.
    pub fn load(path: &Path) -> Option<Self> {
        Self::parse(&std::fs::read_to_string(path).ok()?)
    }

    /// Every client's key in `home`: the client slug and the key.
    pub fn list(home: &Path) -> Vec<(String, AgentKey)> {
        let Ok(entries) = std::fs::read_dir(home) else { return Vec::new() };
        let mut out: Vec<(String, AgentKey)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let slug = name.strip_prefix(FILE_PREFIX)?.strip_suffix(".json")?.to_string();
                Some((slug, Self::load(&e.path())?))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn parse(text: &str) -> Option<Self> {
        let stored: Stored = serde_json::from_str(text).ok()?;
        let seed: [u8; 32] = unb64(&stored.seed).ok()?.try_into().ok()?;
        Some(Self { signing: SigningKey::from_bytes(&seed) })
    }

    /// The public key, base64, for `hello`.
    pub fn public_key_b64(&self) -> String {
        b64(self.signing.verifying_key().as_bytes())
    }

    /// The fingerprint of the public key.
    pub fn id(&self) -> String {
        agent_id(self.signing.verifying_key().as_bytes())
    }

    /// The signature (base64) for `auth` over the nonce (base64) from `hello`.
    pub fn sign_hello(&self, nonce_b64: &str) -> twosecret_core::Result<String> {
        let nonce = unb64(nonce_b64)?;
        Ok(b64(&self.signing.sign(&hello_challenge(&nonce)).to_bytes()))
    }
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twosecret_core::agent::verify_hello;

    #[test]
    fn key_is_created_once_and_signs() {
        let dir = std::env::temp_dir().join(format!("2secret-agent-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = AgentKey::load_or_create(&dir, "Claude Code").unwrap();
        let again = AgentKey::load_or_create(&dir, "claude code").unwrap();
        assert_eq!(key.id(), again.id());
        assert_eq!(key.public_key_b64(), again.public_key_b64());
        let nonce = twosecret_core::util::random_bytes::<32>();
        let sig = key.sign_hello(&b64(&nonce)).unwrap();
        assert_eq!(verify_hello(&key.public_key_b64(), &nonce, &sig).unwrap(), key.id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(AgentKey::path(&dir, "Claude Code")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_ne!(AgentKey::ephemeral().id(), key.id());
        let other = AgentKey::load_or_create(&dir, "Cursor").unwrap();
        assert_ne!(other.id(), key.id(), "one key per client");
        assert_eq!(slug("  Claude Code!! "), "claude-code");
        assert_eq!(slug("***"), "default");
        let listed = AgentKey::list(&dir);
        assert_eq!(listed.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(), vec!["claude-code", "cursor"]);
        assert_eq!(listed[1].1.id(), other.id());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
