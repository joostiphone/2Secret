//! The persistent, fully encrypted representation of an account on a device.
//!
//! A [`Profile`] contains no plaintext secrets: vault names, item contents and
//! even the sync token are encrypted. It can safely be backed up or synced by
//! other means. The [`DeviceSecrets`] (holding the Secret Key) are stored
//! separately and must *not* travel together with the profile.

use serde::{Deserialize, Serialize};

use crate::crypto::{EncString, EncryptedKeyset, KdfParams, SecretKey, WrappedKey};
use crate::{Error, Result};

pub const PROFILE_FORMAT: &str = "2secret-profile";
pub const PROFILE_VERSION: u32 = 1;

/// Storage key of the profile.
pub const PROFILE_KEY: &str = "profile";
/// Storage key of the device secrets.
pub const DEVICE_KEY: &str = "device";

/// Associated data strings that bind ciphertexts to their context.
pub mod aad {
    pub fn vault_key(vault_id: &str) -> Vec<u8> {
        format!("2secret/v1/vault-key/{vault_id}").into_bytes()
    }
    pub fn vault_meta(vault_id: &str) -> Vec<u8> {
        format!("2secret/v1/vault-meta/{vault_id}").into_bytes()
    }
    pub fn item(vault_id: &str, item_id: &str) -> Vec<u8> {
        format!("2secret/v1/item/{vault_id}/{item_id}").into_bytes()
    }
    pub fn server_token(account_id: &str) -> Vec<u8> {
        format!("2secret/v1/server-token/{account_id}").into_bytes()
    }
    pub fn avatar(account_id: &str) -> Vec<u8> {
        format!("2secret/v1/avatar/{account_id}").into_bytes()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub format: String,
    pub version: u32,
    pub account: AccountRecord,
    #[serde(default)]
    pub server: Option<ServerLink>,
    #[serde(default)]
    pub vaults: Vec<VaultRecord>,
    #[serde(default)]
    pub items: Vec<ItemRecord>,
    /// The vault new items go to when none is chosen: the personal vault
    /// created with the account. Unset on devices that signed in later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_vault: Option<String>,
}

impl Profile {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("profile serialization cannot fail")
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let profile: Profile = serde_json::from_str(json)?;
        if profile.format != PROFILE_FORMAT {
            return Err(Error::Unsupported("not a 2Secret profile".into()));
        }
        if profile.version > PROFILE_VERSION {
            return Err(Error::Unsupported(format!(
                "profile version {} was written by a newer 2Secret",
                profile.version
            )));
        }
        Ok(profile)
    }

    pub fn vault(&self, id: &str) -> Option<&VaultRecord> {
        self.vaults.iter().find(|v| v.id == id)
    }

    pub fn vault_mut(&mut self, id: &str) -> Option<&mut VaultRecord> {
        self.vaults.iter_mut().find(|v| v.id == id)
    }

    pub fn item(&self, id: &str) -> Option<&ItemRecord> {
        self.items.iter().find(|i| i.id == id)
    }

    pub fn item_mut(&mut self, id: &str) -> Option<&mut ItemRecord> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    /// Does the profile have changes that still need to be uploaded?
    pub fn has_pending_changes(&self) -> bool {
        self.items.iter().any(|i| i.dirty) || self.vaults.iter().any(|v| v.sync_state != SyncState::Synced)
    }
}

/// Public account information plus the encrypted keyset.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountRecord {
    pub id: String,
    pub email: String,
    pub name: String,
    /// Account salt (base64), input to key derivation.
    pub salt: String,
    pub kdf: KdfParams,
    pub keyset: EncryptedKeyset,
    pub created_at: i64,
    /// Profile photo: a `data:image/…` URL encrypted with the account key
    /// (see [`crate::session::Session::avatar`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<EncString>,
    /// The photo was changed on this device and not yet sent to the server.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub avatar_dirty: bool,
    /// When this device last asked the server for the photo (not stored).
    #[serde(skip)]
    pub avatar_checked_at: i64,
}

/// Link to a 2Secret sync server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerLink {
    pub url: String,
    /// Session token, encrypted with the account key.
    #[serde(default)]
    pub token: Option<EncString>,
    #[serde(default)]
    pub last_sync_at: Option<i64>,
    /// The server has our ML-KEM public key (post-quantum sharing).
    #[serde(default)]
    pub pq_key_published: bool,
}

/// Access level of an account on a vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read only.
    Viewer,
    /// Can create, edit and delete items.
    Editor,
    /// Editor who can also share the vault and rename it.
    Manager,
    /// Created the vault; can delete it.
    Owner,
}

impl Role {
    pub fn can_write(&self) -> bool {
        *self >= Role::Editor
    }
    pub fn can_manage(&self) -> bool {
        *self >= Role::Manager
    }
    pub fn id(&self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Manager => "manager",
            Role::Owner => "owner",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        Some(match s.trim().to_lowercase().as_str() {
            "viewer" | "view" | "read" | "readonly" | "read-only" => Role::Viewer,
            "editor" | "edit" | "write" => Role::Editor,
            "manager" | "manage" | "admin" => Role::Manager,
            "owner" => Role::Owner,
            _ => return None,
        })
    }
}

/// Local synchronisation state of a vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    #[default]
    Synced,
    /// Created locally, not yet known to the server.
    PendingCreate,
    /// Metadata (name, description) changed locally.
    PendingUpdate,
    /// Deleted (owner) or left (member) locally.
    PendingDelete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultRecord {
    pub id: String,
    pub owner_id: String,
    pub role: Role,
    /// The vault key, wrapped for this account.
    pub wrapped_key: WrappedKey,
    /// [`VaultMeta`] encrypted with the vault key.
    pub meta: EncString,
    /// Highest server revision that has been merged locally.
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub sync_state: SyncState,
    /// Number of accounts with access (as last reported by the server).
    #[serde(default = "one")]
    pub member_count: u32,
    pub created_at: i64,
    /// Generation of the vault key (see `VaultDto::key_rev`).
    #[serde(default)]
    pub key_rev: u64,
    /// Fingerprints of keys this vault had before (see
    /// [`retired_key_id`]): a server that offers one of those again is
    /// refused, so a removed member's old key cannot come back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_keys: Vec<String>,
}

/// How many replaced keys a vault remembers.
pub const RETIRED_KEYS: usize = 16;

/// The fingerprint of a vault key in [`VaultRecord::retired_keys`].
pub fn retired_key_id(key: &crate::crypto::SymmetricKey) -> String {
    crate::util::b64(&crate::crypto::sha256(key.as_bytes())[..16])
}

fn one() -> u32 {
    1
}

/// Decrypted vault metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Optional accent colour (`#rrggbb`) or emoji used by the apps.
    #[serde(default)]
    pub icon: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemRecord {
    pub id: String,
    pub vault_id: String,
    /// Encrypted [`crate::Item`]; `None` marks a deletion not yet synced.
    pub data: Option<EncString>,
    /// Server revision this local version is based on (0 = never uploaded).
    #[serde(default)]
    pub revision: u64,
    /// Changed locally since the last successful upload.
    #[serde(default)]
    pub dirty: bool,
}

/// Device-local secrets. Kept apart from the profile on purpose.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceSecrets {
    pub account_id: String,
    pub email: String,
    pub secret_key: String,
}

impl DeviceSecrets {
    pub fn new(account_id: &str, email: &str, secret_key: &SecretKey) -> Self {
        Self { account_id: account_id.to_string(), email: email.to_string(), secret_key: secret_key.formatted() }
    }

    pub fn secret_key(&self) -> Result<SecretKey> {
        SecretKey::parse(&self.secret_key)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serialization cannot fail")
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

impl Drop for DeviceSecrets {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_key.zeroize();
    }
}

impl std::fmt::Debug for DeviceSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSecrets")
            .field("account_id", &self.account_id)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}
