//! An unlocked account: decrypted keys, vaults and items in memory.
//!
//! Every mutating method immediately re-encrypts the affected data into the
//! underlying [`Profile`], so `session.profile()` is always ready to be
//! persisted.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::api::{MemberDto, MemberKey, RotateVaultKeyRequest, RotatedItem};
use crate::crypto::{
    decrypt, decrypt_json, derive_keys, encrypt, encrypt_json, AccountPublicKeys, DerivedKeys, EncString,
    EncryptedKeyset, KdfParams, Keyset, PublicKey, SecretKey, SymmetricKey, WrappedKey,
};
use crate::item::{Category, Item, ItemSummary};
use crate::passkey::Passkey;
use crate::profile::{
    aad, AccountRecord, ItemRecord, Profile, Role, ServerLink, SyncState, VaultMeta, VaultRecord, PROFILE_FORMAT,
    PROFILE_VERSION,
};
use crate::util::{b64, new_id, normalize_email, now, random_bytes, unb64, url_matches};
use crate::{Error, Result};

/// Minimum length of a master password.
/// Minimum length of a master password (LastPass allowed 8 characters for
/// years; 12 is today's common minimum).
pub const MIN_PASSWORD_LEN: usize = 12;

/// Largest profile photo (its `data:` URL); the apps make 128-pixel JPEGs of
/// a few KB.
pub const MAX_AVATAR_BYTES: usize = 48 * 1024;

/// Minimum strength of a master password: "good" (3 of 4) on the zxcvbn scale.
pub const MIN_PASSWORD_LEVEL: crate::strength::StrengthLevel = crate::strength::StrengthLevel::Good;

/// Why a master password is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordProblem {
    TooShort,
    TooWeak,
}

/// Check a new master password against the policy. `context` holds words a
/// guesser would try first (name, e-mail address).
pub fn check_master_password(password: &str, context: &[&str]) -> std::result::Result<(), PasswordProblem> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(PasswordProblem::TooShort);
    }
    if crate::strength::estimate(password, context).level < MIN_PASSWORD_LEVEL {
        return Err(PasswordProblem::TooWeak);
    }
    Ok(())
}

fn require_master_password(password: &str, context: &[&str]) -> Result<()> {
    check_master_password(password, context).map_err(|p| match p {
        PasswordProblem::TooShort => {
            Error::invalid(format!("the master password must be at least {MIN_PASSWORD_LEN} characters"))
        }
        PasswordProblem::TooWeak => Error::invalid("the master password is too easy to guess"),
    })
}

/// A decrypted vault.
struct OpenVault {
    key: SymmetricKey,
    meta: VaultMeta,
}

/// A vault key that was shared with us, wrapped again with our own account
/// key (see [`Session::vault_keys_to_rewrap`]).
#[derive(Clone, Debug, PartialEq)]
pub struct KeyRewrap {
    pub vault_id: String,
    pub wrapped_key: WrappedKey,
    /// Generation of the vault key, so the server can refuse a stale rewrap.
    pub key_rev: u64,
}

/// Public information about a vault for display.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub role: Role,
    pub owner_id: String,
    pub is_owner: bool,
    pub member_count: u32,
    pub item_count: usize,
    pub sync_state: SyncState,
    pub created_at: i64,
}

impl VaultInfo {
    pub fn is_shared(&self) -> bool {
        self.member_count > 1 || !self.is_owner
    }
}

/// Criteria for listing items.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemFilter {
    pub vault_id: Option<String>,
    pub category: Option<Category>,
    pub favorites_only: bool,
    /// List the trash instead of active items.
    pub trashed: bool,
    pub tag: Option<String>,
    pub query: String,
}

/// Everything the sync server needs to change the master password.
#[derive(Clone, Debug)]
pub struct PasswordChange {
    pub current_auth_key: SymmetricKey,
    pub new_auth_key: SymmetricKey,
    pub salt: String,
    pub kdf: KdfParams,
    pub keyset: EncryptedKeyset,
}

/// Unlocked account state.
pub struct Session {
    profile: Profile,
    keyset: Keyset,
    vaults: BTreeMap<String, OpenVault>,
    items: HashMap<String, (String, Item)>,
    /// Records that could not be decrypted (reported, never silently dropped).
    undecryptable: Vec<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("account", &self.profile.account.email)
            .field("vaults", &self.vaults.len())
            .field("items", &self.items.len())
            .finish()
    }
}

impl Session {
    // ------------------------------------------------------------------
    // Account creation and unlocking
    // ------------------------------------------------------------------

    /// Create a brand-new account with one personal vault. Returns the
    /// session and the freshly generated Secret Key, which the user must save.
    pub fn create_account(
        name: &str,
        email: &str,
        password: &str,
        kdf: KdfParams,
        default_vault_name: &str,
    ) -> Result<(Session, SecretKey)> {
        Self::create_account_with_keys(name, email, password, kdf, default_vault_name).map(|(s, sk, _)| (s, sk))
    }

    /// Like [`Session::create_account`], also returning the derived keys
    /// (so a server registration does not need to run Argon2id again).
    pub fn create_account_with_keys(
        name: &str,
        email: &str,
        password: &str,
        kdf: KdfParams,
        default_vault_name: &str,
    ) -> Result<(Session, SecretKey, DerivedKeys)> {
        let email = normalize_email(email);
        if email.is_empty() {
            return Err(Error::invalid("an e-mail address is required"));
        }
        require_master_password(password, &[name, &email])?;
        kdf.validate()?;
        let secret_key = SecretKey::generate();
        let salt: [u8; 16] = random_bytes();
        let keys = derive_keys(password, &secret_key, &email, &salt, &kdf)?;
        let keyset = Keyset::generate();
        let account = AccountRecord {
            id: new_id(),
            email,
            name: name.trim().to_string(),
            salt: b64(&salt),
            kdf,
            keyset: keyset.encrypt(&keys.master_key),
            created_at: now(),
            avatar: None,
            avatar_dirty: false,
            avatar_checked_at: 0,
        };
        let profile = Profile {
            format: PROFILE_FORMAT.into(),
            version: PROFILE_VERSION,
            account,
            server: None,
            vaults: Vec::new(),
            items: Vec::new(),
            default_vault: None,
        };
        let mut session = Session::from_parts(profile, keyset)?;
        let name = if default_vault_name.trim().is_empty() { "Personal" } else { default_vault_name };
        let personal = session.create_vault(name, "")?;
        session.profile.default_vault = Some(personal);
        Ok((session, secret_key, keys))
    }

    /// Build a profile for an account that already exists on a server (used
    /// when signing in on a new device). Vaults and items arrive via sync.
    pub fn from_server_account(account: AccountRecord, keys: &DerivedKeys, server: ServerLink) -> Result<Session> {
        let profile = Profile {
            format: PROFILE_FORMAT.into(),
            version: PROFILE_VERSION,
            account,
            server: Some(server),
            vaults: Vec::new(),
            items: Vec::new(),
            default_vault: None,
        };
        Session::open(profile, keys)
    }

    /// Derive the unlock keys for a profile. This is the slow (Argon2id) step;
    /// apps run it on a background thread.
    pub fn derive(profile: &Profile, password: &str, secret_key: &SecretKey) -> Result<DerivedKeys> {
        let salt = unb64(&profile.account.salt)?;
        derive_keys(password, secret_key, &profile.account.email, &salt, &profile.account.kdf)
    }

    /// Unlock a profile with previously derived keys.
    pub fn open(profile: Profile, keys: &DerivedKeys) -> Result<Session> {
        let keyset = Keyset::decrypt(&profile.account.keyset, &keys.master_key)?;
        Session::from_parts(profile, keyset)
    }

    /// Derive keys and unlock in one step.
    pub fn unlock(profile: Profile, password: &str, secret_key: &SecretKey) -> Result<Session> {
        let keys = Session::derive(&profile, password, secret_key)?;
        Session::open(profile, &keys)
    }

    /// Unlock with a cached account key (CLI sessions).
    pub fn open_with_account_key(profile: Profile, account_key: SymmetricKey) -> Result<Session> {
        let keyset = Keyset::from_account_key(&profile.account.keyset, account_key)?;
        Session::from_parts(profile, keyset)
    }

    /// An independent copy of this unlocked session (re-decrypts the profile).
    pub fn try_clone(&self) -> Result<Session> {
        Session::from_parts(self.profile.clone(), self.keyset.clone())
    }

    fn from_parts(profile: Profile, keyset: Keyset) -> Result<Session> {
        let mut session =
            Session { profile, keyset, vaults: BTreeMap::new(), items: HashMap::new(), undecryptable: Vec::new() };
        session.reload()?;
        Ok(session)
    }

    /// Re-decrypt all vaults and items from the profile.
    pub(crate) fn reload(&mut self) -> Result<()> {
        self.vaults.clear();
        self.items.clear();
        self.undecryptable.clear();
        let mut vault_ids = Vec::new();
        for v in &self.profile.vaults {
            match self.open_vault_record(v) {
                Ok(open) => {
                    vault_ids.push(v.id.clone());
                    self.vaults.insert(v.id.clone(), open);
                }
                Err(_) => self.undecryptable.push(format!("vault:{}", v.id)),
            }
        }
        let records: Vec<ItemRecord> = self.profile.items.clone();
        for rec in &records {
            if let Some(data) = &rec.data {
                match self.decrypt_item(&rec.vault_id, &rec.id, data) {
                    Ok(item) => {
                        self.items.insert(rec.id.clone(), (rec.vault_id.clone(), item));
                    }
                    Err(_) => self.undecryptable.push(format!("item:{}", rec.id)),
                }
            }
        }
        Ok(())
    }

    fn open_vault_record(&self, v: &VaultRecord) -> Result<OpenVault> {
        let key = v.wrapped_key.unwrap(&self.keyset, &aad::vault_key(&v.id))?;
        let meta: VaultMeta = decrypt_json(&key, &v.meta, &aad::vault_meta(&v.id))?;
        Ok(OpenVault { key, meta })
    }

    pub(crate) fn decrypt_item(&self, vault_id: &str, item_id: &str, data: &EncString) -> Result<Item> {
        let vault = self.vaults.get(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        let item: Item = decrypt_json(&vault.key, data, &aad::item(vault_id, item_id))?;
        if item.id != item_id {
            return Err(Error::Decryption);
        }
        Ok(item)
    }

    pub(crate) fn encrypt_item(&self, vault_id: &str, item: &Item) -> Result<EncString> {
        let vault = self.vaults.get(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        encrypt_json(&vault.key, item, &aad::item(vault_id, &item.id))
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    pub(crate) fn profile_mut(&mut self) -> &mut Profile {
        &mut self.profile
    }

    pub fn account(&self) -> &AccountRecord {
        &self.profile.account
    }

    pub fn keyset(&self) -> &Keyset {
        &self.keyset
    }

    pub fn account_key(&self) -> &SymmetricKey {
        &self.keyset.account_key
    }

    pub fn public_key(&self) -> PublicKey {
        self.keyset.public_key()
    }

    /// Both public keys (X25519 and ML-KEM-768) of this account.
    pub fn public_keys(&self) -> AccountPublicKeys {
        self.keyset.public_keys()
    }

    /// Our ML-KEM public key, if the sync server does not have it yet.
    pub fn pq_key_to_publish(&self) -> Option<String> {
        let link = self.profile.server.as_ref()?;
        (!link.pq_key_published).then(|| self.keyset.pq_private_key().public_key().to_b64())
    }

    pub fn mark_pq_key_published(&mut self) {
        if let Some(link) = &mut self.profile.server {
            link.pq_key_published = true;
        }
    }

    /// Vault keys that others shared with us by public-key encryption, wrapped
    /// again with our own account key. Once the server stores these instead,
    /// nothing that a future quantum computer could open stays on the server.
    pub fn vault_keys_to_rewrap(&self) -> Vec<KeyRewrap> {
        self.profile
            .vaults
            .iter()
            .filter(|v| v.wrapped_key.is_sealed() && v.sync_state == SyncState::Synced)
            .filter_map(|v| {
                let key = self.vaults.get(&v.id)?.key.clone();
                Some(KeyRewrap {
                    vault_id: v.id.clone(),
                    wrapped_key: WrappedKey::wrap_symmetric(&self.keyset.account_key, &key, &aad::vault_key(&v.id)),
                    key_rev: v.key_rev,
                })
            })
            .collect()
    }

    /// Build the request that replaces a vault's key (see
    /// [`RotateVaultKeyRequest`]): a new random key, the metadata and every
    /// item re-encrypted with it, and the key wrapped for each of `members`
    /// (the vault's current members as listed by the server; for us with our
    /// own account key, for everybody else with their public keys).
    ///
    /// The vault must be fully synced, so that no local edit is left behind
    /// encrypted with the old key.
    pub fn rotate_vault_key_request(&self, vault_id: &str, members: &[MemberDto]) -> Result<RotateVaultKeyRequest> {
        let record = self.profile.vault(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        if !record.role.can_manage() {
            return Err(Error::PermissionDenied("only the owner and managers can replace a vault's key".into()));
        }
        let pending = self.profile.items.iter().any(|i| i.vault_id == vault_id && i.dirty);
        if record.sync_state != SyncState::Synced || pending {
            return Err(Error::invalid("sync the vault before replacing its key"));
        }
        let open = self.vaults.get(vault_id).ok_or(Error::Decryption)?;
        let key = SymmetricKey::generate();
        let key_aad = aad::vault_key(vault_id);

        let mut items = Vec::new();
        for rec in self.profile.items.iter().filter(|i| i.vault_id == vault_id) {
            if let Some(data) = &rec.data {
                let item = self.decrypt_item(vault_id, &rec.id, data)?;
                items.push(RotatedItem {
                    id: rec.id.clone(),
                    data: encrypt_json(&key, &item, &aad::item(vault_id, &rec.id))?,
                });
            }
        }

        let me = &self.profile.account.id;
        if !members.iter().any(|m| &m.account_id == me) {
            return Err(Error::invalid("the member list does not include this account"));
        }
        let mut wrapped = Vec::new();
        for m in members {
            let wrapped_key = if &m.account_id == me {
                WrappedKey::wrap_symmetric(&self.keyset.account_key, &key, &key_aad)
            } else {
                let keys = AccountPublicKeys::from_b64(&m.public_key, m.pq_public_key.as_deref())?;
                WrappedKey::wrap_for(&keys, &key, &key_aad)?
            };
            wrapped.push(MemberKey { account_id: m.account_id.clone(), wrapped_key });
        }

        Ok(RotateVaultKeyRequest {
            key_rev: record.key_rev,
            meta: encrypt_json(&key, &open.meta, &aad::vault_meta(vault_id))?,
            members: wrapped,
            items,
        })
    }

    /// Re-encrypt what this device stores for a vault with `new_key`, after
    /// someone else replaced the vault's key. Records that cannot be read with
    /// the old key are left untouched.
    pub(crate) fn reencrypt_vault(&mut self, vault_id: &str, new_key: &SymmetricKey) {
        let Some(old) = self.vaults.get(vault_id).map(|v| v.key.clone()) else { return };
        if let Some(v) = self.profile.vaults.iter_mut().find(|v| v.id == vault_id) {
            let meta_aad = aad::vault_meta(vault_id);
            if let Ok(meta) = decrypt_json::<VaultMeta>(&old, &v.meta, &meta_aad) {
                if let Ok(enc) = encrypt_json(new_key, &meta, &meta_aad) {
                    v.meta = enc;
                }
            }
        }
        for rec in self.profile.items.iter_mut().filter(|i| i.vault_id == vault_id) {
            let item_aad = aad::item(vault_id, &rec.id);
            let Some(data) = &rec.data else { continue };
            if let Ok(item) = decrypt_json::<Item>(&old, data, &item_aad) {
                if let Ok(enc) = encrypt_json(new_key, &item, &item_aad) {
                    rec.data = Some(enc);
                }
            }
        }
    }

    /// Store a vault key wrapping that the server has accepted.
    pub fn set_vault_wrapped_key(&mut self, vault_id: &str, wrapped: WrappedKey) {
        if let Some(v) = self.profile.vaults.iter_mut().find(|v| v.id == vault_id) {
            v.wrapped_key = wrapped;
        }
    }

    /// Records that failed to decrypt (should normally be empty).
    pub fn undecryptable(&self) -> &[String] {
        &self.undecryptable
    }

    /// Verify a master password without changing anything (re-authentication
    /// for sensitive actions).
    pub fn verify_password(&self, password: &str, secret_key: &SecretKey) -> Result<DerivedKeys> {
        let keys = Session::derive(&self.profile, password, secret_key)?;
        Keyset::decrypt(&self.profile.account.keyset, &keys.master_key)?;
        Ok(keys)
    }

    // ------------------------------------------------------------------
    // Vaults
    // ------------------------------------------------------------------

    fn vault_info(&self, rec: &VaultRecord) -> Option<VaultInfo> {
        let open = self.vaults.get(&rec.id)?;
        Some(VaultInfo {
            id: rec.id.clone(),
            name: open.meta.name.clone(),
            description: open.meta.description.clone(),
            icon: open.meta.icon.clone(),
            role: rec.role,
            owner_id: rec.owner_id.clone(),
            is_owner: rec.owner_id == self.profile.account.id,
            member_count: rec.member_count,
            item_count: self.items.values().filter(|(v, i)| v == &rec.id && !i.is_trashed()).count(),
            sync_state: rec.sync_state,
            created_at: rec.created_at,
        })
    }

    /// All accessible vaults: own vaults first (oldest first), then shared
    /// vaults alphabetically.
    pub fn vaults(&self) -> Vec<VaultInfo> {
        let mut list: Vec<VaultInfo> = self
            .profile
            .vaults
            .iter()
            .filter(|v| v.sync_state != SyncState::PendingDelete)
            .filter_map(|v| self.vault_info(v))
            .collect();
        list.sort_by(|a, b| {
            b.is_owner
                .cmp(&a.is_owner)
                .then(a.created_at.cmp(&b.created_at))
                .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        list
    }

    pub fn vault(&self, id: &str) -> Option<VaultInfo> {
        self.profile.vault(id).filter(|v| v.sync_state != SyncState::PendingDelete).and_then(|v| self.vault_info(v))
    }

    /// Find a vault by id or (case-insensitive) name.
    pub fn find_vault(&self, name_or_id: &str) -> Result<VaultInfo> {
        let vaults = self.vaults();
        if let Some(v) = vaults.iter().find(|v| v.id == name_or_id) {
            return Ok(v.clone());
        }
        let lower = name_or_id.trim().to_lowercase();
        let matches: Vec<&VaultInfo> = vaults.iter().filter(|v| v.name.to_lowercase() == lower).collect();
        match matches.len() {
            0 => Err(Error::not_found(format!("vault '{name_or_id}'"))),
            1 => Ok(matches[0].clone()),
            _ => Err(Error::invalid(format!("more than one vault is called '{name_or_id}', use its id"))),
        }
    }

    /// The vault new items go to by default: the personal vault created with
    /// the account, or else the oldest vault we own that is not shared.
    /// A shared vault is only chosen when nothing else can be written to.
    pub fn default_vault_id(&self) -> Option<String> {
        let vaults = self.vaults();
        if let Some(id) = &self.profile.default_vault {
            if vaults.iter().any(|v| &v.id == id && v.role.can_write()) {
                return Some(id.clone());
            }
        }
        vaults
            .iter()
            .find(|v| v.is_owner && !v.is_shared())
            .or_else(|| vaults.iter().find(|v| v.role.can_write()))
            .map(|v| v.id.clone())
    }

    pub fn vault_key(&self, vault_id: &str) -> Option<&SymmetricKey> {
        self.vaults.get(vault_id).map(|v| &v.key)
    }

    pub fn create_vault(&mut self, name: &str, description: &str) -> Result<String> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::invalid("a vault needs a name"));
        }
        let id = new_id();
        let key = SymmetricKey::generate();
        let meta =
            VaultMeta { name: name.to_string(), description: description.trim().to_string(), icon: String::new() };
        let record = VaultRecord {
            id: id.clone(),
            owner_id: self.profile.account.id.clone(),
            role: Role::Owner,
            wrapped_key: WrappedKey::wrap_symmetric(&self.keyset.account_key, &key, &aad::vault_key(&id)),
            meta: encrypt_json(&key, &meta, &aad::vault_meta(&id))?,
            revision: 0,
            sync_state: SyncState::PendingCreate,
            member_count: 1,
            created_at: now(),
            key_rev: 0,
        };
        self.profile.vaults.push(record);
        self.vaults.insert(id.clone(), OpenVault { key, meta });
        Ok(id)
    }

    pub fn update_vault(&mut self, id: &str, name: &str, description: &str, icon: Option<&str>) -> Result<()> {
        let rec = self.profile.vault(id).ok_or_else(|| Error::not_found(format!("vault {id}")))?;
        if !rec.role.can_manage() {
            return Err(Error::PermissionDenied("you cannot rename this vault".into()));
        }
        let open = self.vaults.get_mut(id).ok_or_else(|| Error::not_found(id))?;
        if !name.trim().is_empty() {
            open.meta.name = name.trim().to_string();
        }
        open.meta.description = description.trim().to_string();
        if let Some(icon) = icon {
            open.meta.icon = icon.to_string();
        }
        let meta = encrypt_json(&open.key, &open.meta, &aad::vault_meta(id))?;
        let rec = self.profile.vault_mut(id).expect("checked above");
        rec.meta = meta;
        if rec.sync_state == SyncState::Synced {
            rec.sync_state = SyncState::PendingUpdate;
        }
        Ok(())
    }

    /// Delete a vault we own, or leave a vault shared with us. All of its
    /// items disappear from this device.
    pub fn delete_vault(&mut self, id: &str) -> Result<()> {
        let rec = self.profile.vault(id).ok_or_else(|| Error::not_found(format!("vault {id}")))?;
        let never_synced = rec.sync_state == SyncState::PendingCreate || self.profile.server.is_none();
        if never_synced {
            self.profile.vaults.retain(|v| v.id != id);
            self.vaults.remove(id);
        } else {
            self.profile.vault_mut(id).expect("exists").sync_state = SyncState::PendingDelete;
        }
        self.profile.items.retain(|i| i.vault_id != id);
        self.items.retain(|_, (v, _)| v != id);
        Ok(())
    }

    /// Wrap a vault key for another account (vault sharing): hybrid
    /// post-quantum when the recipient has an ML-KEM key.
    pub fn wrap_vault_key_for(&self, vault_id: &str, recipient: &AccountPublicKeys) -> Result<WrappedKey> {
        let key = self.vault_key(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        WrappedKey::wrap_for(recipient, key, &aad::vault_key(vault_id))
    }

    // ------------------------------------------------------------------
    // Items
    // ------------------------------------------------------------------

    pub fn item(&self, id: &str) -> Option<&Item> {
        self.items.get(id).map(|(_, i)| i)
    }

    pub fn item_vault(&self, id: &str) -> Option<&str> {
        self.items.get(id).map(|(v, _)| v.as_str())
    }

    /// Iterate over all decrypted items with their vault id.
    pub fn all_items(&self) -> impl Iterator<Item = (&str, &Item)> {
        self.items.values().map(|(v, i)| (v.as_str(), i))
    }

    pub fn item_count(&self) -> usize {
        self.items.values().filter(|(_, i)| !i.is_trashed()).count()
    }

    pub fn list(&self, filter: &ItemFilter) -> Vec<ItemSummary> {
        let mut out: Vec<ItemSummary> = self
            .items
            .values()
            .filter(|(v, _)| filter.vault_id.as_deref().is_none_or(|f| f == v))
            .filter(|(_, i)| i.is_trashed() == filter.trashed)
            .filter(|(_, i)| filter.category.is_none_or(|c| c == i.category))
            .filter(|(_, i)| !filter.favorites_only || i.favorite)
            .filter(|(_, i)| filter.tag.as_deref().is_none_or(|t| i.tags.iter().any(|x| x.eq_ignore_ascii_case(t))))
            .filter(|(_, i)| i.matches(&filter.query))
            .map(|(v, i)| i.summary(v))
            .collect();
        out.sort_by(|a, b| {
            a.title.to_lowercase().cmp(&b.title.to_lowercase()).then(a.subtitle.cmp(&b.subtitle)).then(a.id.cmp(&b.id))
        });
        out
    }

    /// Find exactly one item by id or title (case-insensitive), optionally
    /// restricted to a vault.
    pub fn find_item(&self, query: &str, vault_id: Option<&str>) -> Result<&Item> {
        if let Some((v, item)) = self.items.get(query) {
            if vault_id.is_none_or(|f| f == v) {
                return Ok(item);
            }
        }
        let lower = query.trim().to_lowercase();
        let candidates: Vec<&Item> = self
            .items
            .values()
            .filter(|(v, i)| !i.is_trashed() && vault_id.is_none_or(|f| f == v))
            .map(|(_, i)| i)
            .filter(|i| i.title.to_lowercase() == lower || i.id.starts_with(&lower) && lower.len() >= 8)
            .collect();
        match candidates.len() {
            0 => Err(Error::not_found(format!("item '{query}'"))),
            1 => Ok(candidates[0]),
            n => Err(Error::invalid(format!("{n} items match '{query}', use the item id instead"))),
        }
    }

    /// Items whose URLs match the given page (used for autofill).
    pub fn items_for_url(&self, page_url: &str) -> Vec<ItemSummary> {
        let mut out: Vec<ItemSummary> = self
            .items
            .values()
            .filter(|(_, i)| !i.is_trashed())
            .filter(|(_, i)| i.urls.iter().any(|u| url_matches(u, page_url)))
            .map(|(v, i)| i.summary(v))
            .collect();
        out.sort_by(|a, b| b.favorite.cmp(&a.favorite).then(a.title.cmp(&b.title)));
        out
    }

    /// Passkeys for the website `rp_id`, with the id of the item holding them
    /// (items in the trash are left out).
    pub fn passkeys_for(&self, rp_id: &str) -> Vec<(String, Passkey)> {
        let mut out: Vec<(String, Passkey)> = self
            .items
            .values()
            .filter(|(_, i)| !i.is_trashed())
            .flat_map(|(_, i)| i.passkeys.iter().filter(|p| p.rp_id == rp_id).map(|p| (i.id.clone(), p.clone())))
            .collect();
        out.sort_by(|a, b| a.1.user_name.cmp(&b.1.user_name));
        out
    }

    /// Store a new passkey: in the login `item_id` if given, otherwise in a
    /// new login for the website at `url` in `vault_id`. Returns the item id.
    pub fn save_passkey(
        &mut self,
        vault_id: &str,
        item_id: Option<&str>,
        url: &str,
        passkey: Passkey,
    ) -> Result<String> {
        if let Some(id) = item_id {
            let mut item = self.item(id).ok_or_else(|| Error::not_found(format!("item {id}")))?.clone();
            item.passkeys.retain(|p| p.credential_id != passkey.credential_id);
            item.passkeys.push(passkey);
            self.update_item(item)?;
            return Ok(id.to_string());
        }
        let title = if passkey.rp_name.is_empty() { passkey.rp_id.clone() } else { passkey.rp_name.clone() };
        let mut item = Item::login(&title, &passkey.user_name, "", Some(url));
        item.passkeys.push(passkey);
        self.add_item(vault_id, item)
    }

    /// Delete one passkey from an item.
    pub fn remove_passkey(&mut self, item_id: &str, credential_id: &str) -> Result<()> {
        let mut item = self.item(item_id).ok_or_else(|| Error::not_found(format!("item {item_id}")))?.clone();
        let before = item.passkeys.len();
        item.passkeys.retain(|p| p.credential_id != credential_id);
        if item.passkeys.len() == before {
            return Err(Error::not_found("passkey"));
        }
        self.update_item(item)
    }

    /// All tags with the number of items using them.
    pub fn tags(&self) -> Vec<(String, usize)> {
        let mut map: BTreeMap<String, (String, usize)> = BTreeMap::new();
        for (_, item) in self.items.values() {
            if item.is_trashed() {
                continue;
            }
            for tag in &item.tags {
                let e = map.entry(tag.to_lowercase()).or_insert_with(|| (tag.clone(), 0));
                e.1 += 1;
            }
        }
        map.into_values().collect()
    }

    fn writable_vault(&self, vault_id: &str) -> Result<()> {
        let rec = self
            .profile
            .vault(vault_id)
            .filter(|v| v.sync_state != SyncState::PendingDelete)
            .ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        if !rec.role.can_write() {
            return Err(Error::PermissionDenied("this vault is read-only for you".into()));
        }
        Ok(())
    }

    fn store_item(&mut self, vault_id: &str, item: Item) -> Result<()> {
        item.validate()?;
        let data = self.encrypt_item(vault_id, &item)?;
        match self.profile.item_mut(&item.id) {
            Some(rec) => {
                rec.data = Some(data);
                rec.dirty = true;
            }
            None => self.profile.items.push(ItemRecord {
                id: item.id.clone(),
                vault_id: vault_id.to_string(),
                data: Some(data),
                revision: 0,
                dirty: true,
            }),
        }
        self.items.insert(item.id.clone(), (vault_id.to_string(), item));
        Ok(())
    }

    /// Add a new item to a vault. Returns the item id.
    pub fn add_item(&mut self, vault_id: &str, mut item: Item) -> Result<String> {
        self.writable_vault(vault_id)?;
        if item.id.is_empty() || self.items.contains_key(&item.id) || self.profile.item(&item.id).is_some() {
            item.id = new_id();
        }
        item.normalize();
        let ts = now();
        if item.created_at == 0 {
            item.created_at = ts;
        }
        item.updated_at = ts;
        if item.password_changed_at.is_none() && item.password().is_some() {
            item.password_changed_at = Some(ts);
        }
        let id = item.id.clone();
        self.store_item(vault_id, item)?;
        Ok(id)
    }

    /// Save changes to an existing item.
    pub fn update_item(&mut self, mut item: Item) -> Result<()> {
        let (vault_id, previous) = self
            .items
            .get(&item.id)
            .map(|(v, i)| (v.clone(), i.clone()))
            .ok_or_else(|| Error::not_found(format!("item {}", item.id)))?;
        self.writable_vault(&vault_id)?;
        item.normalize();
        item.track_password_change(&previous);
        item.created_at = previous.created_at;
        item.updated_at = now().max(previous.updated_at + 1);
        self.store_item(&vault_id, item)
    }

    fn modify_item(&mut self, id: &str, f: impl FnOnce(&mut Item)) -> Result<()> {
        let mut item = self.item(id).cloned().ok_or_else(|| Error::not_found(format!("item {id}")))?;
        f(&mut item);
        self.update_item(item)
    }

    /// Give an item the icon fetched for its website, unless its website
    /// changed in the meantime.
    pub fn set_icon(&mut self, id: &str, icon: crate::favicon::WebsiteIcon) -> Result<()> {
        let item = self.item(id).ok_or_else(|| Error::not_found(format!("item {id}")))?;
        if crate::favicon::icon_host(item).as_deref() != Some(icon.host.as_str()) || item.icon.as_ref() == Some(&icon) {
            return Ok(());
        }
        self.modify_item(id, |i| i.icon = Some(icon))
    }

    pub fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<()> {
        self.modify_item(id, |i| i.favorite = favorite)
    }

    /// Move an item to the trash (recoverable).
    /// Give an item a one-time password (see [`Item::set_totp`]).
    pub fn set_totp(&mut self, id: &str, value: &str) -> Result<()> {
        self.modify_item(id, |i| i.set_totp(value))
    }

    pub fn trash_item(&mut self, id: &str) -> Result<()> {
        self.modify_item(id, |i| i.trashed_at = Some(now()))
    }

    pub fn restore_item(&mut self, id: &str) -> Result<()> {
        self.modify_item(id, |i| i.trashed_at = None)
    }

    /// Permanently delete an item.
    pub fn delete_item(&mut self, id: &str) -> Result<()> {
        let vault_id =
            self.item_vault(id).map(|s| s.to_string()).ok_or_else(|| Error::not_found(format!("item {id}")))?;
        self.writable_vault(&vault_id)?;
        self.items.remove(id);
        let rec = self.profile.item_mut(id).expect("record exists for every item");
        if rec.revision == 0 {
            self.profile.items.retain(|i| i.id != id);
        } else {
            rec.data = None;
            rec.dirty = true;
        }
        Ok(())
    }

    /// Permanently delete everything in the trash. Returns the count.
    pub fn empty_trash(&mut self, vault_id: Option<&str>) -> Result<usize> {
        let ids: Vec<String> = self
            .items
            .iter()
            .filter(|(_, (v, i))| i.is_trashed() && vault_id.is_none_or(|f| f == v))
            .filter(|(_, (v, _))| self.profile.vault(v).is_some_and(|r| r.role.can_write()))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            self.delete_item(id)?;
        }
        Ok(ids.len())
    }

    /// Move an item to another vault (it is re-encrypted with the target
    /// vault key and gets a new id). Returns the new id.
    pub fn move_item(&mut self, id: &str, target_vault: &str) -> Result<String> {
        let source =
            self.item_vault(id).map(|s| s.to_string()).ok_or_else(|| Error::not_found(format!("item {id}")))?;
        if source == target_vault {
            return Ok(id.to_string());
        }
        self.writable_vault(target_vault)?;
        self.writable_vault(&source)?;
        let mut item = self.item(id).cloned().expect("checked above");
        item.id = new_id();
        let created = item.created_at;
        let new_id = self.add_item(target_vault, item)?;
        if let Some((_, i)) = self.items.get_mut(&new_id) {
            i.created_at = created;
        }
        self.delete_item(id)?;
        Ok(new_id)
    }

    /// Create a copy of an item in the same vault.
    pub fn duplicate_item(&mut self, id: &str) -> Result<String> {
        let vault = self.item_vault(id).map(|s| s.to_string()).ok_or_else(|| Error::not_found(format!("item {id}")))?;
        let mut copy = self.item(id).cloned().expect("checked above");
        copy.id = new_id();
        copy.title = format!("{} (copy)", copy.title);
        copy.created_at = 0;
        copy.password_history.clear();
        self.add_item(&vault, copy)
    }

    // ------------------------------------------------------------------
    // Account management
    // ------------------------------------------------------------------

    pub fn rename_account(&mut self, name: &str) {
        self.profile.account.name = name.trim().to_string();
    }

    /// The profile photo, as a checked `data:image/…` URL.
    pub fn avatar(&self) -> Option<String> {
        let account = &self.profile.account;
        let plain = decrypt(&self.keyset.account_key, account.avatar.as_ref()?, &aad::avatar(&account.id)).ok()?;
        let url = String::from_utf8(plain.to_vec()).ok()?;
        crate::favicon::is_image_data_url(&url).then_some(url)
    }

    /// Set (a `data:image/…` URL of at most [`MAX_AVATAR_BYTES`]) or remove
    /// the profile photo. It is encrypted with the account key and goes to
    /// the server with the next sync.
    pub fn set_avatar(&mut self, image: Option<&str>) -> Result<()> {
        let avatar = match image {
            Some(url) if url.len() > MAX_AVATAR_BYTES || !crate::favicon::is_image_data_url(url) => {
                return Err(Error::invalid("the photo is too large or not an image"));
            }
            Some(url) => {
                Some(encrypt(&self.keyset.account_key, url.as_bytes(), &aad::avatar(&self.profile.account.id)))
            }
            None => None,
        };
        self.profile.account.avatar = avatar;
        self.profile.account.avatar_dirty = true;
        Ok(())
    }

    /// A photo change for the server: `Some(photo)` while one waits.
    pub fn avatar_to_upload(&self) -> Option<Option<EncString>> {
        let account = &self.profile.account;
        account.avatar_dirty.then(|| account.avatar.clone())
    }

    /// The server has `sent`; done unless the photo changed again meanwhile.
    pub fn mark_avatar_uploaded(&mut self, sent: &Option<EncString>) {
        if &self.profile.account.avatar == sent {
            self.profile.account.avatar_dirty = false;
        }
    }

    /// Ask the server for the photo with the next sync.
    pub fn recheck_avatar(&mut self) {
        self.profile.account.avatar_checked_at = 0;
    }

    /// Whether to ask the server for the photo again (at most hourly).
    pub fn avatar_check_due(&self) -> bool {
        !self.profile.account.avatar_dirty && now() - self.profile.account.avatar_checked_at >= 3600
    }

    /// Take the server's photo (another device changed it), unless this
    /// device has a change of its own waiting or it does not open with our
    /// key. Returns whether the photo changed.
    pub fn apply_server_avatar(&mut self, avatar: Option<EncString>) -> bool {
        let account = &mut self.profile.account;
        account.avatar_checked_at = now();
        if account.avatar_dirty || account.avatar == avatar {
            return false;
        }
        if let Some(enc) = &avatar {
            if decrypt(&self.keyset.account_key, enc, &aad::avatar(&account.id)).is_err() {
                return false;
            }
        }
        account.avatar = avatar;
        true
    }

    /// Compute a master password change without applying it. Apply it with
    /// [`Session::commit_password_change`] (after the server accepted it).
    pub fn prepare_password_change(
        &self,
        current_password: &str,
        new_password: &str,
        secret_key: &SecretKey,
    ) -> Result<PasswordChange> {
        require_master_password(new_password, &[&self.profile.account.name, &self.profile.account.email])?;
        let current = self.verify_password(current_password, secret_key)?;
        let salt: [u8; 16] = random_bytes();
        let kdf = KdfParams::default().max_with(&self.profile.account.kdf);
        let new_keys = derive_keys(new_password, secret_key, &self.profile.account.email, &salt, &kdf)?;
        Ok(PasswordChange {
            current_auth_key: current.auth_key,
            new_auth_key: new_keys.auth_key,
            salt: b64(&salt),
            kdf,
            keyset: self.keyset.encrypt(&new_keys.master_key),
        })
    }

    pub fn commit_password_change(&mut self, change: &PasswordChange) {
        self.profile.account.salt = change.salt.clone();
        self.profile.account.kdf = change.kdf.clone();
        self.profile.account.keyset = change.keyset.clone();
    }

    // ------------------------------------------------------------------
    // Server link
    // ------------------------------------------------------------------

    pub fn server(&self) -> Option<&ServerLink> {
        self.profile.server.as_ref()
    }

    /// Link this account to a sync server and store the (encrypted) token.
    pub fn set_server(&mut self, url: &str, token: &str) {
        let enc = encrypt(&self.keyset.account_key, token.as_bytes(), &aad::server_token(&self.profile.account.id));
        match &mut self.profile.server {
            Some(link) if link.url == url => link.token = Some(enc),
            _ => {
                self.profile.server = Some(ServerLink {
                    url: url.trim_end_matches('/').to_string(),
                    token: Some(enc),
                    last_sync_at: None,
                    pq_key_published: false,
                })
            }
        }
    }

    pub fn server_token(&self) -> Option<String> {
        let enc = self.profile.server.as_ref()?.token.as_ref()?;
        let raw =
            crate::crypto::decrypt(&self.keyset.account_key, enc, &aad::server_token(&self.profile.account.id)).ok()?;
        String::from_utf8(raw.to_vec()).ok()
    }

    /// Forget the session token (sign out of the server, keep the link).
    pub fn clear_server_token(&mut self) {
        if let Some(link) = &mut self.profile.server {
            link.token = None;
        }
    }

    /// Disconnect from the server. The data stays on this device and the
    /// account becomes a local-only account.
    pub fn unlink_server(&mut self) {
        self.profile.server = None;
        let deleted: Vec<String> = self
            .profile
            .vaults
            .iter()
            .filter(|v| v.sync_state == SyncState::PendingDelete)
            .map(|v| v.id.clone())
            .collect();
        self.profile.vaults.retain(|v| !deleted.contains(&v.id));
        self.profile.vaults.retain(|v| v.owner_id == self.profile.account.id);
        let kept: Vec<String> = self.profile.vaults.iter().map(|v| v.id.clone()).collect();
        self.vaults.retain(|id, _| kept.contains(id));
        self.items.retain(|_, (v, _)| kept.contains(v));
        self.profile.items.retain(|i| i.data.is_some() && kept.contains(&i.vault_id));
        for v in &mut self.profile.vaults {
            v.sync_state = SyncState::PendingCreate;
            v.revision = 0;
            v.member_count = 1;
        }
        for i in &mut self.profile.items {
            i.revision = 0;
            i.dirty = true;
        }
    }
}

impl KdfParams {
    /// Component-wise maximum, so a password change never weakens the KDF.
    pub fn max_with(&self, other: &KdfParams) -> KdfParams {
        if other.algorithm != self.algorithm {
            return self.clone();
        }
        KdfParams {
            algorithm: self.algorithm.clone(),
            memory_kib: self.memory_kib.max(other.memory_kib),
            iterations: self.iterations.max(other.iterations),
            parallelism: self.parallelism.max(other.parallelism),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn new_session() -> (Session, SecretKey) {
        Session::create_account(
            "Test User",
            "test@example.com",
            "correct horse battery staple",
            KdfParams::insecure_for_tests(),
            "Personal",
        )
        .unwrap()
    }

    #[test]
    fn create_lock_unlock() {
        let (mut s, sk) = new_session();
        let vault = s.default_vault_id().unwrap();
        let id = s.add_item(&vault, Item::login("GitHub", "octo", "pw1", Some("github.com"))).unwrap();
        let json = s.profile().to_json();
        assert!(!json.contains("octo"), "profile must not contain plaintext");
        assert!(!json.contains("GitHub"));
        assert!(!json.contains("Personal"));

        let profile = Profile::from_json(&json).unwrap();
        let s2 = Session::unlock(profile.clone(), "correct horse battery staple", &sk).unwrap();
        assert_eq!(s2.item(&id).unwrap().username(), Some("octo"));
        assert_eq!(s2.vaults()[0].name, "Personal");
        assert!(matches!(Session::unlock(profile.clone(), "wrong password!", &sk), Err(Error::WrongPassword)));
        assert!(matches!(
            Session::unlock(profile, "correct horse battery staple", &SecretKey::generate()),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn website_icons() {
        let (mut s, _) = new_session();
        let vault = s.default_vault_id().unwrap();
        let id = s.add_item(&vault, Item::login("GitHub", "octo", "pw1", Some("https://github.com/login"))).unwrap();
        let icon = |host: &str| crate::favicon::WebsiteIcon::from_bytes(host, b"\x89PNG\r\n\x1a\n").unwrap();
        // Fetched for a website the item no longer has: ignored.
        s.set_icon(&id, icon("gitlab.com")).unwrap();
        assert_eq!(s.item(&id).unwrap().icon, None);
        s.set_icon(&id, icon("github.com")).unwrap();
        assert_eq!(s.item(&id).unwrap().icon, Some(icon("github.com")));
        assert!(!s.profile().to_json().contains("github.com"), "the icon is encrypted with the item");
        // Another website: the old icon goes.
        let mut item = s.item(&id).unwrap().clone();
        item.urls = vec!["https://gitlab.com".into()];
        s.update_item(item).unwrap();
        assert_eq!(s.item(&id).unwrap().icon, None);
    }

    #[test]
    fn profile_photo() {
        let (mut s, _) = new_session();
        let photo = "data:image/jpeg;base64,/9j/4AAQSkZJRg==";
        assert_eq!(s.avatar(), None);
        assert!(s.set_avatar(Some("data:text/html;base64,PGI+")).is_err());
        assert!(s.set_avatar(Some(&format!("data:image/png;base64,{}", "A".repeat(MAX_AVATAR_BYTES)))).is_err());
        s.set_avatar(Some(photo)).unwrap();
        assert_eq!(s.avatar().as_deref(), Some(photo));
        assert!(!s.profile().to_json().contains("/9j/4AAQ"), "the photo is encrypted");

        // Waiting to be sent: the server's (older) photo does not replace it.
        let sent = s.avatar_to_upload().unwrap();
        assert!(sent.is_some());
        assert!(!s.avatar_check_due());
        assert!(!s.apply_server_avatar(None));
        s.mark_avatar_uploaded(&sent);
        assert_eq!(s.avatar_to_upload(), None);

        // Another device removed it.
        assert!(s.apply_server_avatar(None));
        assert_eq!(s.avatar(), None);
        // Something that does not open with our key is ignored.
        let (other, _) = new_session();
        let foreign = encrypt(&other.keyset.account_key, photo.as_bytes(), &aad::avatar(&s.account().id));
        assert!(!s.apply_server_avatar(Some(foreign)));
        assert!(s.apply_server_avatar(sent));
        assert_eq!(s.avatar().as_deref(), Some(photo));
    }

    #[test]
    fn short_password_rejected() {
        assert!(Session::create_account("x", "x@y.z", "short", KdfParams::insecure_for_tests(), "P").is_err());
    }

    #[test]
    fn account_key_reopen() {
        let (s, _) = new_session();
        let ak = s.account_key().clone();
        let s2 = Session::open_with_account_key(s.profile().clone(), ak).unwrap();
        assert_eq!(s2.vaults().len(), 1);
        assert!(Session::open_with_account_key(s.profile().clone(), SymmetricKey::generate()).is_err());
    }

    #[test]
    fn item_lifecycle() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let id = s.add_item(&v, Item::login("Mail", "me", "old", None)).unwrap();
        let mut item = s.item(&id).unwrap().clone();
        item.set_value("password", "new");
        s.update_item(item).unwrap();
        assert_eq!(s.item(&id).unwrap().password_history[0].value, "old");

        s.trash_item(&id).unwrap();
        assert!(s.list(&ItemFilter::default()).is_empty());
        assert_eq!(s.list(&ItemFilter { trashed: true, ..Default::default() }).len(), 1);
        s.restore_item(&id).unwrap();
        assert_eq!(s.list(&ItemFilter::default()).len(), 1);

        let dup = s.duplicate_item(&id).unwrap();
        assert_eq!(s.item(&dup).unwrap().title, "Mail (copy)");

        let v2 = s.create_vault("Work", "").unwrap();
        let moved = s.move_item(&id, &v2).unwrap();
        assert!(s.item(&id).is_none());
        assert_eq!(s.item_vault(&moved), Some(v2.as_str()));

        s.trash_item(&dup).unwrap();
        assert_eq!(s.empty_trash(None).unwrap(), 1);
        assert!(s.item(&dup).is_none());
        // Never-synced items leave no tombstone behind.
        assert!(s.profile().item(&dup).is_none());
    }

    #[test]
    fn oversized_items_are_refused() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let mut item = Item::new(Category::Document, "Big");
        for i in 0..2 {
            let data = vec![i as u8; crate::item::MAX_ATTACHMENT_BYTES];
            item.attachments.push(crate::item::Attachment::new("a.bin", "", &data).unwrap());
        }
        assert!(s.add_item(&v, item).is_err());
        assert_eq!(s.item_count(), 0);
    }

    #[test]
    fn filters_and_find() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let mut a = Item::login("Alpha", "a", "1", Some("https://alpha.com"));
        a.favorite = true;
        a.tags = vec!["work".into()];
        s.add_item(&v, a).unwrap();
        s.add_item(&v, Item::new(Category::SecureNote, "Beta")).unwrap();
        assert_eq!(s.list(&ItemFilter { favorites_only: true, ..Default::default() }).len(), 1);
        assert_eq!(s.list(&ItemFilter { category: Some(Category::SecureNote), ..Default::default() })[0].title, "Beta");
        assert_eq!(s.list(&ItemFilter { tag: Some("WORK".into()), ..Default::default() }).len(), 1);
        assert_eq!(s.find_item("alpha", None).unwrap().title, "Alpha");
        assert!(s.find_item("gamma", None).is_err());
        assert_eq!(s.items_for_url("https://login.alpha.com/x").len(), 1);
        assert_eq!(s.tags(), vec![("work".to_string(), 1)]);
    }

    #[test]
    fn vault_management() {
        let (mut s, _) = new_session();
        let id = s.create_vault("Family", "Shared stuff").unwrap();
        assert_eq!(s.find_vault("family").unwrap().id, id);
        s.update_vault(&id, "Familie", "", None).unwrap();
        assert_eq!(s.vault(&id).unwrap().name, "Familie");
        s.add_item(&id, Item::login("Netflix", "fam", "pw", None)).unwrap();
        s.delete_vault(&id).unwrap();
        assert!(s.vault(&id).is_none());
        assert_eq!(s.item_count(), 0);
    }

    #[test]
    fn password_change() {
        let (mut s, sk) = new_session();
        let change = s.prepare_password_change("correct horse battery staple", "a brand new password", &sk).unwrap();
        assert!(s.prepare_password_change("nope nope nope", "a brand new password", &sk).is_err());
        s.commit_password_change(&change);
        let p = s.profile().clone();
        assert!(Session::unlock(p.clone(), "a brand new password", &sk).is_ok());
        assert!(Session::unlock(p, "correct horse battery staple", &sk).is_err());
    }

    #[test]
    fn server_token_is_encrypted() {
        let (mut s, _) = new_session();
        s.set_server("https://vault.example.com/", "tok-123");
        assert_eq!(s.server_token().as_deref(), Some("tok-123"));
        assert!(!s.profile().to_json().contains("tok-123"));
        assert_eq!(s.server().unwrap().url, "https://vault.example.com");
    }

    #[test]
    fn sharing_wraps_for_recipient() {
        let (s, _) = new_session();
        let (bob, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let wrapped = s.wrap_vault_key_for(&v, &bob.public_keys()).unwrap();
        assert!(matches!(wrapped, WrappedKey::HybridSealed { .. }));
        let key = wrapped.unwrap(bob.keyset(), &aad::vault_key(&v)).unwrap();
        assert_eq!(&key, s.vault_key(&v).unwrap());
    }

    #[test]
    fn new_items_go_to_the_personal_vault() {
        let (mut s, _) = new_session();
        let personal = s.default_vault_id().unwrap();
        // Created in the same second as the personal vault, and sorted before it.
        s.create_vault("Aardvark", "").unwrap();
        assert_eq!(s.default_vault_id().unwrap(), personal);

        // On devices that signed in later there is no stored default: a vault
        // someone shared with us must not win over our own.
        let (alice, _) = new_session();
        let v = alice.default_vault_id().unwrap();
        let mut record = alice.profile().vault(&v).unwrap().clone();
        record.wrapped_key = alice.wrap_vault_key_for(&v, &s.public_keys()).unwrap();
        record.owner_id = alice.account().id.clone();
        record.role = Role::Editor;
        record.created_at = 0;
        record.sync_state = SyncState::Synced;
        s.profile.vaults.push(record);
        s.profile.default_vault = None;
        s.reload().unwrap();
        let chosen = s.vault(&s.default_vault_id().unwrap()).unwrap();
        assert!(chosen.is_owner);
    }

    #[test]
    fn shared_vault_keys_are_rewrapped_with_the_own_account_key() {
        let (alice, _) = new_session();
        let (mut bob, _) = new_session();
        let v = alice.default_vault_id().unwrap();
        let wrapped = alice.wrap_vault_key_for(&v, &bob.public_keys()).unwrap();
        // Bob receives the shared vault as the sync engine would store it.
        let mut record = alice.profile().vault(&v).unwrap().clone();
        record.wrapped_key = wrapped;
        record.owner_id = alice.account().id.clone();
        record.role = Role::Editor;
        record.sync_state = SyncState::Synced;
        bob.profile.vaults.push(record);
        bob.reload().unwrap();
        let rewraps = bob.vault_keys_to_rewrap();
        assert_eq!(rewraps.len(), 1);
        let rewrap = rewraps.into_iter().next().unwrap();
        assert!(!rewrap.wrapped_key.is_sealed());
        bob.set_vault_wrapped_key(&rewrap.vault_id, rewrap.wrapped_key);
        bob.reload().unwrap();
        assert_eq!(bob.vault_key(&v), alice.vault_key(&v));
        assert!(bob.vault_keys_to_rewrap().is_empty());
    }

    #[test]
    fn pq_key_is_published_once_per_server() {
        let (mut s, _) = new_session();
        assert!(s.pq_key_to_publish().is_none());
        s.set_server("https://vault.example.com", "tok");
        let key = s.pq_key_to_publish().unwrap();
        assert_eq!(Some(key), s.public_keys().ml_kem.map(|k| k.to_b64()));
        s.mark_pq_key_published();
        assert!(s.pq_key_to_publish().is_none());
    }
}
