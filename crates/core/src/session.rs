//! An unlocked account: decrypted keys, vaults and items in memory.
//!
//! Every mutating method immediately re-encrypts the affected data into the
//! underlying [`Profile`], so `session.profile()` is always ready to be
//! persisted.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::crypto::{
    decrypt_json, derive_keys, encrypt, encrypt_json, DerivedKeys, EncString, EncryptedKeyset, KdfParams, Keyset,
    PublicKey, SecretKey, SymmetricKey, WrappedKey,
};
use crate::item::{Category, Item, ItemSummary};
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
        };
        let profile = Profile {
            format: PROFILE_FORMAT.into(),
            version: PROFILE_VERSION,
            account,
            server: None,
            vaults: Vec::new(),
            items: Vec::new(),
        };
        let mut session = Session::from_parts(profile, keyset)?;
        let name = if default_vault_name.trim().is_empty() { "Personal" } else { default_vault_name };
        session.create_vault(name, "")?;
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

    /// The vault new items go to by default: the oldest vault we own.
    pub fn default_vault_id(&self) -> Option<String> {
        self.vaults().into_iter().find(|v| v.role.can_write()).map(|v| v.id)
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

    /// Wrap a vault key for another account (vault sharing).
    pub fn wrap_vault_key_for(&self, vault_id: &str, recipient: &PublicKey) -> Result<WrappedKey> {
        let key = self.vault_key(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        Ok(WrappedKey::wrap_sealed(recipient, key, &aad::vault_key(vault_id)))
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

    pub fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<()> {
        self.modify_item(id, |i| i.favorite = favorite)
    }

    /// Move an item to the trash (recoverable).
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
        let wrapped = s.wrap_vault_key_for(&v, &bob.public_key()).unwrap();
        let key = wrapped.unwrap(bob.keyset(), &aad::vault_key(&v)).unwrap();
        assert_eq!(&key, s.vault_key(&v).unwrap());
    }
}
