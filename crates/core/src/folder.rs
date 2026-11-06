//! Vaults in storage folders: a folder that iCloud Drive, Dropbox, Google
//! Drive, OneDrive, Syncthing or a network share keeps in sync between
//! devices. This module holds the file format and the rules for merging what
//! the devices write there; `docs/VAULT-FOLDER.md` describes both.
//!
//! It does no I/O. The client reads the vault's folder into a [`Snapshot`],
//! [`Session::apply_folder`] merges it into the session and returns the files
//! to write and remove ([`FolderPlan`]), and once they are written the client
//! calls [`Session::folder_written`].
//!
//! Every device writes only its own files, named after its device tag
//! (`<item>~<tag>.json`), so storage apps never see two devices change the
//! same file. Copies they make anyway ("… 2.json", "… (conflicted copy).json")
//! are read like the rest. Everything in the folder is encrypted with the
//! vault key; a deletion is an encrypted tombstone, so the storage service
//! cannot fake one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt_json, encrypt_json, EncString, SymmetricKey, WrappedKey};
use crate::item::Item;
use crate::profile::{
    aad, FolderService, ItemRecord, Leftover, MoveTarget, MovedTo, Role, SyncState, VaultLocation, VaultMeta,
    VaultRecord,
};
use crate::session::Session;
use crate::sync::merge_password_history;
use crate::util::{now, random_bytes};
use crate::{Error, Result};

/// `format` of a `vault.json`.
pub const FORMAT: &str = "2secret-vault-folder";
/// Newest version of the folder format this code reads and writes.
pub const VERSION: u32 = 1;
/// The file that says which vault a folder holds (written once).
pub const VAULT_FILE: &str = "vault.json";
/// Written in a folder whose vault moved elsewhere (or was deleted).
pub const MOVED_FILE: &str = "moved.json";
/// The folder with the item files.
pub const ITEMS_DIR: &str = "items";
/// The folder 2Secret makes in a chosen folder, for its vault folders.
pub const PARENT_DIR: &str = "2Secret";
/// How long a deletion is remembered in the folder, in days. A device that
/// was away longer can bring a deleted item back.
pub const TOMBSTONE_DAYS: i64 = 90;
/// Length of a device tag.
pub const TAG_LEN: usize = 10;
/// Start of the name of a file being written (renamed when complete).
pub const TEMP_PREFIX: &str = ".~tmp-";

/// `vault.json`: which vault the folder holds, and its key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultFile {
    pub format: String,
    pub version: u32,
    pub vault_id: String,
    /// The account the vault belongs to (only that account can open it).
    pub account_id: String,
    pub created_at: i64,
    /// The vault key, wrapped with the account key.
    pub wrapped_key: WrappedKey,
}

impl VaultFile {
    pub fn parse(json: &str) -> Result<VaultFile> {
        let file: VaultFile =
            serde_json::from_str(json).map_err(|_| Error::invalid("this folder does not hold a 2Secret vault"))?;
        if file.format != FORMAT {
            return Err(Error::invalid("this folder does not hold a 2Secret vault"));
        }
        if file.version > VERSION {
            return Err(Error::Unsupported("this vault folder was written by a newer 2Secret; update 2Secret".into()));
        }
        if !valid_id(&file.vault_id) {
            return Err(Error::invalid("this folder does not hold a 2Secret vault"));
        }
        Ok(file)
    }
}

/// `meta~<tag>.json`: one device's version of the vault's name, description
/// and icon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaFile {
    pub vault_id: String,
    /// A [`MetaVersion`], encrypted with the vault key.
    pub meta: EncString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct MetaVersion {
    meta: VaultMeta,
    updated_at: i64,
}

/// `items/<item>~<tag>.json`: one device's version of an item, or its
/// deletion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemFile {
    pub id: String,
    pub vault_id: String,
    /// The item, encrypted exactly as for the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<EncString>,
    /// For a deleted item: a [`Tombstone`], encrypted with the vault key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tomb: Option<EncString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Tombstone {
    deleted_at: i64,
}

/// `moved.json`: where the vault went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MovedFile {
    pub vault_id: String,
    /// A [`MovedTo`], encrypted with the vault key.
    pub moved: EncString,
}

/// Everything read from a vault's folder.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// The `meta~…` files: file name and contents.
    pub metas: Vec<(String, MetaFile)>,
    /// The files in `items/`: file name and contents.
    pub items: Vec<(String, ItemFile)>,
    pub moved: Option<MovedFile>,
    /// Files that could not be read yet (still downloading, damaged). They
    /// are skipped and tried again next time, never taken as a deletion.
    pub unreadable: usize,
}

/// What a folder sync did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderReport {
    /// Items added or changed here from the folder.
    pub downloaded: usize,
    /// Items deleted here because they were deleted in the folder.
    pub deleted: usize,
    /// Files this device writes into the folder.
    pub written: usize,
    /// Files skipped because they could not be read or opened.
    pub unreadable: usize,
    /// The vault's name, description or icon changed.
    #[serde(default)]
    pub meta_changed: bool,
    /// The folder says the vault moved elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved: Option<MovedTo>,
}

/// Files to write and remove after [`Session::apply_folder`], with paths
/// relative to the vault's folder (`/` between parts).
#[derive(Clone, Debug, Default)]
pub struct FolderPlan {
    pub vault_id: String,
    pub write: Vec<(String, String)>,
    pub remove: Vec<String>,
    pub report: FolderReport,
    /// The local data of each item written (`None`: its tombstone), so that
    /// [`Session::folder_written`] leaves alone what changed meanwhile.
    written_items: Vec<(String, Option<EncString>)>,
    written_meta: Option<EncString>,
}

/// A file name in a vault folder: `<stem>~<tag>.json`, or a copy that a
/// storage app made of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileName {
    /// The item id, or `meta`.
    pub stem: String,
    pub tag: String,
    /// Exactly as 2Secret names it (not a copy).
    pub exact: bool,
}

fn tag_char(c: char) -> bool {
    c.is_ascii_lowercase() || ('2'..='7').contains(&c)
}

/// Recognise a vault folder file name, including the copies storage apps
/// make (`x~tag 2.json`, `x~tag (1).json`, `x~tag (conflicted copy).json`,
/// `x~tag-PC.json`, `x~tag.sync-conflict-….json`). Temporary files and
/// iCloud placeholders (starting with `.`) are not recognised.
pub fn parse_file_name(name: &str) -> Option<FileName> {
    if name.starts_with('.') || !name.to_ascii_lowercase().ends_with(".json") {
        return None;
    }
    let (stem, rest) = name.split_once('~')?;
    let tag = rest.get(..TAG_LEN)?;
    if stem.is_empty() || !tag.chars().all(tag_char) {
        return None;
    }
    let after = &rest[TAG_LEN..];
    if after.chars().next().is_some_and(tag_char) {
        return None;
    }
    Some(FileName { stem: stem.to_string(), tag: tag.to_string(), exact: after == ".json" })
}

/// Whether an id can be part of a file name (as the server accepts them).
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// The file of an item version (relative to the vault folder).
pub fn item_path(item_id: &str, tag: &str) -> String {
    format!("{ITEMS_DIR}/{item_id}~{tag}.json")
}

/// The file of a device's version of the vault metadata.
pub fn meta_path(tag: &str) -> String {
    format!("meta~{tag}.json")
}

/// The name of a new vault's folder: its name (made safe for every file
/// system) and the start of its id, e.g. `Work-1a2b3c4d`.
pub fn vault_dir_name(name: &str, vault_id: &str) -> String {
    let mut safe: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' { c } else { '-' })
        .collect::<String>()
        .trim()
        .trim_matches('-')
        .chars()
        .take(40)
        .collect();
    safe = safe.trim().to_string();
    if safe.is_empty() {
        safe = "Vault".into();
    }
    let short: String = vault_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    format!("{safe}-{short}")
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("serialization cannot fail")
}

/// One version of an item in the folder.
struct Version {
    name: String,
    tag: String,
    exact: bool,
    item: Option<Item>,
    data: Option<EncString>,
    deleted_at: Option<i64>,
}

impl Session {
    /// This device's tag in storage folders (made on first use).
    pub fn device_tag(&mut self) -> String {
        if let Some(tag) = &self.profile().device_tag {
            return tag.clone();
        }
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let tag: String = random_bytes::<TAG_LEN>().iter().map(|b| ALPHABET[(*b % 32) as usize] as char).collect();
        self.profile_mut().device_tag = Some(tag.clone());
        tag
    }

    /// Check that `file` is the `vault.json` of our vault `vault_id`: same
    /// vault, same account, same key.
    pub fn check_vault_file(&self, vault_id: &str, file: &VaultFile) -> Result<()> {
        if file.account_id != self.account().id {
            return Err(Error::FolderOtherAccount);
        }
        if file.vault_id != vault_id {
            return Err(Error::invalid("this folder holds another vault"));
        }
        let key = self.folder_key(file)?;
        if self.vault_key(vault_id) != Some(&key) {
            return Err(Error::invalid("this folder holds another copy of the vault, with another key"));
        }
        Ok(())
    }

    /// Read the `moved.json` that is next to a `vault.json`.
    pub fn read_moved_with(&self, file: &VaultFile, moved: &MovedFile) -> Result<MovedTo> {
        let key = self.folder_key(file)?;
        if moved.vault_id != file.vault_id {
            return Err(Error::Decryption);
        }
        decrypt_json(&key, &moved.moved, &aad::vault_moved(&file.vault_id))
    }

    /// Whether this account can move the vault: only its owner can, a shared
    /// vault stays on the server, and a placeholder is moved from where the
    /// vault is.
    pub fn can_move(&self, vault_id: &str) -> Result<()> {
        let rec = self.profile().vault(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        if rec.role != Role::Owner || rec.owner_id != self.account().id {
            return Err(Error::PermissionDenied("only the owner can move a vault".into()));
        }
        if rec.location.is_account() && rec.member_count > 1 {
            return Err(Error::VaultShared);
        }
        if rec.location.is_account() && self.vault_meta(vault_id).is_some_and(|m| m.moved.is_some()) {
            return Err(Error::invalid("this vault is kept elsewhere; open it there to move it"));
        }
        if rec.sync_state == SyncState::PendingDelete {
            return Err(Error::not_found(format!("vault {vault_id}")));
        }
        Ok(())
    }

    /// The vault key in a `vault.json`. Only a key wrapped with our own
    /// account key is taken: anyone can seal a key to our public key.
    fn folder_key(&self, file: &VaultFile) -> Result<SymmetricKey> {
        if file.account_id != self.account().id {
            return Err(Error::FolderOtherAccount);
        }
        if !matches!(file.wrapped_key, WrappedKey::Symmetric { .. }) {
            return Err(Error::invalid("the key in this vault folder is not wrapped with the account key"));
        }
        file.wrapped_key.unwrap(self.keyset(), &aad::vault_key(&file.vault_id))
    }

    /// All files of a vault for a new folder: `vault.json`, the metadata and
    /// every item, written as this device. Paths are relative to the vault
    /// folder.
    pub fn folder_export(&mut self, vault_id: &str) -> Result<Vec<(String, String)>> {
        let tag = self.device_tag();
        let rec = self.profile().vault(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?.clone();
        let key = self.vault_key(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?.clone();
        let mut files = vec![(
            VAULT_FILE.to_string(),
            to_json(&VaultFile {
                format: FORMAT.into(),
                version: VERSION,
                vault_id: vault_id.to_string(),
                account_id: self.account().id.clone(),
                created_at: rec.created_at,
                wrapped_key: WrappedKey::wrap_symmetric(self.account_key(), &key, &aad::vault_key(vault_id)),
            }),
        )];
        let mut meta = self.vault_meta(vault_id).cloned().unwrap_or_default();
        meta.moved = None;
        files.push((meta_path(&tag), self.meta_file_json(vault_id, &key, meta, now())?));
        let mut items: Vec<(&str, &Item)> = self.all_items().filter(|(v, _)| *v == vault_id).collect();
        items.sort_by(|a, b| a.1.id.cmp(&b.1.id));
        for (_, item) in items {
            if !valid_id(&item.id) {
                return Err(Error::invalid(format!("the item '{}' has an id that cannot be a file name", item.title)));
            }
            let data = self.encrypt_item(vault_id, item)?;
            let file = ItemFile { id: item.id.clone(), vault_id: vault_id.to_string(), data: Some(data), tomb: None };
            files.push((item_path(&item.id, &tag), to_json(&file)));
        }
        Ok(files)
    }

    fn meta_file_json(&self, vault_id: &str, key: &SymmetricKey, meta: VaultMeta, updated_at: i64) -> Result<String> {
        let enc = encrypt_json(key, &MetaVersion { meta, updated_at }, &aad::vault_meta_version(vault_id))?;
        Ok(to_json(&MetaFile { vault_id: vault_id.to_string(), meta: enc }))
    }

    /// The contents of a `moved.json` saying where the vault went.
    pub fn moved_file(&self, vault_id: &str, moved: &MovedTo) -> Result<String> {
        let key = self.vault_key(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        let enc = encrypt_json(key, moved, &aad::vault_moved(vault_id))?;
        Ok(to_json(&MovedFile { vault_id: vault_id.to_string(), moved: enc }))
    }

    /// The vault's metadata for the server placeholder of a vault that moves
    /// to a storage folder (`moved` set), or for its return (`None`).
    pub fn placeholder_meta(&self, vault_id: &str, moved: Option<MovedTo>) -> Result<EncString> {
        let key = self.vault_key(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        let mut meta = self.vault_meta(vault_id).cloned().unwrap_or_default();
        meta.moved = moved;
        encrypt_json(key, &meta, &aad::vault_meta(vault_id))
    }

    /// Read a `moved.json` of our vault.
    pub fn read_moved_file(&self, vault_id: &str, file: &MovedFile) -> Result<MovedTo> {
        let key = self.vault_key(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        if file.vault_id != vault_id {
            return Err(Error::Decryption);
        }
        decrypt_json(key, &file.moved, &aad::vault_moved(vault_id))
    }

    /// Merge what a vault's folder holds into the session, and work out what
    /// this device has to write there. Nothing is ever taken as deleted
    /// without a tombstone: a missing or unreadable file only means it has
    /// not arrived yet.
    pub fn apply_folder(&mut self, vault_id: &str, snapshot: &Snapshot) -> Result<FolderPlan> {
        let rec = self.profile().vault(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        if !rec.location.is_folder() {
            return Err(Error::invalid("this vault is not in a storage folder"));
        }
        let tag = self.device_tag();
        let key = self.vault_key(vault_id).ok_or(Error::Decryption)?.clone();
        let ts = now();
        let mut plan = FolderPlan { vault_id: vault_id.to_string(), ..Default::default() };
        plan.report.unreadable = snapshot.unreadable;

        if let Some(file) = &snapshot.moved {
            match self.read_moved_file(vault_id, file) {
                Ok(moved) => plan.report.moved = Some(moved),
                Err(_) => plan.report.unreadable += 1,
            }
        }
        self.merge_folder_meta(vault_id, &key, &tag, &snapshot.metas, ts, &mut plan)?;

        // Every readable version of every item.
        let mut by_id: BTreeMap<String, Vec<Version>> = BTreeMap::new();
        for (name, file) in &snapshot.items {
            let Some(fname) = parse_file_name(name) else { continue };
            if !valid_id(&fname.stem) || file.id != fname.stem || file.vault_id != vault_id {
                plan.report.unreadable += 1;
                continue;
            }
            let item = match &file.data {
                Some(d) => match self.decrypt_item(vault_id, &file.id, d) {
                    Ok(item) => Some(item),
                    Err(_) => {
                        plan.report.unreadable += 1;
                        continue;
                    }
                },
                None => None,
            };
            let deleted_at = match &file.tomb {
                Some(t) => match decrypt_json::<Tombstone>(&key, t, &aad::item_tombstone(vault_id, &file.id)) {
                    Ok(t) => Some(t.deleted_at),
                    Err(_) => {
                        plan.report.unreadable += 1;
                        continue;
                    }
                },
                None => None,
            };
            if item.is_none() && deleted_at.is_none() {
                plan.report.unreadable += 1;
                continue;
            }
            by_id.entry(file.id.clone()).or_default().push(Version {
                name: name.clone(),
                tag: fname.tag,
                exact: fname.exact,
                item,
                data: file.data.clone(),
                deleted_at,
            });
        }

        let mut ids: BTreeSet<String> = by_id.keys().cloned().collect();
        ids.extend(self.profile().items.iter().filter(|i| i.vault_id == vault_id).map(|i| i.id.clone()));
        for id in ids {
            let versions = by_id.remove(&id).unwrap_or_default();
            self.merge_folder_item(vault_id, &key, &tag, &id, versions, ts, &mut plan)?;
        }
        self.reload()?;
        Ok(plan)
    }

    #[allow(clippy::too_many_arguments)]
    fn merge_folder_item(
        &mut self,
        vault_id: &str,
        key: &SymmetricKey,
        tag: &str,
        id: &str,
        versions: Vec<Version>,
        ts: i64,
        plan: &mut FolderPlan,
    ) -> Result<()> {
        let rec = self.profile().item(id).cloned();
        if rec.as_ref().is_some_and(|r| r.vault_id != vault_id) {
            return Ok(()); // Another vault's item with the same id.
        }
        let local_item = match rec.as_ref().and_then(|r| r.data.as_ref()) {
            Some(_) => match self.item(id) {
                Some(item) => Some(item.clone()),
                None => return Ok(()), // Unreadable here: leave it alone.
            },
            None => None,
        };
        let local_deleted = rec.as_ref().is_some_and(|r| r.data.is_none() && r.dirty);
        let local_deleted_at = rec.as_ref().and_then(|r| r.deleted_at).unwrap_or(ts);

        // The candidates: every version in the folder, and ours.
        let mut candidates: Vec<(&Item, &str)> =
            versions.iter().filter_map(|v| v.item.as_ref().map(|i| (i, v.tag.as_str()))).collect();
        if let Some(item) = &local_item {
            candidates.push((item, tag));
        }
        let newest_delete =
            versions.iter().filter_map(|v| v.deleted_at).chain(local_deleted.then_some(local_deleted_at)).max();
        let newest = candidates.iter().copied().max_by(|a, b| a.0.updated_at.cmp(&b.0.updated_at).then(a.1.cmp(b.1)));
        // An edit after the last deletion wins; the passwords of the other
        // versions are kept in its history.
        let result: Option<Item> = match newest {
            Some((winner, _)) if newest_delete.is_none_or(|d| winner.updated_at > d) => {
                let mut merged = winner.clone();
                for (other, _) in &candidates {
                    if !std::ptr::eq(*other, winner) {
                        merge_password_history(&mut merged, other);
                    }
                }
                Some(merged)
            }
            _ => None,
        };

        // Copies of our own files that a storage app made: their content is
        // merged above, the files go.
        let (copies, kept): (Vec<&Version>, Vec<&Version>) = versions.iter().partition(|v| v.tag == tag && !v.exact);
        for copy in &copies {
            plan.remove.push(format!("{ITEMS_DIR}/{}", copy.name));
        }
        let own = kept.iter().find(|v| v.tag == tag && v.exact);

        match result {
            Some(item) => {
                let data = if local_item.as_ref() == Some(&item) {
                    rec.as_ref().and_then(|r| r.data.clone()).expect("local item has data")
                } else {
                    let data = match versions.iter().find(|v| v.item.as_ref() == Some(&item)) {
                        Some(v) => v.data.clone().expect("a version with an item has data"),
                        None => self.encrypt_item(vault_id, &item)?,
                    };
                    plan.report.downloaded += 1;
                    data
                };
                // Write our own version unless the folder already has it.
                let present = kept.iter().any(|v| v.item.as_ref() == Some(&item) && v.deleted_at.is_none());
                let p = self.profile_mut();
                match p.item_mut(id) {
                    Some(r) => {
                        r.data = Some(data.clone());
                        r.dirty = !present;
                    }
                    None => p.items.push(ItemRecord {
                        id: id.to_string(),
                        vault_id: vault_id.to_string(),
                        data: Some(data.clone()),
                        revision: 0,
                        dirty: !present,
                        deleted_at: None,
                    }),
                }
                if !present {
                    let file = ItemFile {
                        id: id.to_string(),
                        vault_id: vault_id.to_string(),
                        data: Some(data.clone()),
                        tomb: None,
                    };
                    plan.write.push((item_path(id, tag), to_json(&file)));
                    plan.written_items.push((id.to_string(), Some(data)));
                    plan.report.written += 1;
                }
            }
            None => {
                let Some(deleted_at) = newest_delete else { return Ok(()) };
                if rec.is_some() && !local_deleted {
                    self.profile_mut().items.retain(|i| i.id != id);
                    plan.report.deleted += 1;
                }
                // Our tombstone, when the deletion is ours, when our own file
                // still holds the item (so tombstones can be cleared up), or
                // when the deletion was only in a copy that goes.
                let tomb_present = kept.iter().any(|v| v.deleted_at.is_some_and(|d| d >= deleted_at));
                let own_live = own.is_some_and(|v| v.item.is_some());
                if local_deleted || own_live || !tomb_present {
                    let tomb = encrypt_json(key, &Tombstone { deleted_at }, &aad::item_tombstone(vault_id, id))?;
                    let file =
                        ItemFile { id: id.to_string(), vault_id: vault_id.to_string(), data: None, tomb: Some(tomb) };
                    plan.write.push((item_path(id, tag), to_json(&file)));
                    plan.written_items.push((id.to_string(), None));
                    plan.report.written += 1;
                } else if own.is_some()
                    && kept.iter().all(|v| v.item.is_none())
                    && deleted_at < ts - TOMBSTONE_DAYS * 86_400
                {
                    // Every device has the deletion, long enough ago.
                    plan.remove.push(item_path(id, tag));
                }
            }
        }
        Ok(())
    }

    fn merge_folder_meta(
        &mut self,
        vault_id: &str,
        key: &SymmetricKey,
        tag: &str,
        metas: &[(String, MetaFile)],
        ts: i64,
        plan: &mut FolderPlan,
    ) -> Result<()> {
        let mut versions: Vec<(MetaVersion, String, bool)> = Vec::new();
        for (name, file) in metas {
            let Some(fname) = parse_file_name(name) else { continue };
            if fname.stem != "meta" || file.vault_id != vault_id {
                plan.report.unreadable += 1;
                continue;
            }
            match decrypt_json::<MetaVersion>(key, &file.meta, &aad::vault_meta_version(vault_id)) {
                Ok(mut v) => {
                    v.meta.moved = None;
                    if fname.tag == tag && !fname.exact {
                        plan.remove.push(name.clone());
                    }
                    versions.push((v, fname.tag, fname.exact));
                }
                Err(_) => plan.report.unreadable += 1,
            }
        }
        let rec = self.profile().vault(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        let changed_here = rec.sync_state == SyncState::PendingUpdate;
        let rec_meta = rec.meta.clone();
        let mut local = self.vault_meta(vault_id).cloned().unwrap_or_default();
        local.moved = None;
        let newest = versions.iter().max_by(|a, b| a.0.updated_at.cmp(&b.0.updated_at).then(a.1.cmp(&b.1)));
        let write = if changed_here {
            let updated_at = newest.map_or(ts, |n| ts.max(n.0.updated_at + 1));
            Some((local, updated_at))
        } else if let Some((newest, ntag, exact)) = newest {
            if newest.meta != local {
                self.set_vault_meta(vault_id, newest.meta.clone())?;
                plan.report.meta_changed = true;
            }
            // Only in a copy of our own file: keep it in ours.
            (ntag == tag && !exact && !versions.iter().any(|v| v.1 == tag && v.2 && v.0 == *newest))
                .then(|| (newest.meta.clone(), newest.updated_at))
        } else {
            Some((local, ts))
        };
        if let Some((meta, updated_at)) = write {
            plan.write.push((meta_path(tag), self.meta_file_json(vault_id, key, meta, updated_at)?));
            plan.written_meta = changed_here.then_some(rec_meta);
            plan.report.written += 1;
        }
        Ok(())
    }

    /// The files of `plan` are in the folder now.
    pub fn folder_written(&mut self, plan: &FolderPlan) {
        let p = self.profile_mut();
        for (id, data) in &plan.written_items {
            match data {
                Some(d) => {
                    if let Some(r) = p.item_mut(id).filter(|r| r.data.as_ref() == Some(d)) {
                        r.dirty = false;
                    }
                }
                None => p.items.retain(|i| &i.id != id || i.data.is_some()),
            }
        }
        if let Some(meta) = &plan.written_meta {
            if let Some(v) = p.vault_mut(&plan.vault_id) {
                if &v.meta == meta && v.sync_state == SyncState::PendingUpdate {
                    v.sync_state = SyncState::Synced;
                }
            }
        }
    }

    /// Start using the vault in a storage folder (`location`): a vault this
    /// device does not have yet, or one it knows as a server placeholder.
    /// Call [`Session::apply_folder`] next to read its items.
    pub fn attach_folder(&mut self, file: &VaultFile, snapshot: &Snapshot, location: VaultLocation) -> Result<String> {
        if !location.is_folder() {
            return Err(Error::invalid("not a storage folder"));
        }
        let key = self.folder_key(file)?;
        let vault_id = file.vault_id.clone();
        if let Some(rec) = self.profile().vault(&vault_id).cloned() {
            if self.vault_key(&vault_id) != Some(&key) {
                return Err(Error::invalid("this folder holds another copy of the vault, with another key"));
            }
            let placeholder = self.vault_meta(&vault_id).is_some_and(|m| m.moved.is_some());
            if rec.location.is_account() && !placeholder {
                return Err(Error::invalid(
                    "this vault is still on the server here; move it to the folder instead of adding the folder",
                ));
            }
            if rec.location.is_account() {
                let on_server = rec.sync_state == SyncState::Synced && self.profile().server.is_some();
                let leftovers: Vec<Leftover> = self
                    .profile()
                    .items
                    .iter()
                    .filter(|i| i.vault_id == vault_id && i.data.is_some() && i.revision > 0)
                    .map(|i| Leftover { id: i.id.clone(), revision: i.revision })
                    .collect();
                let p = self.profile_mut();
                p.items.retain(|i| i.vault_id != vault_id || i.data.is_some());
                for i in p.items.iter_mut().filter(|i| i.vault_id == vault_id) {
                    i.revision = 0;
                }
                let v = p.vault_mut(&vault_id).expect("exists");
                v.leftovers = leftovers;
                v.on_server = on_server;
                v.sync_state = SyncState::Synced;
            }
            if let Some(mut meta) = self.vault_meta(&vault_id).cloned() {
                if meta.moved.take().is_some() {
                    self.set_vault_meta(&vault_id, meta)?;
                }
            }
            self.profile_mut().vault_mut(&vault_id).expect("exists").location = location;
        } else {
            // The newest name in the folder (else a plain one).
            let meta = snapshot
                .metas
                .iter()
                .filter(|(_, f)| f.vault_id == vault_id)
                .filter_map(|(_, f)| {
                    decrypt_json::<MetaVersion>(&key, &f.meta, &aad::vault_meta_version(&vault_id)).ok()
                })
                .max_by_key(|v| v.updated_at)
                .map(|v| VaultMeta { moved: None, ..v.meta })
                .unwrap_or_else(|| VaultMeta { name: "Vault".into(), ..Default::default() });
            let record = VaultRecord {
                id: vault_id.clone(),
                owner_id: self.account().id.clone(),
                role: Role::Owner,
                wrapped_key: WrappedKey::wrap_symmetric(self.account_key(), &key, &aad::vault_key(&vault_id)),
                meta: encrypt_json(&key, &meta, &aad::vault_meta(&vault_id))?,
                revision: 0,
                sync_state: SyncState::Synced,
                member_count: 1,
                created_at: file.created_at,
                key_rev: 0,
                retired_keys: Vec::new(),
                location,
                leftovers: Vec::new(),
                on_server: false,
            };
            self.profile_mut().vaults.push(record);
        }
        self.reload()?;
        Ok(vault_id)
    }

    /// Change where a vault is kept, after its contents were copied there
    /// (see [`Session::folder_export`]). For a vault leaving the server, the
    /// items still on it are remembered for removal (the server keeps an
    /// empty placeholder); for a vault going to the server, everything is
    /// marked for upload.
    ///
    /// Only the owner can move a vault, and shared vaults stay on the server.
    pub fn relocate_vault(&mut self, vault_id: &str, to: VaultLocation) -> Result<()> {
        self.can_move(vault_id)?;
        let rec = self.profile().vault(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?.clone();
        if rec.location == to {
            return Ok(());
        }
        let linked = self.profile().server.is_some();
        let from_server = rec.location.is_account() && linked;
        if from_server && rec.sync_state != SyncState::Synced {
            return Err(Error::invalid("sync the vault before moving it"));
        }
        let p = self.profile_mut();
        match &to {
            VaultLocation::Account => {
                let leftovers = rec.leftovers.clone();
                p.items
                    .retain(|i| i.vault_id != vault_id || i.data.is_some() || leftovers.iter().any(|l| l.id == i.id));
                for i in p.items.iter_mut().filter(|i| i.vault_id == vault_id) {
                    i.dirty = true;
                    i.revision = leftovers.iter().find(|l| l.id == i.id).map_or(0, |l| l.revision);
                }
                let v = p.vault_mut(vault_id).expect("exists");
                v.sync_state = SyncState::PendingCreate;
                v.revision = 0;
                v.leftovers.clear();
                v.on_server = false;
            }
            VaultLocation::Device | VaultLocation::Folder { .. } => {
                let leftovers: Vec<Leftover> = if from_server {
                    p.items
                        .iter()
                        .filter(|i| i.vault_id == vault_id && i.data.is_some() && i.revision > 0)
                        .map(|i| Leftover { id: i.id.clone(), revision: i.revision })
                        .collect()
                } else {
                    rec.leftovers.clone()
                };
                p.items.retain(|i| i.vault_id != vault_id || i.data.is_some());
                for i in p.items.iter_mut().filter(|i| i.vault_id == vault_id) {
                    i.dirty = false;
                    i.revision = 0;
                }
                let v = p.vault_mut(vault_id).expect("exists");
                v.sync_state = SyncState::Synced;
                if to.is_folder() {
                    if from_server {
                        v.on_server = true;
                    }
                    v.leftovers = leftovers;
                } else {
                    // Going to one device: the caller removes it from the server.
                    v.on_server = false;
                    v.leftovers.clear();
                    v.revision = 0;
                }
            }
        }
        self.profile_mut().vault_mut(vault_id).expect("exists").location = to;
        if let Some(mut meta) = self.vault_meta(vault_id).cloned() {
            if meta.moved.take().is_some() {
                self.set_vault_meta(vault_id, meta)?;
            }
        }
        self.reload()
    }

    /// The server no longer has (a placeholder of) a vault kept elsewhere.
    pub fn mark_off_server(&mut self, vault_id: &str) {
        if let Some(v) = self.profile_mut().vault_mut(vault_id).filter(|v| !v.location.is_account()) {
            v.on_server = false;
            v.leftovers.clear();
            v.revision = 0;
        }
    }

    /// Point a folder vault at another folder holding the same vault (it
    /// moved there, or the folder is somewhere else on this device).
    pub fn set_vault_folder(&mut self, vault_id: &str, location: VaultLocation) -> Result<()> {
        let rec =
            self.profile_mut().vault_mut(vault_id).ok_or_else(|| Error::not_found(format!("vault {vault_id}")))?;
        if !rec.location.is_folder() || !location.is_folder() {
            return Err(Error::invalid("not a storage folder"));
        }
        rec.location = location;
        Ok(())
    }

    /// Forget a vault that moved away from its storage folder to one device
    /// (another one) or was deleted.
    pub fn forget_folder_vault(&mut self, vault_id: &str) {
        let p = self.profile_mut();
        p.vaults.retain(|v| v.id != vault_id || !v.location.is_folder());
        if p.vault(vault_id).is_none() {
            self.forget_vault(vault_id);
        }
    }
}

/// A platform 2Secret runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    MacOs,
    Windows,
    Linux,
    /// FreeBSD, OpenBSD, NetBSD.
    Bsd,
    /// iPhone and iPad.
    Ios,
    Android,
    /// The web vault and the browser extension.
    Web,
}

impl Platform {
    pub const ALL: [Platform; 7] = [
        Platform::MacOs,
        Platform::Windows,
        Platform::Linux,
        Platform::Bsd,
        Platform::Ios,
        Platform::Android,
        Platform::Web,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Platform::MacOs => "macOS",
            Platform::Windows => "Windows",
            Platform::Linux => "Linux",
            Platform::Bsd => "BSD",
            Platform::Ios => "iPhone and iPad",
            Platform::Android => "Android",
            Platform::Web => "the web vault and the browser extension",
        }
    }

    /// The platform this code was built for.
    pub fn current() -> Platform {
        if cfg!(target_arch = "wasm32") {
            Platform::Web
        } else if cfg!(target_os = "ios") {
            Platform::Ios
        } else if cfg!(target_os = "android") {
            Platform::Android
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")) {
            Platform::Bsd
        } else {
            Platform::Linux
        }
    }

    /// Whether 2Secret on this platform can keep vaults in a storage folder
    /// yet (the desktop apps and the command line).
    pub fn has_folder_vaults(&self) -> bool {
        matches!(self, Platform::MacOs | Platform::Windows | Platform::Linux | Platform::Bsd)
    }
}

/// Whether a vault in a storage folder can be used on a platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Yes,
    /// The service has an app there, but 2Secret cannot use folders there
    /// yet (a later version).
    Later,
    /// The service has no app for that platform.
    No,
}

impl FolderService {
    /// Where a vault in this service's folder can be used: the one source for
    /// the warnings in the apps, the command line and the documentation.
    pub fn availability(&self) -> [(Platform, Availability); 7] {
        use Availability::*;
        let row: [Availability; 7] = match self {
            // macOS, Windows (iCloud for Windows), Linux, BSD, iOS, Android, web
            FolderService::ICloudDrive => [Yes, Yes, No, No, Later, No, No],
            FolderService::Dropbox => [Yes, Yes, Yes, No, Later, Later, No],
            FolderService::GoogleDrive => [Yes, Yes, No, No, Later, Later, No],
            FolderService::OneDrive => [Yes, Yes, No, No, Later, Later, No],
            FolderService::Other => [Yes, Yes, Yes, Yes, No, Later, No],
        };
        let mut out = [(Platform::MacOs, Yes); 7];
        for (i, p) in Platform::ALL.iter().enumerate() {
            out[i] = (*p, row[i]);
        }
        out
    }

    /// The platforms where the service has no app, so a vault in its folder
    /// can never show up there.
    pub fn missing_on(&self) -> Vec<Platform> {
        self.availability().iter().filter(|(_, a)| *a == Availability::No).map(|(p, _)| *p).collect()
    }

    pub fn available_on(&self, platform: Platform) -> Availability {
        self.availability().iter().find(|(p, _)| *p == platform).map_or(Availability::No, |(_, a)| *a)
    }
}

/// Where a move puts a vault, for other devices (a server placeholder or a
/// `moved.json`).
pub fn move_target(service: FolderService, folder: &str) -> MoveTarget {
    MoveTarget::Folder { service, folder: folder.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::tests::new_session;

    /// A storage folder shared by "devices" (sessions of the same account).
    #[derive(Default, Clone)]
    struct Folder {
        files: BTreeMap<String, String>,
    }

    impl Folder {
        fn snapshot(&self) -> Snapshot {
            let mut snap = Snapshot::default();
            for (path, json) in &self.files {
                if let Some(name) = path.strip_prefix("items/") {
                    match serde_json::from_str(json) {
                        Ok(f) => snap.items.push((name.to_string(), f)),
                        Err(_) => snap.unreadable += 1,
                    }
                } else if path.starts_with("meta~") {
                    match serde_json::from_str(json) {
                        Ok(f) => snap.metas.push((path.clone(), f)),
                        Err(_) => snap.unreadable += 1,
                    }
                } else if path == MOVED_FILE {
                    snap.moved = serde_json::from_str(json).ok();
                }
            }
            snap
        }

        fn sync(&mut self, s: &mut Session, vault: &str) -> FolderReport {
            let plan = s.apply_folder(vault, &self.snapshot()).unwrap();
            for (path, json) in &plan.write {
                self.files.insert(path.clone(), json.clone());
            }
            for path in &plan.remove {
                self.files.remove(path);
            }
            s.folder_written(&plan);
            plan.report
        }

        fn vault_file(&self) -> VaultFile {
            VaultFile::parse(&self.files[VAULT_FILE]).unwrap()
        }
    }

    fn location() -> VaultLocation {
        VaultLocation::Folder { path: "/tmp/x".into(), service: FolderService::Dropbox }
    }

    /// Device `a` with a folder vault, and device `b` of the same account
    /// with it attached.
    fn two_devices() -> (Session, Session, String, Folder) {
        let (mut a, _) = new_session();
        let mut b = a.try_clone().unwrap();
        b.profile_mut().device_tag = None;
        let vault = a.create_vault_at("Work", "", location()).unwrap();
        let mut folder = Folder::default();
        for (path, json) in a.folder_export(&vault).unwrap() {
            folder.files.insert(path, json);
        }
        folder.sync(&mut a, &vault);
        b.profile_mut().vaults.retain(|v| v.id != vault);
        b.reload().unwrap();
        b.attach_folder(&folder.vault_file(), &folder.snapshot(), location()).unwrap();
        folder.sync(&mut b, &vault);
        assert_ne!(a.device_tag(), b.device_tag());
        (a, b, vault, folder)
    }

    #[test]
    fn file_names_and_the_copies_storage_apps_make() {
        let tag = "abcdefgh23";
        let id = "0f8e2c1a-1111-4222-8333-444455556666";
        let exact = parse_file_name(&format!("{id}~{tag}.json")).unwrap();
        assert_eq!((exact.stem.as_str(), exact.tag.as_str(), exact.exact), (id, tag, true));
        for copy in [
            format!("{id}~{tag} 2.json"),
            format!("{id}~{tag} (1).json"),
            format!("{id}~{tag} (Joost's conflicted copy 2026-11-06).json"),
            format!("{id}~{tag}-DESKTOP-4F2.json"),
            format!("{id}~{tag}.sync-conflict-20261106-120000-ABCDEFG.json"),
        ] {
            let parsed = parse_file_name(&copy).unwrap();
            assert_eq!((parsed.stem.as_str(), parsed.tag.as_str(), parsed.exact), (id, tag, false), "{copy}");
        }
        assert!(parse_file_name(&format!(".~tmp-{id}~{tag}.json")).is_none());
        assert!(parse_file_name(&format!(".{id}~{tag}.json.icloud")).is_none());
        assert!(parse_file_name(&format!("{id}~{tag}x.json")).is_none());
        assert!(parse_file_name(&format!("{id}~ABCDEFGH23.json")).is_none());
        assert!(parse_file_name("notes.txt").is_none());
        assert_eq!(parse_file_name("meta~abcdefgh23.json").unwrap().stem, "meta");
        assert!(valid_id(id) && !valid_id("../x") && !valid_id("a/b") && !valid_id(""));
        assert_eq!(vault_dir_name("Work / Private: 2026", "1a2b3c4d-5e6f"), "Work - Private- 2026-1a2b3c4d");
        assert_eq!(vault_dir_name("…", "1a2b3c4d"), "Vault-1a2b3c4d");
    }

    #[test]
    fn two_devices_share_a_folder() {
        let (mut a, mut b, vault, mut folder) = two_devices();
        assert_eq!(b.vault(&vault).unwrap().name, "Work");

        // A new item on one device arrives on the other.
        let id = a.add_item(&vault, Item::login("Mail", "me", "pw-1", None)).unwrap();
        let r = folder.sync(&mut a, &vault);
        assert_eq!(r.written, 1);
        assert!(!a.profile().has_pending_folder_changes());
        let r = folder.sync(&mut b, &vault);
        assert_eq!(r.downloaded, 1);
        assert_eq!(r.written, 0, "b only reads what a wrote");
        assert_eq!(b.item(&id).unwrap().password(), Some("pw-1"));

        // Edited on both: the newest edit wins and keeps the other password.
        let mut ia = a.item(&id).unwrap().clone();
        ia.set_value("password", "pw-a");
        a.update_item(ia).unwrap();
        let mut ib = b.item(&id).unwrap().clone();
        ib.set_value("password", "pw-b");
        b.update_item(ib).unwrap();
        // b's edit is later.
        {
            let mut late = b.item(&id).unwrap().clone();
            late.updated_at += 10;
            b.update_item(late).unwrap();
        }
        folder.sync(&mut a, &vault);
        folder.sync(&mut b, &vault);
        folder.sync(&mut a, &vault);
        let r = folder.sync(&mut b, &vault);
        assert_eq!(r.written, 0, "the devices agree");
        let (xa, xb) = (a.item(&id).unwrap(), b.item(&id).unwrap());
        assert_eq!(xa, xb);
        assert_eq!(xa.password(), Some("pw-b"));
        assert!(xa.password_history.iter().any(|h| h.value == "pw-a"));

        // Renamed on one device.
        a.update_vault(&vault, "Work stuff", "", None).unwrap();
        folder.sync(&mut a, &vault);
        assert!(folder.sync(&mut b, &vault).meta_changed);
        assert_eq!(b.vault(&vault).unwrap().name, "Work stuff");

        // Deleted on one device: gone on the other, with a tombstone.
        b.delete_item(&id).unwrap();
        folder.sync(&mut b, &vault);
        assert!(b.profile().item(&id).is_none());
        let r = folder.sync(&mut a, &vault);
        assert_eq!(r.deleted, 1);
        assert!(a.item(&id).is_none());
        // Its own file got a tombstone too, so the item stays deleted.
        folder.sync(&mut a, &vault);
        assert!(a.item(&id).is_none() && b.item(&id).is_none());
    }

    #[test]
    fn missing_or_damaged_files_are_never_deletions() {
        let (mut a, mut b, vault, mut folder) = two_devices();
        let id = a.add_item(&vault, Item::login("Mail", "me", "pw", None)).unwrap();
        folder.sync(&mut a, &vault);
        folder.sync(&mut b, &vault);
        // The file goes missing (not downloaded yet), then arrives damaged.
        let path = item_path(&id, &a.device_tag());
        let saved = folder.files.remove(&path).unwrap();
        folder.sync(&mut b, &vault);
        assert!(b.item(&id).is_some(), "a missing file is not a deletion");
        folder.files.insert(path.clone(), saved[..saved.len() / 2].to_string());
        folder.sync(&mut b, &vault);
        assert!(b.item(&id).is_some());
        // b writes what only it still has.
        assert!(folder.files.contains_key(&item_path(&id, &b.device_tag())));

        // A file tampered with, or one of another vault, is skipped.
        let mut file: ItemFile = serde_json::from_str(&folder.files[&item_path(&id, &b.device_tag())]).unwrap();
        file.vault_id = "other".into();
        folder.files.insert(item_path(&id, "zzzzzzzzzz"), serde_json::to_string(&file).unwrap());
        let r = folder.sync(&mut a, &vault);
        assert!(r.unreadable >= 1);
        assert!(a.item(&id).is_some());
    }

    #[test]
    fn an_edit_after_a_deletion_wins() {
        let (mut a, mut b, vault, mut folder) = two_devices();
        let id = a.add_item(&vault, Item::login("Mail", "me", "pw", None)).unwrap();
        folder.sync(&mut a, &vault);
        folder.sync(&mut b, &vault);
        a.delete_item(&id).unwrap();
        folder.sync(&mut a, &vault);
        // b edits later, before seeing the deletion.
        let mut item = b.item(&id).unwrap().clone();
        item.title = "Mail (kept)".into();
        item.updated_at = now() + 60;
        b.profile_mut().item_mut(&id).unwrap().data = Some(b.encrypt_item(&vault, &item).unwrap());
        b.reload().unwrap();
        folder.sync(&mut b, &vault);
        folder.sync(&mut a, &vault);
        assert_eq!(a.item(&id).unwrap().title, "Mail (kept)");
    }

    #[test]
    fn copies_of_own_files_are_merged_and_removed() {
        let (mut a, _b, vault, mut folder) = two_devices();
        let id = a.add_item(&vault, Item::login("Mail", "me", "pw", None)).unwrap();
        folder.sync(&mut a, &vault);
        let tag = a.device_tag();
        let own = item_path(&id, &tag);
        let copy = format!("items/{id}~{tag} 2.json");
        // The copy holds a newer version.
        let mut item = a.item(&id).unwrap().clone();
        item.title = "Newer".into();
        item.updated_at += 100;
        let file = ItemFile {
            id: id.clone(),
            vault_id: vault.clone(),
            data: Some(a.encrypt_item(&vault, &item).unwrap()),
            tomb: None,
        };
        folder.files.insert(copy.clone(), serde_json::to_string(&file).unwrap());
        folder.sync(&mut a, &vault);
        assert!(!folder.files.contains_key(&copy));
        assert_eq!(a.item(&id).unwrap().title, "Newer");
        let kept: ItemFile = serde_json::from_str(&folder.files[&own]).unwrap();
        assert_eq!(a.decrypt_item(&vault, &id, kept.data.as_ref().unwrap()).unwrap().title, "Newer");
    }

    #[test]
    fn old_tombstones_are_cleared_up() {
        let (mut a, mut b, vault, mut folder) = two_devices();
        let id = a.add_item(&vault, Item::login("Mail", "me", "pw", None)).unwrap();
        folder.sync(&mut a, &vault);
        folder.sync(&mut b, &vault);
        a.delete_item(&id).unwrap();
        folder.sync(&mut a, &vault);
        folder.sync(&mut b, &vault);
        // Make the tombstone old.
        let key = a.vault_key(&vault).unwrap().clone();
        let old = now() - (TOMBSTONE_DAYS + 1) * 86_400;
        for tag in [a.device_tag(), b.device_tag()] {
            let tomb = encrypt_json(&key, &Tombstone { deleted_at: old }, &aad::item_tombstone(&vault, &id)).unwrap();
            let file = ItemFile { id: id.clone(), vault_id: vault.clone(), data: None, tomb: Some(tomb) };
            folder.files.insert(item_path(&id, &tag), serde_json::to_string(&file).unwrap());
        }
        folder.sync(&mut a, &vault);
        folder.sync(&mut b, &vault);
        assert!(!folder.files.keys().any(|k| k.contains(&id)));
        assert!(a.item(&id).is_none() && b.item(&id).is_none());
    }

    #[test]
    fn a_folder_of_another_account_or_with_a_sealed_key_is_refused() {
        let (a, _b, vault, folder) = two_devices();
        let (mut other, _) = new_session();
        let err = other.attach_folder(&folder.vault_file(), &folder.snapshot(), location()).unwrap_err();
        assert!(matches!(err, Error::FolderOtherAccount));
        // Someone who knows our public key seals their own key to it.
        let mut forged = folder.vault_file();
        let key = SymmetricKey::generate();
        forged.vault_id = crate::util::new_id();
        forged.wrapped_key = WrappedKey::wrap_for(&a.public_keys(), &key, &aad::vault_key(&forged.vault_id)).unwrap();
        let mut a2 = a.try_clone().unwrap();
        assert!(a2.attach_folder(&forged, &Snapshot::default(), location()).is_err());
        assert!(a.check_vault_file(&vault, &folder.vault_file()).is_ok());
    }

    #[test]
    fn availability_warnings() {
        assert_eq!(
            FolderService::ICloudDrive.missing_on(),
            vec![Platform::Linux, Platform::Bsd, Platform::Android, Platform::Web]
        );
        assert_eq!(FolderService::Dropbox.available_on(Platform::Linux), Availability::Yes);
        assert_eq!(FolderService::GoogleDrive.available_on(Platform::Linux), Availability::No);
        assert_eq!(FolderService::Other.available_on(Platform::Ios), Availability::No);
        assert!(Platform::current().has_folder_vaults() || cfg!(target_arch = "wasm32"));
        for s in FolderService::ALL {
            assert_eq!(FolderService::parse(s.id()), Some(s));
        }
    }
}
