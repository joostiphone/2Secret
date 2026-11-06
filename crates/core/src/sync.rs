//! Client side of the sync protocol: building requests from local changes and
//! merging server responses, including conflict resolution.
//!
//! The protocol is revision based. Every vault on the server has a counter;
//! each accepted item write bumps it and stamps the item with the new value.
//! Clients remember the highest revision they merged and ask for everything
//! newer. Uploads carry the revision they were based on; a stale base yields a
//! conflict that the client resolves (newest edit wins, the losing password is
//! preserved in the item's password history so nothing is ever lost).

use serde::{Deserialize, Serialize};

use crate::api::VaultSyncResult;
use crate::api::{ItemChange, ItemDto, SyncRequest, SyncResponse, VaultDto, VaultSyncRequest};
use crate::crypto::SymmetricKey;
use crate::item::{Item, PasswordHistoryEntry, MAX_PASSWORD_HISTORY};
use crate::profile::{
    aad, retired_key_id, ItemRecord, KeyChange, Leftover, Role, SyncState, VaultLocation, VaultRecord, RETIRED_KEYS,
};
use crate::session::Session;
use crate::util::now;
use crate::Result;

/// Outcome of applying a sync response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    pub uploaded: usize,
    pub downloaded: usize,
    pub deleted: usize,
    pub conflicts: usize,
    pub rejected: usize,
    /// Changes the server did not store because its storage limit is
    /// reached; they stay on this device.
    #[serde(default)]
    pub over_quota: usize,
    pub vaults_added: usize,
    pub vaults_removed: usize,
    /// True when local changes remain that need another round trip.
    pub needs_another_round: bool,
    /// The profile photo was changed on another device.
    #[serde(default)]
    pub avatar_changed: bool,
    /// Vault keys the server offered and this device refused: keys the vault
    /// had before, or a key sealed to our public key for a vault without
    /// other members.
    #[serde(default)]
    pub keys_refused: usize,
    /// The vaults (ids) those refused keys were for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys_refused_in: Vec<String>,
    /// Vaults (ids) whose key another member replaced during this sync.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys_replaced: Vec<String>,
    /// Emergency contacts for whom the server reports other public keys than
    /// this device knew: no vault key was sealed to them (see
    /// [`Session::recipient`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub untrusted_contacts: Vec<KeyChange>,
    /// Emergency access as the server sees it (none: not supported there).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency: Option<crate::api::EmergencyOverview>,
}

/// Append the ids in `more` that `list` does not have yet.
fn extend_unique(list: &mut Vec<String>, more: &[String]) {
    for id in more {
        if !list.contains(id) {
            list.push(id.clone());
        }
    }
}

impl SyncReport {
    pub fn merge(&mut self, other: &SyncReport) {
        self.uploaded += other.uploaded;
        self.downloaded += other.downloaded;
        self.deleted += other.deleted;
        self.conflicts += other.conflicts;
        self.rejected += other.rejected;
        // Every round sends all waiting changes: the last one counts.
        self.over_quota = other.over_quota;
        self.vaults_added += other.vaults_added;
        self.vaults_removed += other.vaults_removed;
        self.keys_refused += other.keys_refused;
        extend_unique(&mut self.keys_refused_in, &other.keys_refused_in);
        extend_unique(&mut self.keys_replaced, &other.keys_replaced);
        self.untrusted_contacts.extend(other.untrusted_contacts.iter().cloned());
        self.needs_another_round = other.needs_another_round;
        self.avatar_changed |= other.avatar_changed;
    }
}

impl Session {
    /// The account's vaults (those on its server) in the given state: created,
    /// changed or deleted here and not yet on the server.
    pub fn vaults_pending(&self, state: SyncState) -> Vec<VaultRecord> {
        self.profile().vaults.iter().filter(|v| v.location.is_account() && v.sync_state == state).cloned().collect()
    }

    /// Mark a vault as known to the server (after create/update succeeded).
    pub fn mark_vault_synced(&mut self, vault_id: &str) {
        if let Some(v) = self.profile_mut().vault_mut(vault_id) {
            v.sync_state = SyncState::Synced;
        }
    }

    /// Forget a vault locally after the server confirmed its deletion.
    pub fn forget_vault(&mut self, vault_id: &str) {
        let p = self.profile_mut();
        p.vaults.retain(|v| v.id != vault_id);
        p.items.retain(|i| i.vault_id != vault_id);
        let _ = self.reload();
    }

    /// Build the next sync request: all local changes plus "what's new since
    /// revision N" for every synced vault. Vaults in a storage folder that
    /// left a placeholder on the server are asked for too, with the removal
    /// of what is still on it (see [`VaultRecord::leftovers`]).
    pub fn sync_request(&self) -> SyncRequest {
        let placeholders =
            self.profile().vaults.iter().filter(|v| v.location.is_folder() && v.on_server).map(|v| VaultSyncRequest {
                vault_id: v.id.clone(),
                since: v.revision,
                changes: v
                    .leftovers
                    .iter()
                    .map(|l| ItemChange { id: l.id.clone(), base_revision: l.revision, data: None })
                    .collect(),
                key_rev: Some(v.key_rev),
            });
        let vaults = self
            .profile()
            .vaults
            .iter()
            .filter(|v| v.location.is_account())
            .filter(|v| v.sync_state == SyncState::Synced || v.sync_state == SyncState::PendingUpdate)
            .map(|v| VaultSyncRequest {
                vault_id: v.id.clone(),
                since: v.revision,
                changes: self
                    .profile()
                    .items
                    .iter()
                    .filter(|i| i.vault_id == v.id && i.dirty && v.role.can_write())
                    .map(|i| ItemChange { id: i.id.clone(), base_revision: i.revision, data: i.data.clone() })
                    .collect(),
                key_rev: Some(v.key_rev),
            })
            .chain(placeholders)
            .collect();
        SyncRequest { vaults }
    }

    /// Merge a server response into the local state.
    pub fn apply_sync_response(&mut self, response: SyncResponse) -> Result<SyncReport> {
        self.apply_sync_response_for(None, response)
    }

    /// Merge a server response, knowing which request produced it. Local
    /// edits made while the request was in flight stay marked as changed
    /// (they are uploaded in the next round instead of being lost).
    pub fn apply_sync_response_for(
        &mut self,
        request: Option<&SyncRequest>,
        response: SyncResponse,
    ) -> Result<SyncReport> {
        let sent: std::collections::HashMap<&str, &Option<crate::crypto::EncString>> = request
            .map(|r| r.vaults.iter().flat_map(|v| v.changes.iter().map(|c| (c.id.as_str(), &c.data))).collect())
            .unwrap_or_default();
        let mut report = SyncReport::default();
        self.apply_vault_list(&response.vaults, &mut report)?;

        for result in response.results {
            let vault_id = result.vault_id.clone();
            match self.profile().vault(&vault_id).map(|v| &v.location) {
                Some(VaultLocation::Account) => {}
                Some(VaultLocation::Folder { .. }) => {
                    self.drain_placeholder(&result, &mut report);
                    continue;
                }
                // Not ours, or kept on this device only: the server's copy
                // (if any) is not this vault.
                Some(VaultLocation::Device) | None => continue,
            }

            for acc in &result.accepted {
                let changed_since = sent
                    .get(acc.id.as_str())
                    .map(|data| self.profile().item(&acc.id).is_some_and(|r| &r.data != *data))
                    .unwrap_or(false);
                let p = self.profile_mut();
                if let Some(pos) = p.items.iter().position(|i| i.id == acc.id) {
                    report.uploaded += 1;
                    if changed_since {
                        // Edited again meanwhile: keep it dirty, rebased.
                        p.items[pos].revision = acc.revision;
                        report.needs_another_round = true;
                    } else if p.items[pos].data.is_none() {
                        p.items.remove(pos);
                    } else {
                        p.items[pos].revision = acc.revision;
                        p.items[pos].dirty = false;
                    }
                }
            }

            let mut refetch = false;
            for id in &result.rejected {
                // The server refused our change (e.g. we lost write access):
                // drop the local edit and re-download the server version.
                report.rejected += 1;
                self.profile_mut().items.retain(|i| &i.id != id || i.vault_id != vault_id);
                refetch = true;
            }

            // Not stored for lack of space: the items stay changed and are
            // sent again with a later sync.
            report.over_quota += result.over_quota.len();

            if !result.stale_key.is_empty() {
                // Encrypted with a vault key that was replaced meanwhile. The
                // vault list above brought the new key and re-encrypted our
                // copies; they stay changed and go out in the next round.
                report.needs_another_round = true;
            }

            for remote in &result.changes {
                self.apply_remote_item(remote, &mut report);
            }

            for remote in &result.conflicts {
                report.conflicts += 1;
                self.resolve_conflict(remote, &mut report);
            }

            if let Some(v) = self.profile_mut().vault_mut(&vault_id) {
                if refetch {
                    v.revision = 0;
                    report.needs_another_round = true;
                } else {
                    v.revision = v.revision.max(result.revision);
                }
            }
        }

        if let Some(link) = &mut self.profile_mut().server {
            link.last_sync_at = Some(now());
        }
        self.reload()?;
        if self.profile().items.iter().any(|i| i.dirty) && report.conflicts > 0 {
            report.needs_another_round = true;
        }
        Ok(report)
    }

    fn apply_vault_list(&mut self, vaults: &[VaultDto], report: &mut SyncReport) -> Result<()> {
        // Vaults whose key someone replaced: re-encrypt our copies with the
        // new key while we still have the old one. A key the vault had before
        // (a server going back to the key a removed member still knows) is
        // refused, and the vault keeps its key.
        let mut refused: Vec<String> = Vec::new();
        let mut replaced: Vec<(String, SymmetricKey)> = Vec::new();
        for dto in vaults {
            let Some(local) = self.profile().vault(&dto.id) else { continue };
            if !local.location.is_account() || local.wrapped_key == dto.wrapped_key {
                continue;
            }
            // Only this account's own devices can give a vault without other
            // members a new key, and they wrap it with the account key. A key
            // sealed to our public key (anyone can make one, a server too) is
            // refused for such a vault.
            let alone = local.role == Role::Owner && local.member_count <= 1 && dto.member_count <= 1;
            if alone && dto.wrapped_key.is_sealed() {
                refused.push(dto.id.clone());
                continue;
            }
            let Ok(new_key) = dto.wrapped_key.unwrap(self.keyset(), &aad::vault_key(&dto.id)) else { continue };
            let Some(old_key) = self.vault_key(&dto.id) else { continue };
            if old_key == &new_key {
                continue;
            }
            if local.retired_keys.contains(&retired_key_id(&new_key)) {
                refused.push(dto.id.clone());
            } else {
                let retired = retired_key_id(old_key);
                if let Some(v) = self.profile_mut().vault_mut(&dto.id) {
                    v.retired_keys.retain(|k| *k != retired);
                    v.retired_keys.push(retired);
                    let excess = v.retired_keys.len().saturating_sub(RETIRED_KEYS);
                    v.retired_keys.drain(..excess);
                }
                replaced.push((dto.id.clone(), new_key));
            }
        }
        report.keys_refused += refused.len();
        extend_unique(&mut report.keys_refused_in, &refused);
        for (vault_id, key) in &replaced {
            self.reencrypt_vault(vault_id, key);
            if !report.keys_replaced.contains(vault_id) {
                report.keys_replaced.push(vault_id.clone());
            }
        }

        let account_id = self.account().id.clone();
        let p = self.profile_mut();
        // Vaults we lost access to (deleted by the owner or access revoked).
        // Vaults kept elsewhere (this device, a storage folder) are not the
        // server's to remove or change, even when it lists a vault with the
        // same id (the placeholder a move leaves there).
        let before = p.vaults.len();
        p.vaults.retain(|v| {
            !v.location.is_account()
                || v.sync_state == SyncState::PendingCreate
                || v.sync_state == SyncState::PendingDelete
                || vaults.iter().any(|d| d.id == v.id)
        });
        report.vaults_removed += before - p.vaults.len();
        let kept: Vec<String> = p.vaults.iter().map(|v| v.id.clone()).collect();
        p.items.retain(|i| kept.contains(&i.vault_id));
        for v in p.vaults.iter_mut().filter(|v| !v.location.is_account()) {
            v.on_server = vaults.iter().any(|d| d.id == v.id);
            if !v.on_server {
                v.leftovers.clear();
                v.revision = 0;
            }
        }

        for dto in vaults {
            match p.vault_mut(&dto.id) {
                Some(local) => {
                    if refused.contains(&dto.id) || !local.location.is_account() {
                        continue;
                    }
                    if local.sync_state != SyncState::PendingUpdate {
                        local.meta = dto.meta.clone();
                    }
                    local.role = dto.role;
                    local.owner_id = dto.owner_id.clone();
                    local.member_count = dto.member_count;
                    if local.wrapped_key != dto.wrapped_key {
                        local.wrapped_key = dto.wrapped_key.clone();
                    }
                    local.key_rev = dto.key_rev;
                }
                None => {
                    report.vaults_added += 1;
                    p.vaults.push(VaultRecord {
                        id: dto.id.clone(),
                        owner_id: dto.owner_id.clone(),
                        role: if dto.owner_id == account_id {
                            dto.role.max(crate::profile::Role::Owner)
                        } else {
                            dto.role
                        },
                        wrapped_key: dto.wrapped_key.clone(),
                        meta: dto.meta.clone(),
                        revision: 0,
                        sync_state: SyncState::Synced,
                        member_count: dto.member_count,
                        created_at: dto.created_at,
                        key_rev: dto.key_rev,
                        retired_keys: Vec::new(),
                        location: VaultLocation::Account,
                        leftovers: Vec::new(),
                        on_server: false,
                    });
                }
            }
        }
        self.reload()
    }

    fn apply_remote_item(&mut self, remote: &ItemDto, report: &mut SyncReport) {
        let p = self.profile_mut();
        match p.items.iter().position(|i| i.id == remote.id) {
            Some(pos) => {
                let local = &p.items[pos];
                if local.vault_id != remote.vault_id {
                    return; // Another vault's item with the same ID: not ours to replace.
                }
                if remote.revision <= local.revision {
                    return; // Already have this (e.g. our own accepted write).
                }
                if local.dirty {
                    // Concurrent edit that the server did not flag (we did not
                    // send it yet): treat it like a conflict.
                    report.conflicts += 1;
                    self.resolve_conflict(remote, report);
                    return;
                }
                match &remote.data {
                    Some(data) => {
                        p.items[pos].data = Some(data.clone());
                        p.items[pos].revision = remote.revision;
                        report.downloaded += 1;
                    }
                    None => {
                        p.items.remove(pos);
                        report.deleted += 1;
                    }
                }
            }
            None => {
                if let Some(data) = &remote.data {
                    p.items.push(ItemRecord {
                        id: remote.id.clone(),
                        vault_id: remote.vault_id.clone(),
                        data: Some(data.clone()),
                        revision: remote.revision,
                        dirty: false,
                        deleted_at: None,
                    });
                    report.downloaded += 1;
                }
            }
        }
    }

    /// Resolve a conflict between our dirty local record and the server's
    /// current version.
    fn resolve_conflict(&mut self, remote: &ItemDto, report: &mut SyncReport) {
        let local_rec = match self.profile().item(&remote.id) {
            Some(r) => r.clone(),
            None => {
                // We no longer have it locally: just take the server version.
                self.apply_remote_item(remote, report);
                return;
            }
        };
        let vault_id = local_rec.vault_id.clone();
        let local_item = local_rec.data.as_ref().and_then(|d| self.decrypt_item(&vault_id, &local_rec.id, d).ok());
        let remote_item = remote.data.as_ref().and_then(|d| self.decrypt_item(&vault_id, &remote.id, d).ok());

        let winner: Option<(Item, bool)> = match (local_item, remote_item) {
            // Both deleted: nothing left to do.
            (None, None) => None,
            // We deleted, they edited: keep their edit (safer than losing data).
            (None, Some(theirs)) => Some((theirs, false)),
            // They deleted, we edited: resurrect our version.
            (Some(ours), None) => Some((ours, true)),
            (Some(ours), Some(theirs)) => Some(merge_items(&ours, &theirs)),
        };

        match winner {
            None => {
                self.profile_mut().items.retain(|i| i.id != remote.id);
            }
            Some((item, ours)) => {
                let data = if ours { self.encrypt_item(&vault_id, &item).ok() } else { remote.data.clone() };
                if let Some(rec) = self.profile_mut().item_mut(&remote.id) {
                    rec.data = data;
                    rec.revision = remote.revision;
                    rec.dirty = ours;
                }
            }
        }
    }
}

impl Session {
    /// Take in what the server reported for the placeholder of a vault that
    /// moved to a storage folder: items someone still added or changed there
    /// join the folder vault (and go into the folder with the next folder
    /// sync), and are then removed from the placeholder.
    fn drain_placeholder(&mut self, result: &VaultSyncResult, report: &mut SyncReport) {
        let vault_id = result.vault_id.as_str();
        let mut gone: Vec<&str> = result.accepted.iter().map(|a| a.id.as_str()).collect();
        gone.extend(result.rejected.iter().map(|id| id.as_str()));
        let mut found: Vec<Leftover> = Vec::new();
        for remote in result.conflicts.iter().chain(&result.changes) {
            if remote.vault_id != vault_id {
                continue;
            }
            match &remote.data {
                Some(_) => {
                    if self.absorb_item(vault_id, remote) {
                        report.downloaded += 1;
                    }
                    found.push(Leftover { id: remote.id.clone(), revision: remote.revision });
                }
                None => gone.push(remote.id.as_str()),
            }
        }
        if let Some(v) = self.profile_mut().vault_mut(vault_id) {
            v.leftovers.retain(|l| !gone.contains(&l.id.as_str()) && !found.iter().any(|f| f.id == l.id));
            v.leftovers.extend(found);
            v.revision = v.revision.max(result.revision);
            if !v.leftovers.is_empty() {
                report.needs_another_round = true;
            }
        }
    }

    /// Merge an item from elsewhere (a server placeholder) into a vault kept
    /// in a storage folder. It is marked changed, so it goes into the folder.
    /// Returns whether the local copy changed.
    pub(crate) fn absorb_item(&mut self, vault_id: &str, remote: &ItemDto) -> bool {
        let Some(data) = &remote.data else { return false };
        let Ok(theirs) = self.decrypt_item(vault_id, &remote.id, data) else { return false };
        if self.profile().item(&remote.id).is_some_and(|r| r.vault_id != vault_id) {
            return false;
        }
        let ours = self.item(&remote.id).cloned();
        let item = match &ours {
            Some(ours) => merge_items(&theirs, ours).0,
            None => theirs,
        };
        if ours.as_ref() == Some(&item) {
            return false;
        }
        let Ok(data) = self.encrypt_item(vault_id, &item) else { return false };
        let p = self.profile_mut();
        match p.item_mut(&remote.id) {
            Some(rec) => {
                rec.data = Some(data);
                rec.dirty = true;
            }
            None => p.items.push(ItemRecord {
                id: remote.id.clone(),
                vault_id: vault_id.to_string(),
                data: Some(data),
                revision: 0,
                dirty: true,
                deleted_at: None,
            }),
        }
        true
    }
}

/// Merge two versions of an item: the newest edit wins (`ours` on a tie) and
/// the other one's passwords are kept in its password history, so no
/// password is ever lost. Returns the result and whether it differs from
/// `theirs` (so it still has to go to wherever `theirs` came from).
///
/// Used for conflicts with the server and for storage folders alike.
pub fn merge_items(ours: &Item, theirs: &Item) -> (Item, bool) {
    if ours == theirs {
        return (theirs.clone(), false);
    }
    let mut merged = if ours.updated_at >= theirs.updated_at { ours.clone() } else { theirs.clone() };
    let other = if ours.updated_at >= theirs.updated_at { theirs } else { ours };
    merge_password_history(&mut merged, other);
    let changed = merged != *theirs;
    (merged, changed)
}

/// Add the other version's current and previous passwords to `item`'s history.
pub(crate) fn merge_password_history(item: &mut Item, other: &Item) {
    let current = item.password().unwrap_or("").to_string();
    let mut candidates: Vec<PasswordHistoryEntry> = Vec::new();
    if let Some(pw) = other.password() {
        candidates.push(PasswordHistoryEntry { value: pw.to_string(), changed_at: other.updated_at });
    }
    candidates.extend(other.password_history.iter().cloned());
    for entry in candidates {
        if entry.value != current && !item.password_history.iter().any(|h| h.value == entry.value) {
            item.password_history.push(entry);
        }
    }
    // Newest first; equal times by value, so every device gets the same order.
    item.password_history.sort_by(|a, b| b.changed_at.cmp(&a.changed_at).then_with(|| a.value.cmp(&b.value)));
    item.password_history.truncate(MAX_PASSWORD_HISTORY);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Accepted, MemberDto, RotateVaultKeyRequest, VaultSyncResult};
    use crate::crypto::{decrypt_json, encrypt_json, WrappedKey};
    use crate::profile::Role;
    use crate::session::tests::new_session;

    /// Minimal in-memory server implementing the revision protocol.
    #[derive(Default)]
    struct FakeServer {
        vaults: Vec<VaultDto>,
        items: Vec<ItemDto>,
    }

    impl FakeServer {
        fn create_vaults(&mut self, s: &mut Session) {
            for v in s.vaults_pending(SyncState::PendingCreate) {
                // Back from elsewhere: the client then updates the name.
                if let Some(existing) = self.vaults.iter_mut().find(|d| d.id == v.id) {
                    existing.meta = v.meta.clone();
                    s.mark_vault_synced(&v.id);
                    continue;
                }
                self.vaults.push(VaultDto {
                    id: v.id.clone(),
                    owner_id: v.owner_id.clone(),
                    role: Role::Owner,
                    meta: v.meta.clone(),
                    wrapped_key: v.wrapped_key.clone(),
                    revision: 0,
                    member_count: 1,
                    created_at: v.created_at,
                    key_rev: 0,
                });
                s.mark_vault_synced(&v.id);
            }
        }

        fn sync(&mut self, req: SyncRequest) -> SyncResponse {
            let mut results = Vec::new();
            for vr in req.vaults {
                let Some(vault) = self.vaults.iter_mut().find(|v| v.id == vr.vault_id) else {
                    continue;
                };
                let mut accepted = Vec::new();
                let mut conflicts = Vec::new();
                let mut stale_key = Vec::new();
                for ch in vr.changes {
                    if ch.data.is_some() && vr.key_rev.unwrap_or(0) != vault.key_rev {
                        stale_key.push(ch.id);
                        continue;
                    }
                    let current = self.items.iter().find(|i| i.id == ch.id).cloned();
                    let current_rev = current.as_ref().map(|c| c.revision).unwrap_or(0);
                    if current_rev != ch.base_revision {
                        conflicts.push(current.unwrap());
                        continue;
                    }
                    vault.revision += 1;
                    let dto = ItemDto {
                        id: ch.id.clone(),
                        vault_id: vr.vault_id.clone(),
                        revision: vault.revision,
                        data: ch.data,
                    };
                    self.items.retain(|i| i.id != ch.id);
                    self.items.push(dto);
                    accepted.push(Accepted { id: ch.id, revision: vault.revision });
                }
                let changes = self
                    .items
                    .iter()
                    .filter(|i| i.vault_id == vr.vault_id && i.revision > vr.since)
                    .filter(|i| !accepted.iter().any(|a| a.id == i.id))
                    .cloned()
                    .collect();
                results.push(VaultSyncResult {
                    vault_id: vr.vault_id,
                    revision: vault.revision,
                    accepted,
                    conflicts,
                    changes,
                    rejected: vec![],
                    over_quota: vec![],
                    stale_key,
                });
            }
            SyncResponse { vaults: self.vaults.clone(), results }
        }

        fn full_sync(&mut self, s: &mut Session) -> SyncReport {
            self.create_vaults(s);
            let mut total = SyncReport::default();
            for _ in 0..4 {
                let r = s.apply_sync_response(self.sync(s.sync_request())).unwrap();
                total.merge(&r);
                if !r.needs_another_round && !s.profile().items.iter().any(|i| i.dirty) {
                    break;
                }
            }
            total
        }
    }

    impl FakeServer {
        /// Apply a key replacement the way the real server does.
        fn rotate(&mut self, vault_id: &str, req: RotateVaultKeyRequest) {
            let Self { vaults, items } = self;
            let vault = vaults.iter_mut().find(|v| v.id == vault_id).unwrap();
            assert_eq!(vault.key_rev, req.key_rev);
            vault.key_rev += 1;
            vault.meta = req.meta;
            vault.wrapped_key = req.members[0].wrapped_key.clone();
            for rotated in req.items {
                vault.revision += 1;
                let item = items.iter_mut().find(|i| i.id == rotated.id).unwrap();
                item.data = Some(rotated.data);
                item.revision = vault.revision;
            }
        }
    }

    fn me(s: &Session) -> MemberDto {
        MemberDto {
            account_id: s.account().id.clone(),
            email: s.account().email.clone(),
            name: s.account().name.clone(),
            role: Role::Owner,
            public_key: s.public_key().to_b64(),
            pq_public_key: None,
        }
    }

    #[test]
    fn an_item_of_another_vault_with_the_same_id_is_not_ours() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        let w = a.create_vault("Work", "").unwrap();
        let id = a.add_item(&v, Item::login("Site", "u", "p1", None)).unwrap();
        let other = a.add_item(&w, Item::login("Other", "o", "p2", None)).unwrap();
        server.full_sync(&mut a);
        let data = server.items.iter().find(|i| i.id == other).unwrap().data.clone();
        server.items.push(ItemDto { id: id.clone(), vault_id: w.clone(), revision: 100, data });
        server.vaults.iter_mut().find(|d| d.id == w).unwrap().revision = 100;
        server.full_sync(&mut a);
        assert_eq!(a.item(&id).unwrap().password(), Some("p1"));
        assert!(a.undecryptable().is_empty());
    }

    #[test]
    fn a_server_cannot_bring_back_an_old_vault_key() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        let id = a.add_item(&v, Item::login("Site", "u", "p1", None)).unwrap();
        server.full_sync(&mut a);
        let old_wrapped = server.vaults[0].wrapped_key.clone();
        let req = a.rotate_vault_key_request(&v, &[me(&a)]).unwrap();
        server.rotate(&v, req);
        server.full_sync(&mut a);
        let key = a.vault_key(&v).unwrap().clone();
        assert_eq!(a.profile().vault(&v).unwrap().retired_keys.len(), 1);

        // The key from before the rotation (which a removed member may
        // still know), even as a newer generation.
        server.vaults[0].wrapped_key = old_wrapped;
        server.vaults[0].key_rev += 1;
        assert_eq!(server.full_sync(&mut a).keys_refused, 1);
        assert_eq!(a.vault_key(&v), Some(&key));
        assert_eq!(a.item(&id).unwrap().password(), Some("p1"));

        // A key rotated in later by a member (the vault is shared) is taken,
        // and the one before it retired.
        let newer = SymmetricKey::generate();
        let meta_aad = aad::vault_meta(&v);
        let meta: crate::profile::VaultMeta = decrypt_json(&key, &server.vaults[0].meta, &meta_aad).unwrap();
        server.vaults[0].meta = encrypt_json(&newer, &meta, &meta_aad).unwrap();
        server.vaults[0].wrapped_key = WrappedKey::wrap_sealed(&a.public_key(), &newer, &aad::vault_key(&v));
        server.vaults[0].member_count = 2;
        let report = server.full_sync(&mut a);
        assert_eq!((report.keys_refused, report.keys_replaced), (0, vec![v.clone()]));
        assert_eq!(a.vault_key(&v), Some(&newer));
        assert_eq!(a.profile().vault(&v).unwrap().retired_keys.len(), 2);
    }

    #[test]
    fn a_sealed_key_for_a_vault_without_other_members_is_refused() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        let id = a.add_item(&v, Item::login("Site", "u", "p1", None)).unwrap();
        server.full_sync(&mut a);
        let key = a.vault_key(&v).unwrap().clone();
        // Only our own devices could replace this key, and they would wrap
        // it with the account key: a sealed one is a server's doing.
        let other = SymmetricKey::generate();
        server.vaults[0].wrapped_key = WrappedKey::wrap_sealed(&a.public_key(), &other, &aad::vault_key(&v));
        server.vaults[0].key_rev += 1;
        let report = server.full_sync(&mut a);
        assert_eq!((report.keys_refused, report.keys_refused_in.clone()), (1, vec![v.clone()]));
        assert!(report.keys_replaced.is_empty());
        assert_eq!(a.vault_key(&v), Some(&key));
        assert_eq!(a.item(&id).unwrap().password(), Some("p1"));
        assert!(a.profile().vault(&v).unwrap().retired_keys.is_empty());
        // With other members, a member may have replaced it: taken, and reported.
        server.vaults[0].member_count = 2;
        let meta_aad = aad::vault_meta(&v);
        let meta: crate::profile::VaultMeta = decrypt_json(&key, &server.vaults[0].meta, &meta_aad).unwrap();
        server.vaults[0].meta = encrypt_json(&other, &meta, &meta_aad).unwrap();
        let report = server.full_sync(&mut a);
        assert_eq!((report.keys_refused, report.keys_replaced), (0, vec![v.clone()]));
        assert_eq!(a.vault_key(&v), Some(&other));
    }

    #[test]
    fn a_replaced_key_is_not_sealed_to_changed_member_keys() {
        let (mut a, _) = new_session();
        let (bob, _) = new_session();
        let (eve, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        server.full_sync(&mut a);
        let member = |keys_of: &Session| MemberDto {
            account_id: bob.account().id.clone(),
            email: "bob@example.com".into(),
            name: "Bob".into(),
            role: Role::Editor,
            public_key: keys_of.public_key().to_b64(),
            pq_public_key: keys_of.public_keys().ml_kem.map(|k| k.to_b64()),
        };
        // Bob's keys are known from sharing the vault with him.
        a.recipient(&bob.account().id, "bob@example.com", &bob.public_key().to_b64(), None).unwrap();
        // The server lists Bob with other keys: nothing is sealed to them.
        let err = a.rotate_vault_key_request(&v, &[me(&a), member(&eve)]).unwrap_err();
        assert!(matches!(err, crate::Error::KeyChanged(_)), "{err}");
        let req = a.rotate_vault_key_request(&v, &[me(&a), member(&bob)]).unwrap();
        assert_eq!(req.members.len(), 2);
        assert!(matches!(req.members[1].wrapped_key, WrappedKey::HybridSealed { .. }));
    }

    #[test]
    fn replaced_vault_keys_reach_other_devices_without_losing_edits() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        let id = a.add_item(&v, Item::login("Site", "u", "p1", None)).unwrap();
        server.full_sync(&mut a);
        let mut b = second_device(&a);
        let old_key = a.vault_key(&v).unwrap().clone();

        // Device B edits and adds an item offline, while A replaces the key.
        let mut edited = b.item(&id).unwrap().clone();
        edited.set_value("password", "p2");
        b.update_item(edited).unwrap();
        let added = b.add_item(&v, Item::login("New", "n", "p3", None)).unwrap();

        assert!(b.rotate_vault_key_request(&v, &[me(&b)]).is_err(), "B has unsynced changes");
        let req = a.rotate_vault_key_request(&v, &[me(&a)]).unwrap();
        assert_eq!(req.items.len(), 1);
        server.rotate(&v, req);
        server.full_sync(&mut a);
        assert_ne!(a.vault_key(&v).unwrap(), &old_key);
        assert_eq!(a.item(&id).unwrap().password(), Some("p1"));

        // B's uploads under the old key are refused, re-encrypted, sent again.
        server.full_sync(&mut b);
        assert_eq!(b.vault_key(&v), a.vault_key(&v));
        assert!(!b.profile().has_pending_changes());
        server.full_sync(&mut a);
        assert_eq!(a.item(&id).unwrap().password(), Some("p2"));
        assert_eq!(a.item(&added).unwrap().title, "New");
        assert!(a.undecryptable().is_empty() && b.undecryptable().is_empty());
        assert_eq!(a.vault(&v).unwrap().name, "Personal");
    }

    fn second_device(s: &Session) -> Session {
        Session::open_with_account_key(s.profile().clone(), s.account_key().clone()).unwrap()
    }

    #[test]
    fn two_devices_converge() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        let id = a.add_item(&v, Item::login("Site", "u", "p1", None)).unwrap();
        let r = server.full_sync(&mut a);
        assert_eq!(r.uploaded, 1);
        assert!(!a.profile().has_pending_changes());

        let mut b = second_device(&a);
        // Device B edits, A deletes nothing; B syncs first.
        let mut item = b.item(&id).unwrap().clone();
        item.set_value("password", "p2");
        b.update_item(item).unwrap();
        server.full_sync(&mut b);
        let r = server.full_sync(&mut a);
        assert_eq!(r.downloaded, 1);
        assert_eq!(a.item(&id).unwrap().password(), Some("p2"));

        // Deletion propagates.
        b.delete_item(&id).unwrap();
        server.full_sync(&mut b);
        server.full_sync(&mut a);
        assert!(a.item(&id).is_none());
        assert!(a.profile().item(&id).is_none());
    }

    #[test]
    fn conflicting_edits_keep_newest_and_history() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        let id = a.add_item(&v, Item::login("Site", "u", "base", None)).unwrap();
        server.full_sync(&mut a);
        let mut b = second_device(&a);

        let mut ia = a.item(&id).unwrap().clone();
        ia.set_value("password", "from-a");
        a.update_item(ia).unwrap();

        let mut ib = b.item(&id).unwrap().clone();
        ib.set_value("password", "from-b");
        ib.updated_at = 0; // will be bumped to previous+1 => older than A's edit
        b.update_item(ib).unwrap();
        // Make B's edit clearly older.
        {
            let mut item = b.item(&id).unwrap().clone();
            item.updated_at = 1;
            let data = b.encrypt_item(&v, &item).unwrap();
            b.profile_mut().item_mut(&id).unwrap().data = Some(data);
            b.reload().unwrap();
        }

        server.full_sync(&mut a);
        let r = server.full_sync(&mut b);
        assert!(r.conflicts >= 1);
        let final_b = b.item(&id).unwrap();
        assert_eq!(final_b.password(), Some("from-a"));
        assert!(final_b.password_history.iter().any(|h| h.value == "from-b"));
        server.full_sync(&mut a);
        assert_eq!(a.item(&id).unwrap().password(), Some("from-a"));
        assert!(a.item(&id).unwrap().password_history.iter().any(|h| h.value == "from-b"));
    }

    #[test]
    fn edit_wins_over_concurrent_delete() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        let id = a.add_item(&v, Item::login("Site", "u", "p", None)).unwrap();
        server.full_sync(&mut a);
        let mut b = second_device(&a);
        a.delete_item(&id).unwrap();
        server.full_sync(&mut a);
        let mut item = b.item(&id).unwrap().clone();
        item.notes = "important".into();
        b.update_item(item).unwrap();
        server.full_sync(&mut b);
        assert_eq!(b.item(&id).unwrap().notes, "important");
        server.full_sync(&mut a);
        assert_eq!(a.item(&id).unwrap().notes, "important");
    }

    #[test]
    fn edits_during_flight_are_not_lost() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v = a.default_vault_id().unwrap();
        let id = a.add_item(&v, Item::login("Site", "u", "p1", None)).unwrap();
        server.create_vaults(&mut a);
        let req = a.sync_request();
        // The user edits while the request is on the wire.
        let mut item = a.item(&id).unwrap().clone();
        item.set_value("password", "p2");
        a.update_item(item).unwrap();
        let resp = server.sync(req.clone());
        let r = a.apply_sync_response_for(Some(&req), resp).unwrap();
        assert!(r.needs_another_round);
        assert!(a.profile().item(&id).unwrap().dirty);
        server.full_sync(&mut a);
        assert!(!a.profile().has_pending_changes());
        let b = second_device(&a);
        assert_eq!(b.item(&id).unwrap().password(), Some("p2"));
        let stored = server.items.iter().find(|i| i.id == id).unwrap();
        assert_eq!(stored.revision, 2);
    }

    #[test]
    fn removed_vaults_disappear() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let v2 = a.create_vault("Temp", "").unwrap();
        a.add_item(&v2, Item::login("x", "y", "z", None)).unwrap();
        server.full_sync(&mut a);
        assert_eq!(a.vaults().len(), 2);
        server.vaults.retain(|v| v.id != v2);
        let r = server.full_sync(&mut a);
        assert_eq!(r.vaults_removed, 1);
        assert_eq!(a.vaults().len(), 1);
        assert_eq!(a.item_count(), 0);
    }

    fn folder() -> VaultLocation {
        VaultLocation::Folder { path: "/tmp/work".into(), service: crate::profile::FolderService::Dropbox }
    }

    #[test]
    fn vaults_kept_elsewhere_are_not_the_servers() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let here = a.create_vault_at("Here", "", VaultLocation::Device).unwrap();
        let there = a.create_vault_at("There", "", folder()).unwrap();
        let id = a.add_item(&here, Item::login("Local", "me", "pw", None)).unwrap();
        a.add_item(&there, Item::login("Folder", "me", "pw", None)).unwrap();
        server.full_sync(&mut a);
        assert_eq!(server.vaults.len(), 1, "only the personal vault goes to the server");
        assert!(server.items.is_empty());
        assert!(!a.profile().has_pending_changes());
        assert!(a.profile().has_pending_folder_changes());
        // A server listing vaults with the same ids changes nothing here.
        for vid in [&here, &there] {
            let mut fake = server.vaults[0].clone();
            fake.id = vid.clone();
            server.vaults.push(fake);
        }
        server.items.push(ItemDto { id: id.clone(), vault_id: here.clone(), revision: 9, data: None });
        server.full_sync(&mut a);
        assert_eq!(a.vault(&here).unwrap().name, "Here");
        assert_eq!(a.vault(&there).unwrap().name, "There");
        assert!(a.item(&id).is_some());
        assert!(a.profile().vault(&there).unwrap().on_server);
        // Vaults kept elsewhere stay when the account leaves its server.
        a.unlink_server();
        assert!(a.vault(&here).is_some() && a.vault(&there).is_some() && a.item(&id).is_some());
        assert!(a.profile().vault(&here).unwrap().location.is_device());
    }

    #[test]
    fn a_vault_moved_to_a_folder_leaves_an_emptied_placeholder() {
        use crate::profile::{FolderService, MoveTarget, MovedTo};
        let (mut a, _) = new_session();
        a.set_server("https://sync.example.com", "token");
        let mut server = FakeServer::default();
        let w = a.create_vault("Work", "").unwrap();
        let one = a.add_item(&w, Item::login("One", "me", "pw", None)).unwrap();
        server.full_sync(&mut a);
        let mut b = second_device(&a);
        server.full_sync(&mut b);
        assert!(b.item(&one).is_some());

        // a moves Work to a folder: the server copy becomes a placeholder.
        let moved = MovedTo {
            to: MoveTarget::Folder { service: FolderService::Dropbox, folder: "2Secret/Work".into() },
            at: now(),
        };
        let meta = a.placeholder_meta(&w, Some(moved)).unwrap();
        server.vaults.iter_mut().find(|d| d.id == w).unwrap().meta = meta;
        a.relocate_vault(&w, folder()).unwrap();
        assert_eq!(a.profile().vault(&w).unwrap().leftovers.len(), 1);

        // Meanwhile b adds an item to the server copy.
        let two = b.add_item(&w, Item::login("Two", "me", "pw", None)).unwrap();
        server.full_sync(&mut b);
        assert!(b.vault(&w).unwrap().is_placeholder());
        assert!(b.add_item(&w, Item::login("Three", "me", "pw", None)).is_err(), "nothing goes into a placeholder");
        assert_ne!(b.default_vault_id().as_deref(), Some(w.as_str()));

        // a takes what is left on the placeholder and empties it.
        server.full_sync(&mut a);
        assert!(server.items.iter().filter(|i| i.vault_id == w).all(|i| i.data.is_none()));
        assert!(a.item(&one).is_some() && a.item(&two).is_some());
        let rec = a.profile().vault(&w).unwrap();
        assert!(rec.leftovers.is_empty() && rec.on_server);
        assert!(a.profile().has_pending_folder_changes(), "Two still has to go into the folder");
        server.full_sync(&mut b);
        assert!(b.item(&one).is_none() && b.item(&two).is_none());
        assert_eq!(b.vault(&w).unwrap().item_count, 0);

        // And back to the server: everything is there again for b.
        a.relocate_vault(&w, VaultLocation::Account).unwrap();
        server.full_sync(&mut a);
        assert!(!a.profile().has_pending_changes());
        server.full_sync(&mut b);
        assert!(!b.vault(&w).unwrap().is_placeholder());
        assert!(b.item(&one).is_some() && b.item(&two).is_some());
    }

    #[test]
    fn shared_vaults_stay_on_the_server() {
        let (mut a, _) = new_session();
        let mut server = FakeServer::default();
        let w = a.create_vault("Team", "").unwrap();
        server.full_sync(&mut a);
        server.vaults.iter_mut().find(|d| d.id == w).unwrap().member_count = 2;
        server.full_sync(&mut a);
        assert!(matches!(a.relocate_vault(&w, folder()), Err(crate::Error::VaultShared)));
    }
}
