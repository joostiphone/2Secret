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

use crate::api::{ItemChange, ItemDto, SyncRequest, SyncResponse, VaultDto, VaultSyncRequest};
use crate::item::{Item, PasswordHistoryEntry, MAX_PASSWORD_HISTORY};
use crate::profile::{ItemRecord, SyncState, VaultRecord};
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
    pub vaults_added: usize,
    pub vaults_removed: usize,
    /// True when local changes remain that need another round trip.
    pub needs_another_round: bool,
}

impl SyncReport {
    pub fn merge(&mut self, other: &SyncReport) {
        self.uploaded += other.uploaded;
        self.downloaded += other.downloaded;
        self.deleted += other.deleted;
        self.conflicts += other.conflicts;
        self.rejected += other.rejected;
        self.vaults_added += other.vaults_added;
        self.vaults_removed += other.vaults_removed;
        self.needs_another_round = other.needs_another_round;
    }
}

impl Session {
    /// Vaults created locally that must be created on the server first.
    pub fn vaults_pending(&self, state: SyncState) -> Vec<VaultRecord> {
        self.profile()
            .vaults
            .iter()
            .filter(|v| v.sync_state == state)
            .cloned()
            .collect()
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
    /// revision N" for every synced vault.
    pub fn sync_request(&self) -> SyncRequest {
        let vaults = self
            .profile()
            .vaults
            .iter()
            .filter(|v| v.sync_state == SyncState::Synced || v.sync_state == SyncState::PendingUpdate)
            .map(|v| VaultSyncRequest {
                vault_id: v.id.clone(),
                since: v.revision,
                changes: self
                    .profile()
                    .items
                    .iter()
                    .filter(|i| i.vault_id == v.id && i.dirty && v.role.can_write())
                    .map(|i| ItemChange {
                        id: i.id.clone(),
                        base_revision: i.revision,
                        data: i.data.clone(),
                    })
                    .collect(),
            })
            .collect();
        SyncRequest { vaults }
    }

    /// Merge a server response into the local state.
    pub fn apply_sync_response(&mut self, response: SyncResponse) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        self.apply_vault_list(&response.vaults, &mut report)?;

        for result in response.results {
            let vault_id = result.vault_id.clone();
            if self.profile().vault(&vault_id).is_none() {
                continue;
            }

            for acc in &result.accepted {
                let p = self.profile_mut();
                if let Some(pos) = p.items.iter().position(|i| i.id == acc.id) {
                    report.uploaded += 1;
                    if p.items[pos].data.is_none() {
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
                self.profile_mut().items.retain(|i| &i.id != id);
                refetch = true;
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
        let account_id = self.account().id.clone();
        let p = self.profile_mut();
        // Vaults we lost access to (deleted by the owner or access revoked).
        let before = p.vaults.len();
        p.vaults.retain(|v| {
            v.sync_state == SyncState::PendingCreate
                || v.sync_state == SyncState::PendingDelete
                || vaults.iter().any(|d| d.id == v.id)
        });
        report.vaults_removed += before - p.vaults.len();
        let kept: Vec<String> = p.vaults.iter().map(|v| v.id.clone()).collect();
        p.items.retain(|i| kept.contains(&i.vault_id));

        for dto in vaults {
            match p.vault_mut(&dto.id) {
                Some(local) => {
                    if local.sync_state != SyncState::PendingUpdate {
                        local.meta = dto.meta.clone();
                    }
                    local.role = dto.role;
                    local.owner_id = dto.owner_id.clone();
                    local.member_count = dto.member_count;
                    if local.wrapped_key != dto.wrapped_key {
                        local.wrapped_key = dto.wrapped_key.clone();
                    }
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
        let local_item = local_rec
            .data
            .as_ref()
            .and_then(|d| self.decrypt_item(&vault_id, &local_rec.id, d).ok());
        let remote_item = remote
            .data
            .as_ref()
            .and_then(|d| self.decrypt_item(&vault_id, &remote.id, d).ok());

        let winner: Option<(Item, bool)> = match (local_item, remote_item) {
            // Both deleted: nothing left to do.
            (None, None) => None,
            // We deleted, they edited: keep their edit (safer than losing data).
            (None, Some(theirs)) => Some((theirs, false)),
            // They deleted, we edited: resurrect our version.
            (Some(ours), None) => Some((ours, true)),
            (Some(ours), Some(theirs)) => {
                if ours.updated_at >= theirs.updated_at {
                    let mut merged = ours.clone();
                    merge_password_history(&mut merged, &theirs);
                    Some((merged, true))
                } else {
                    let mut merged = theirs.clone();
                    merge_password_history(&mut merged, &ours);
                    // Keep our version if the merge added history, so it is uploaded.
                    let changed = merged.password_history != theirs.password_history;
                    Some((merged, changed))
                }
            }
        };

        match winner {
            None => {
                self.profile_mut().items.retain(|i| i.id != remote.id);
            }
            Some((item, ours)) => {
                let data = if ours {
                    self.encrypt_item(&vault_id, &item).ok()
                } else {
                    remote.data.clone()
                };
                if let Some(rec) = self.profile_mut().item_mut(&remote.id) {
                    rec.data = data;
                    rec.revision = remote.revision;
                    rec.dirty = ours;
                }
            }
        }
    }
}

/// Add the other version's current and previous passwords to `item`'s history.
fn merge_password_history(item: &mut Item, other: &Item) {
    let current = item.password().unwrap_or("").to_string();
    let mut candidates: Vec<PasswordHistoryEntry> = Vec::new();
    if let Some(pw) = other.password() {
        candidates.push(PasswordHistoryEntry {
            value: pw.to_string(),
            changed_at: other.updated_at,
        });
    }
    candidates.extend(other.password_history.iter().cloned());
    for entry in candidates {
        if entry.value != current && !item.password_history.iter().any(|h| h.value == entry.value) {
            item.password_history.push(entry);
        }
    }
    item.password_history.sort_by_key(|h| std::cmp::Reverse(h.changed_at));
    item.password_history.truncate(MAX_PASSWORD_HISTORY);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Accepted, VaultSyncResult};
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
                self.vaults.push(VaultDto {
                    id: v.id.clone(),
                    owner_id: v.owner_id.clone(),
                    role: Role::Owner,
                    meta: v.meta.clone(),
                    wrapped_key: v.wrapped_key.clone(),
                    revision: 0,
                    member_count: 1,
                    created_at: v.created_at,
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
                for ch in vr.changes {
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
                    accepted.push(Accepted {
                        id: ch.id,
                        revision: vault.revision,
                    });
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
                });
            }
            SyncResponse {
                vaults: self.vaults.clone(),
                results,
            }
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
}
