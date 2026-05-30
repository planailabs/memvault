//! Materialized scope member-sets (scoped-indexes Phase 2).
//!
//! Each *scope* is a partition coordinate identified by an opaque, fixed-width
//! `scope_id` digest (derived by the caller): per-bucket, per-view, or
//! per-view×bucket. A scope holds two logical member-sets — active and
//! retracted — distinguished by a byte in each member's value. Counts are
//! maintained eagerly in [`SCOPE_REGISTRY`] so listing/counting is cheap and
//! never requires a full scan.
//!
//! The store treats `scope_id` and `node_id` as opaque; the derivation of
//! `scope_id` and the decision of which scopes a node belongs to live in
//! `memvault-api` (which knows view tag-sets and node identity).

use redb::ReadableTable;

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::keys;
use crate::tables::{SCOPE_MEMBERS, SCOPE_REGISTRY};

/// Partition kind stored in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    Bucket = 0,
    View = 1,
    ViewBucket = 2,
}

impl ScopeKind {
    pub fn from_u8(b: u8) -> ScopeKind {
        match b {
            1 => ScopeKind::View,
            2 => ScopeKind::ViewBucket,
            _ => ScopeKind::Bucket,
        }
    }
}

/// A registry entry describing one materialized scope partition.
#[derive(Debug, Clone)]
pub struct ScopeRegistryEntry {
    pub kind: ScopeKind,
    pub active_count: u64,
    pub retracted_count: u64,
    pub built_ns: u64,
    /// View block CID this partition is scoped to (empty if none).
    pub view_cid: Vec<u8>,
    /// Bucket id this partition is scoped to (empty if none).
    pub bucket_id: Vec<u8>,
}

impl MemvaultStore {
    /// Look up a scope's registry entry, if it has been registered/built.
    pub fn scope_registry_get(
        &self,
        scope_id: &[u8],
    ) -> Result<Option<ScopeRegistryEntry>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SCOPE_REGISTRY)?;
        let Some(v) = table.get(scope_id)? else {
            return Ok(None);
        };
        let (kind, active, retracted, built_ns, view_cid, bucket_id) =
            keys::unpack_scope_registry_value(v.value())?;
        Ok(Some(ScopeRegistryEntry {
            kind: ScopeKind::from_u8(kind),
            active_count: active,
            retracted_count: retracted,
            built_ns,
            view_cid,
            bucket_id,
        }))
    }

    /// True if a scope partition has been registered (built at least once).
    pub fn scope_is_registered(&self, scope_id: &[u8]) -> Result<bool, StoreError> {
        Ok(self.scope_registry_get(scope_id)?.is_some())
    }

    /// Register (or re-register) a scope partition's metadata. Does not touch
    /// member rows or counts that already exist — counts are recomputed by the
    /// member ops. Use [`scope_register_built`] to stamp counts after a build.
    pub fn scope_register(
        &self,
        scope_id: &[u8],
        kind: ScopeKind,
        view_cid: &[u8],
        bucket_id: &[u8],
        built_ns: u64,
    ) -> Result<(), StoreError> {
        let existing = self.scope_registry_get(scope_id)?;
        let (active, retracted) = existing
            .map(|e| (e.active_count, e.retracted_count))
            .unwrap_or((0, 0));
        let val = keys::pack_scope_registry_value(
            kind as u8, active, retracted, built_ns, view_cid, bucket_id,
        );
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SCOPE_REGISTRY)?;
            table.insert(scope_id, val.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// List every registered scope partition. Used at ingest time to know which
    /// view / view×bucket partitions need live updates.
    pub fn scope_registry_list(&self) -> Result<Vec<(Vec<u8>, ScopeRegistryEntry)>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SCOPE_REGISTRY)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            let (kind, active, retracted, built_ns, view_cid, bucket_id) =
                keys::unpack_scope_registry_value(v.value())?;
            out.push((
                k.value().to_vec(),
                ScopeRegistryEntry {
                    kind: ScopeKind::from_u8(kind),
                    active_count: active,
                    retracted_count: retracted,
                    built_ns,
                    view_cid,
                    bucket_id,
                },
            ));
        }
        Ok(out)
    }

    /// Insert or update a node's membership in a scope. Idempotent: if the node
    /// is already present with the same retracted-state the counts are left
    /// unchanged; if its retracted-state differs, the counters are adjusted.
    ///
    /// Registers the scope on first write if not already registered (as a bare
    /// entry — `kind`/coords default to Bucket/empty; callers that care set
    /// them via [`scope_register`]).
    pub fn scope_member_upsert(
        &self,
        scope_id: &[u8],
        node_id: &str,
        retracted: bool,
        wall_ns: u64,
    ) -> Result<(), StoreError> {
        let key = keys::pack_scope_member_key(scope_id, node_id);
        let txn = self.db.begin_write()?;
        let mut d_active: i64 = 0;
        let mut d_retracted: i64 = 0;
        {
            let mut members = txn.open_table(SCOPE_MEMBERS)?;
            let prev = members.get(key.as_slice())?.map(|v| {
                keys::unpack_scope_member_value(v.value()).unwrap_or((false, 0))
            });
            match prev {
                None => {
                    if retracted {
                        d_retracted += 1;
                    } else {
                        d_active += 1;
                    }
                }
                Some((was_retracted, _)) if was_retracted != retracted => {
                    if retracted {
                        d_retracted += 1;
                        d_active -= 1;
                    } else {
                        d_active += 1;
                        d_retracted -= 1;
                    }
                }
                Some(_) => {}
            }
            let val = keys::pack_scope_member_value(retracted, wall_ns);
            members.insert(key.as_slice(), val.as_slice())?;
        }
        Self::adjust_registry_counts(&txn, scope_id, d_active, d_retracted)?;
        txn.commit()?;
        Ok(())
    }

    /// Remove a node from a scope partition entirely (both partitions).
    pub fn scope_member_remove(
        &self,
        scope_id: &[u8],
        node_id: &str,
    ) -> Result<(), StoreError> {
        let key = keys::pack_scope_member_key(scope_id, node_id);
        let txn = self.db.begin_write()?;
        let mut d_active: i64 = 0;
        let mut d_retracted: i64 = 0;
        {
            let mut members = txn.open_table(SCOPE_MEMBERS)?;
            let prev = members
                .get(key.as_slice())?
                .map(|v| keys::unpack_scope_member_value(v.value()).unwrap_or((false, 0)));
            if let Some((was_retracted, _)) = prev {
                if was_retracted {
                    d_retracted -= 1;
                } else {
                    d_active -= 1;
                }
                members.remove(key.as_slice())?;
            }
        }
        if d_active != 0 || d_retracted != 0 {
            Self::adjust_registry_counts(&txn, scope_id, d_active, d_retracted)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Flip a node's retracted-state within a scope, if present. No-op if the
    /// node is not a member.
    pub fn scope_member_set_retracted(
        &self,
        scope_id: &[u8],
        node_id: &str,
        retracted: bool,
    ) -> Result<(), StoreError> {
        let key = keys::pack_scope_member_key(scope_id, node_id);
        let txn = self.db.begin_write()?;
        let mut d_active: i64 = 0;
        let mut d_retracted: i64 = 0;
        let mut changed = false;
        {
            let mut members = txn.open_table(SCOPE_MEMBERS)?;
            let prev = members
                .get(key.as_slice())?
                .map(|v| keys::unpack_scope_member_value(v.value()).unwrap_or((false, 0)));
            if let Some((was_retracted, wall_ns)) = prev {
                if was_retracted != retracted {
                    if retracted {
                        d_retracted += 1;
                        d_active -= 1;
                    } else {
                        d_active += 1;
                        d_retracted -= 1;
                    }
                    let val = keys::pack_scope_member_value(retracted, wall_ns);
                    members.insert(key.as_slice(), val.as_slice())?;
                    changed = true;
                }
            }
        }
        if changed {
            Self::adjust_registry_counts(&txn, scope_id, d_active, d_retracted)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// List members of a scope as `(node_id, wall_ns)`, filtered by the
    /// active/retracted flags. Unordered (caller sorts; the multi-bucket merge
    /// sorts by `wall_ns` anyway). Pass `limit = 0` for no limit.
    pub fn scope_members(
        &self,
        scope_id: &[u8],
        include_active: bool,
        include_retracted: bool,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SCOPE_MEMBERS)?;
        let start = keys::pack_scope_member_prefix(scope_id);
        let end = keys::pack_scope_member_prefix_end(scope_id);
        let mut out = Vec::new();
        for entry in table.range(start.as_slice()..end.as_slice())? {
            let (k, v) = entry?;
            let (retracted, wall_ns) = keys::unpack_scope_member_value(v.value())?;
            if retracted && !include_retracted {
                continue;
            }
            if !retracted && !include_active {
                continue;
            }
            let nid = keys::unpack_scope_member_node_id(k.value(), scope_id.len())?;
            let node_id = String::from_utf8_lossy(nid).into_owned();
            out.push((node_id, wall_ns));
            if limit != 0 && out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Drop a whole scope partition: all member rows + registry entry.
    pub fn scope_drop(&self, scope_id: &[u8]) -> Result<(), StoreError> {
        let start = keys::pack_scope_member_prefix(scope_id);
        let end = keys::pack_scope_member_prefix_end(scope_id);
        let txn = self.db.begin_write()?;
        {
            let mut members = txn.open_table(SCOPE_MEMBERS)?;
            let mut to_delete: Vec<Vec<u8>> = Vec::new();
            for entry in members.range(start.as_slice()..end.as_slice())? {
                let (k, _) = entry?;
                to_delete.push(k.value().to_vec());
            }
            for k in to_delete {
                members.remove(k.as_slice())?;
            }
            let mut reg = txn.open_table(SCOPE_REGISTRY)?;
            reg.remove(scope_id)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Clear all scope member-sets and the registry. Called on a full index
    /// rebuild so stale partitions are discarded and rebuilt lazily.
    pub fn scope_clear_all(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut members = txn.open_table(SCOPE_MEMBERS)?;
            while members.pop_first()?.is_some() {}
            let mut reg = txn.open_table(SCOPE_REGISTRY)?;
            while reg.pop_first()?.is_some() {}
        }
        txn.commit()?;
        Ok(())
    }

    /// Apply signed deltas to a scope's registry counters within an open write
    /// txn. Creates a bare registry entry (kind=Bucket, empty coords) if none
    /// exists yet. Counts saturate at zero.
    fn adjust_registry_counts(
        txn: &redb::WriteTransaction,
        scope_id: &[u8],
        d_active: i64,
        d_retracted: i64,
    ) -> Result<(), StoreError> {
        let mut reg = txn.open_table(SCOPE_REGISTRY)?;
        let (kind, mut active, mut retracted, built_ns, view_cid, bucket_id) =
            match reg.get(scope_id)? {
                Some(v) => keys::unpack_scope_registry_value(v.value())?,
                None => (ScopeKind::Bucket as u8, 0, 0, 0, Vec::new(), Vec::new()),
            };
        active = apply_delta(active, d_active);
        retracted = apply_delta(retracted, d_retracted);
        let val = keys::pack_scope_registry_value(
            kind, active, retracted, built_ns, &view_cid, &bucket_id,
        );
        reg.insert(scope_id, val.as_slice())?;
        Ok(())
    }
}

fn apply_delta(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub((-delta) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (TempDir, MemvaultStore) {
        let dir = TempDir::new().unwrap();
        let s = MemvaultStore::open(dir.path().join("db.redb")).unwrap();
        (dir, s)
    }

    const SID: &[u8] = b"scopeid_fixed_width_0000000000000"; // 33 bytes, fixed

    #[test]
    fn upsert_list_and_counts() {
        let (_d, s) = store();
        s.scope_member_upsert(SID, "doc:aa", false, 100).unwrap();
        s.scope_member_upsert(SID, "doc:bb", false, 200).unwrap();
        s.scope_member_upsert(SID, "doc:cc", true, 300).unwrap();

        let reg = s.scope_registry_get(SID).unwrap().unwrap();
        assert_eq!(reg.active_count, 2);
        assert_eq!(reg.retracted_count, 1);

        let active = s.scope_members(SID, true, false, 0).unwrap();
        assert_eq!(active.len(), 2);
        let all = s.scope_members(SID, true, true, 0).unwrap();
        assert_eq!(all.len(), 3);
        let retr = s.scope_members(SID, false, true, 0).unwrap();
        assert_eq!(retr.len(), 1);
        assert_eq!(retr[0].0, "doc:cc");
    }

    #[test]
    fn upsert_is_idempotent() {
        let (_d, s) = store();
        s.scope_member_upsert(SID, "doc:aa", false, 100).unwrap();
        s.scope_member_upsert(SID, "doc:aa", false, 150).unwrap();
        let reg = s.scope_registry_get(SID).unwrap().unwrap();
        assert_eq!(reg.active_count, 1);
        assert_eq!(reg.retracted_count, 0);
    }

    #[test]
    fn flip_retracted_moves_between_partitions() {
        let (_d, s) = store();
        s.scope_member_upsert(SID, "doc:aa", false, 100).unwrap();
        s.scope_member_set_retracted(SID, "doc:aa", true).unwrap();
        let reg = s.scope_registry_get(SID).unwrap().unwrap();
        assert_eq!(reg.active_count, 0);
        assert_eq!(reg.retracted_count, 1);
        assert_eq!(s.scope_members(SID, true, false, 0).unwrap().len(), 0);
        assert_eq!(s.scope_members(SID, false, true, 0).unwrap().len(), 1);

        // flip back
        s.scope_member_set_retracted(SID, "doc:aa", false).unwrap();
        let reg = s.scope_registry_get(SID).unwrap().unwrap();
        assert_eq!(reg.active_count, 1);
        assert_eq!(reg.retracted_count, 0);
    }

    #[test]
    fn remove_decrements() {
        let (_d, s) = store();
        s.scope_member_upsert(SID, "doc:aa", false, 100).unwrap();
        s.scope_member_upsert(SID, "doc:bb", true, 200).unwrap();
        s.scope_member_remove(SID, "doc:aa").unwrap();
        let reg = s.scope_registry_get(SID).unwrap().unwrap();
        assert_eq!(reg.active_count, 0);
        assert_eq!(reg.retracted_count, 1);
        s.scope_member_remove(SID, "doc:bb").unwrap();
        let reg = s.scope_registry_get(SID).unwrap().unwrap();
        assert_eq!(reg.active_count, 0);
        assert_eq!(reg.retracted_count, 0);
    }

    #[test]
    fn register_and_list_and_drop() {
        let (_d, s) = store();
        let bucket = [7u8; 32];
        s.scope_register(SID, ScopeKind::ViewBucket, b"viewcid", &bucket, 42)
            .unwrap();
        s.scope_member_upsert(SID, "doc:aa", false, 100).unwrap();
        let listed = s.scope_registry_list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1.kind, ScopeKind::ViewBucket);
        assert_eq!(listed[0].1.built_ns, 42);
        assert_eq!(listed[0].1.active_count, 1);

        s.scope_drop(SID).unwrap();
        assert!(s.scope_registry_get(SID).unwrap().is_none());
        assert_eq!(s.scope_members(SID, true, true, 0).unwrap().len(), 0);
    }

    #[test]
    fn two_scopes_are_isolated() {
        let (_d, s) = store();
        let sid_a: &[u8] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 33
        let sid_b: &[u8] = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 33
        s.scope_member_upsert(sid_a, "doc:1", false, 1).unwrap();
        s.scope_member_upsert(sid_b, "doc:2", false, 2).unwrap();
        assert_eq!(s.scope_members(sid_a, true, true, 0).unwrap().len(), 1);
        assert_eq!(s.scope_members(sid_b, true, true, 0).unwrap().len(), 1);
        assert_eq!(s.scope_members(sid_a, true, true, 0).unwrap()[0].0, "doc:1");
    }
}
