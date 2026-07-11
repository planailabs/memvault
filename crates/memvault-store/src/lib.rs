//! `memvault-store` — Persistent storage layer for memvault using redb.
//!
//! Implements block storage with indexed queries over signed envelopes.

use std::path::{Path, PathBuf};

pub mod audit_index;
pub mod blockstore;
pub mod consumed_tokens;
pub mod encryption;
pub mod envelope_view;
pub mod error;
pub mod heads;
pub mod insert;
pub mod keys;
pub mod query;
pub mod retracted;
pub mod rotation_state;
pub mod scope_members;
pub mod tables;

pub use envelope_view::EnvelopeView;
pub use error::StoreError;
pub use insert::{EnvelopeMeta, IngestMeta, deserialize_block, deserialize_block_as};

/// Callback invoked after a block is indexed (every block enters via the
/// single `ingest_block` path; `reindex_block` re-fires it on rebuild).
/// Arguments are `(scope, label, cid)` — e.g. `("sigchain", "node_att", &cid)`.
/// Called for **every** tag found on the block; receivers filter.
///
/// Set via [`MemvaultStore::set_index_notifier`]. The owner is responsible
/// for any cross-crate event publishing — the store itself stays generic.
pub type IndexNotifier = std::sync::Arc<dyn Fn(&str, &str, &[u8]) + Send + Sync>;

/// The main memvault persistent store backed by redb.
pub struct MemvaultStore {
    db: redb::Database,
    /// Filesystem path of the redb database. Retained so upper layers can
    /// site sibling state (e.g. the keystore at `<dir>/identity/`) next to
    /// the blockstore without threading a separate data-dir everywhere.
    path: PathBuf,
    pub(crate) index_notifier: std::sync::OnceLock<IndexNotifier>,
}

impl MemvaultStore {
    /// Open (or create) a memvault store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let db = redb::Database::create(&path)?;

        // Ensure all tables exist by opening them in a write transaction.
        let txn = db.begin_write()?;
        {
            txn.open_table(tables::BLOCKS)?;
            txn.open_table(tables::BY_TAG)?;
            txn.open_table(tables::BY_AUTHOR)?;
            txn.open_table(tables::BY_TIME)?;
            txn.open_table(tables::BY_CAUSAL)?;
            txn.open_table(tables::BY_PROVENANCE)?;
            txn.open_table(tables::EDGES)?;
            txn.open_table(tables::HEADS)?;
            txn.open_table(tables::REVOCATIONS)?;
            txn.open_table(tables::RETRACTED)?;
            txn.open_table(tables::CLUSTER_ORIGIN)?;
            txn.open_table(tables::CONSUMED_TOKENS)?;
            txn.open_table(tables::ROTATIONS)?;
            // Bucket tables (B1)
            txn.open_table(tables::BY_BUCKET)?;
            txn.open_table(tables::BUCKETS)?;
            txn.open_table(tables::BUCKET_CLUSTER)?;
            // Share tables (B5)
            txn.open_table(tables::SHARE_INBOX)?;
            txn.open_table(tables::SHARE_OUTBOX)?;
            txn.open_table(tables::BUCKET_TRUST)?;
            // Identity table
            txn.open_table(tables::LOCAL_IDENTITY)?;
            // Scoped-index member-sets (scoped-indexes Phase 2)
            txn.open_table(tables::SCOPE_MEMBERS)?;
            txn.open_table(tables::SCOPE_REGISTRY)?;
            // VFS root derived index
            txn.open_table(tables::VFS_ROOT)?;
        }
        txn.commit()?;

        Ok(Self {
            db,
            path,
            index_notifier: std::sync::OnceLock::new(),
        })
    }

    /// Filesystem path of the backing redb database.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Directory containing the store (parent of [`Self::path`]). Sibling
    /// state like the keystore lives under here.
    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }

    /// Register a callback to be invoked every time a block is indexed
    /// (fresh insertion or re-index after sync). Write-once.
    ///
    /// Used by upper layers (e.g. the sigchain watcher) to react to new
    /// blocks without depending on the sync code path directly. The store
    /// itself stays generic — it knows nothing about the event bus.
    pub fn set_index_notifier(&self, notifier: IndexNotifier) {
        let _ = self.index_notifier.set(notifier);
    }

    /// Get the stored local peer ID, if any.
    pub fn get_local_peer_id(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(tables::LOCAL_IDENTITY)?;
        Ok(table.get("peer_id")?.map(|v| v.value().to_vec()))
    }

    /// Store the local peer ID. Returns an error if a different peer_id is already stored.
    pub fn set_local_peer_id(&self, peer_id: &[u8]) -> Result<(), StoreError> {
        // Check for mismatch
        if let Some(existing) = self.get_local_peer_id()? {
            if existing != peer_id {
                return Err(StoreError::Other(format!(
                    "peer_id mismatch: store has {}, swarm has {}",
                    hex::encode(&existing),
                    hex::encode(peer_id),
                )));
            }
            return Ok(()); // already stored and matches
        }
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(tables::LOCAL_IDENTITY)?;
            table.insert("peer_id", peer_id)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Get the stored cluster ID, if any.
    pub fn get_local_cluster_id(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(tables::LOCAL_IDENTITY)?;
        Ok(table.get("cluster_id")?.map(|v| v.value().to_vec()))
    }

    /// Store the local cluster ID.
    pub fn set_local_cluster_id(&self, cluster_id: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(tables::LOCAL_IDENTITY)?;
            table.insert("cluster_id", cluster_id)?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── Schema version ─────────────────────────────────────────────────

    /// Current schema version.  Returns 0 for stores that pre-date the
    /// migration system.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(tables::LOCAL_IDENTITY)?;
        match table.get("schema_version")? {
            Some(v) => {
                let bytes = v.value();
                if bytes.len() >= 4 {
                    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                } else {
                    Ok(0)
                }
            }
            None => Ok(0),
        }
    }

    /// Set the schema version.  Called after a migration completes
    /// successfully so the migration is not re-run.
    pub fn set_schema_version(&self, version: u32) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(tables::LOCAL_IDENTITY)?;
            table.insert("schema_version", version.to_le_bytes().as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, MemvaultStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let store = MemvaultStore::open(&path).unwrap();
        (dir, store)
    }

    #[test]
    fn block_roundtrip() {
        let (_dir, store) = temp_store();
        let cid = b"cid-001";
        let data = b"hello block";

        assert!(!store.has_block(cid).unwrap());
        store.put_block(cid, data).unwrap();
        assert!(store.has_block(cid).unwrap());
        assert_eq!(store.get_block(cid).unwrap().unwrap(), data);
    }

    #[test]
    fn block_delete() {
        let (_dir, store) = temp_store();
        let cid = b"cid-del";
        store.put_block(cid, b"data").unwrap();
        assert!(store.delete_block(cid).unwrap());
        assert!(!store.has_block(cid).unwrap());
        assert!(!store.delete_block(cid).unwrap());
    }

    #[test]
    fn insert_and_query_by_tag() {
        let (_dir, store) = temp_store();
        let cid = b"cid-tag-1";
        let meta = EnvelopeMeta {
            author: b"peer-a".to_vec(),
            tags: vec![("system".into(), "log".into())],
            wall_ns: 1000,
            causal: vec![],
            provenance: vec![],
            cluster_id: None,
            bucket_id: None,
            ..Default::default()
        };
        store.insert_envelope(cid, b"envelope-data", &meta).unwrap();

        let results = store.query_by_tag("system", "log", 0, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], cid);

        // Query with after_ns > wall_ns should return empty
        let results = store.query_by_tag("system", "log", 2000, 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn insert_and_query_by_author() {
        let (_dir, store) = temp_store();
        let cid = b"cid-author-1";
        let author = b"peer-b";
        let meta = EnvelopeMeta {
            author: author.to_vec(),
            tags: vec![],
            wall_ns: 500,
            causal: vec![],
            provenance: vec![],
            cluster_id: None,
            bucket_id: None,
            ..Default::default()
        };
        store.insert_envelope(cid, b"data", &meta).unwrap();

        let results = store.query_by_author(author, 0, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], cid);
    }

    #[test]
    fn insert_and_query_by_time() {
        let (_dir, store) = temp_store();

        for i in 0..5u64 {
            let cid = format!("cid-time-{i}");
            let meta = EnvelopeMeta {
                author: b"peer".to_vec(),
                tags: vec![],
                wall_ns: (i + 1) * 100,
                causal: vec![],
                provenance: vec![],
                cluster_id: None,
                bucket_id: None,
                ..Default::default()
            };
            store
                .insert_envelope(cid.as_bytes(), b"data", &meta)
                .unwrap();
        }

        // Query range [200, 400)
        let results = store.query_by_time(200, 400, 10).unwrap();
        assert_eq!(results.len(), 2); // wall_ns 200 and 300
    }

    #[test]
    fn token_consumption() {
        let (_dir, store) = temp_store();
        let token = b"token-cid-1";

        assert_eq!(store.get_token_consumption_count(token).unwrap(), 0);

        let count = store
            .record_token_consumption(token, b"consumer-a", 1000)
            .unwrap();
        assert_eq!(count, 1);

        let count = store
            .record_token_consumption(token, b"consumer-b", 2000)
            .unwrap();
        assert_eq!(count, 2);

        assert_eq!(store.get_token_consumption_count(token).unwrap(), 2);
    }

    #[test]
    fn revocation_tracking() {
        let (_dir, store) = temp_store();
        let target = b"target-cid";

        assert!(!store.is_revoked(target).unwrap());
        store
            .record_revocation(target, b"revocation-block")
            .unwrap();
        assert!(store.is_revoked(target).unwrap());
    }

    #[test]
    fn retraction_tracking() {
        let (_dir, store) = temp_store();
        let cid = b"retracted-cid";

        assert!(!store.is_retracted(cid).unwrap());
        store.record_retraction(cid, b"tombstone-cid").unwrap();
        assert!(store.is_retracted(cid).unwrap());
    }

    #[test]
    fn heads_tracking() {
        let (_dir, store) = temp_store();
        let doc = b"doc-1";
        let peer = b"peer-1";

        assert!(store.get_head(doc, peer).unwrap().is_none());
        store.set_head(doc, peer, b"head-cid-1").unwrap();
        assert_eq!(store.get_head(doc, peer).unwrap().unwrap(), b"head-cid-1");

        // Update head
        store.set_head(doc, peer, b"head-cid-2").unwrap();
        assert_eq!(store.get_head(doc, peer).unwrap().unwrap(), b"head-cid-2");
    }

    #[test]
    fn rotation_state() {
        let (_dir, store) = temp_store();

        store.store_rotation(b"rot-1", 100, b"block-cid-a").unwrap();
        store.store_rotation(b"rot-1", 200, b"block-cid-b").unwrap();
        store.store_rotation(b"rot-2", 150, b"block-cid-c").unwrap();

        let all = store.get_all_rotations().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn insert_envelope_with_causal_and_provenance() {
        let (_dir, store) = temp_store();
        let parent_cid = b"parent-cid";
        let child_cid = b"child-cid";

        let meta = EnvelopeMeta {
            author: b"peer".to_vec(),
            tags: vec![("ns".into(), "test".into())],
            wall_ns: 1000,
            causal: vec![parent_cid.to_vec()],
            provenance: vec![parent_cid.to_vec()],
            cluster_id: Some(b"cluster-1".to_vec()),
            bucket_id: None,
            ..Default::default()
        };
        store
            .insert_envelope(child_cid, b"child-data", &meta)
            .unwrap();

        // Verify the block was stored
        assert!(store.has_block(child_cid).unwrap());
        assert_eq!(store.get_block(child_cid).unwrap().unwrap(), b"child-data");
    }

    #[test]
    fn query_by_tag_with_limit() {
        let (_dir, store) = temp_store();

        for i in 0..10u64 {
            let cid = format!("cid-limit-{i}");
            let meta = EnvelopeMeta {
                author: b"peer".to_vec(),
                tags: vec![("app".into(), "event".into())],
                wall_ns: (i + 1) * 10,
                causal: vec![],
                provenance: vec![],
                cluster_id: None,
                bucket_id: None,
                ..Default::default()
            };
            store
                .insert_envelope(cid.as_bytes(), b"data", &meta)
                .unwrap();
        }

        let results = store.query_by_tag("app", "event", 0, 3).unwrap();
        assert_eq!(results.len(), 3);
    }
}
