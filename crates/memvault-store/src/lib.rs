//! `memvault-store` — Persistent storage layer for memvault using redb.
//!
//! Implements block storage with indexed queries over signed envelopes.

use std::path::Path;

pub mod audit_index;
pub mod blockstore;
pub mod consumed_tokens;
pub mod encryption;
pub mod error;
pub mod heads;
pub mod insert;
pub mod keys;
pub mod query;
pub mod retracted;
pub mod rotation_state;
pub mod tables;

pub use error::StoreError;
pub use insert::EnvelopeMeta;

/// The main memvault persistent store backed by redb.
pub struct MemvaultStore {
    db: redb::Database,
}

impl MemvaultStore {
    /// Open (or create) a memvault store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = redb::Database::create(path)?;

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
            txn.open_table(tables::CLUSTER_DEFAULT_BUCKET)?;
            // Share tables (B5)
            txn.open_table(tables::SHARE_INBOX)?;
            txn.open_table(tables::SHARE_OUTBOX)?;
            txn.open_table(tables::BUCKET_TRUST)?;
            // Identity table
            txn.open_table(tables::LOCAL_IDENTITY)?;
        }
        txn.commit()?;

        Ok(Self { db })
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
            };
            store.insert_envelope(cid.as_bytes(), b"data", &meta).unwrap();
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

        let count = store.record_token_consumption(token, b"consumer-a", 1000).unwrap();
        assert_eq!(count, 1);

        let count = store.record_token_consumption(token, b"consumer-b", 2000).unwrap();
        assert_eq!(count, 2);

        assert_eq!(store.get_token_consumption_count(token).unwrap(), 2);
    }

    #[test]
    fn revocation_tracking() {
        let (_dir, store) = temp_store();
        let target = b"target-cid";

        assert!(!store.is_revoked(target).unwrap());
        store.record_revocation(target, b"revocation-block").unwrap();
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
        };
        store.insert_envelope(child_cid, b"child-data", &meta).unwrap();

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
            };
            store.insert_envelope(cid.as_bytes(), b"data", &meta).unwrap();
        }

        let results = store.query_by_tag("app", "event", 0, 3).unwrap();
        assert_eq!(results.len(), 3);
    }
}
