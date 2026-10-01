//! Block put/get/has/delete operations.

use redb::ReadableTable;

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::tables::{BLOCKS, PINS, SCRATCH};

/// `Ok` iff `cid` is exactly one parseable CID whose multihash matches
/// `data`. Every write into BLOCKS goes through this.
pub(crate) fn check_cid(cid: &[u8], data: &[u8]) -> Result<(), StoreError> {
    match memvault_core::verify_cid(cid, data) {
        Ok(true) => Ok(()),
        Ok(false) => Err(StoreError::CidMismatch {
            expected: format!("hash of {} bytes", data.len()),
            got: format!("CID {}", hex::encode(&cid[..cid.len().min(16)])),
        }),
        Err(e) => Err(StoreError::CidMismatch {
            expected: "a content-addressed CID".to_string(),
            got: format!("{} ({e})", hex::encode(&cid[..cid.len().min(16)])),
        }),
    }
}

impl MemvaultStore {
    /// Store a raw block by CID bytes.
    ///
    /// Verifies the CID's embedded hash matches the data before writing.
    /// Supports all hash algorithms known to `multihash-codetable` (Blake3,
    /// SHA2-256, etc.). A key that is not exactly one parseable CID, or
    /// whose hash this build cannot check, is rejected: BLOCKS holds
    /// content-addressed blocks only (pins and probes live in their own
    /// tables).
    pub fn put_block(&self, cid: &[u8], data: &[u8]) -> Result<(), StoreError> {
        check_cid(cid, data)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BLOCKS)?;
            table.insert(cid, data)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Retrieve a block by CID bytes.
    pub fn get_block(&self, cid: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOCKS)?;
        Ok(table.get(cid)?.map(|v| v.value().to_vec()))
    }

    /// Check if a block exists.
    pub fn has_block(&self, cid: &[u8]) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOCKS)?;
        Ok(table.get(cid)?.is_some())
    }

    /// Iterate all blocks, returning (cid_bytes, block_bytes) pairs.
    pub fn iter_blocks(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOCKS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(out)
    }

    pub fn delete_block(&self, cid: &[u8]) -> Result<bool, StoreError> {
        let txn = self.db.begin_write()?;
        let removed = {
            let mut table = txn.open_table(BLOCKS)?;
            table.remove(cid)?.is_some()
        };
        txn.commit()?;
        Ok(removed)
    }

    // ── Pins (local replication policy; not blocks) ────────────────────

    /// Record a pin for `manifest_cid` with an opaque `reason` value.
    pub fn set_pin(&self, manifest_cid: &[u8], reason: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PINS)?;
            table.insert(manifest_cid, reason)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Remove a pin. Returns whether one existed.
    pub fn remove_pin(&self, manifest_cid: &[u8]) -> Result<bool, StoreError> {
        let txn = self.db.begin_write()?;
        let removed = {
            let mut table = txn.open_table(PINS)?;
            table.remove(manifest_cid)?.is_some()
        };
        txn.commit()?;
        Ok(removed)
    }

    /// The pin reason recorded for `manifest_cid`, if pinned.
    pub fn get_pin(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PINS)?;
        Ok(table.get(manifest_cid)?.map(|v| v.value().to_vec()))
    }

    /// Every recorded pin as `(manifest_cid, reason)`.
    pub fn list_pins(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PINS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(out)
    }

    /// Move pin rows written by older builds into BLOCKS (under the
    /// non-CID key `__pin:<manifest_cid>`) into the PINS table. Runs on
    /// every open; a no-op once migrated. Returns the number moved.
    pub(crate) fn migrate_legacy_pins(db: &redb::Database) -> Result<usize, StoreError> {
        const LEGACY_PIN_PREFIX: &[u8] = b"__pin:";
        let rows: Vec<(Vec<u8>, Vec<u8>)> = {
            let txn = db.begin_read()?;
            let table = txn.open_table(BLOCKS)?;
            let mut out = Vec::new();
            for entry in table.range(LEGACY_PIN_PREFIX..)? {
                let (k, v) = entry?;
                if !k.value().starts_with(LEGACY_PIN_PREFIX) {
                    break;
                }
                out.push((k.value().to_vec(), v.value().to_vec()));
            }
            out
        };
        if rows.is_empty() {
            return Ok(0);
        }
        let txn = db.begin_write()?;
        {
            let mut blocks = txn.open_table(BLOCKS)?;
            let mut pins = txn.open_table(PINS)?;
            for (key, reason) in &rows {
                pins.insert(&key[LEGACY_PIN_PREFIX.len()..], reason.as_slice())?;
                blocks.remove(key.as_slice())?;
            }
        }
        txn.commit()?;
        tracing::info!(moved = rows.len(), "moved legacy pin rows out of BLOCKS");
        Ok(rows.len())
    }

    /// Health probe: write, read back and delete a row in a scratch table
    /// (never BLOCKS, which only holds content-addressed blocks).
    pub fn probe_roundtrip(&self) -> Result<(), StoreError> {
        const KEY: &[u8] = b"probe";
        const VALUE: &[u8] = b"ok";
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SCRATCH)?;
            table.insert(KEY, VALUE)?;
        }
        txn.commit()?;
        let read = {
            let txn = self.db.begin_read()?;
            let table = txn.open_table(SCRATCH)?;
            table.get(KEY)?.map(|v| v.value().to_vec())
        };
        if read.as_deref() != Some(VALUE) {
            return Err(StoreError::Other("probe read-back mismatch".into()));
        }
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SCRATCH)?;
            table.remove(KEY)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Delete every block tagged under the `sigchain` scope (node/agent
    /// attestations + revocations — the cluster membership chain). Returns the
    /// number of blocks removed. This only removes the BLOCKS rows; callers
    /// should follow with `clear_secondary_indexes` + a reindex of the
    /// remaining blocks to drop the now-dangling secondary-index entries.
    ///
    /// Destructive: this "unclusters" the node — afterwards it holds no
    /// membership attestations.
    pub fn delete_sigchain_blocks(&self) -> Result<usize, StoreError> {
        let labels = self.query_unique_labels("sigchain", usize::MAX)?;
        let mut cids: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for label in &labels {
            for cid in self.query_by_tag("sigchain", label, 0, usize::MAX)? {
                cids.insert(cid);
            }
        }
        let mut count = 0usize;
        for cid in &cids {
            if self.delete_block(cid)? {
                count += 1;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod uncluster_tests {
    use crate::MemvaultStore;
    use crate::insert::EnvelopeMeta;
    use tempfile::TempDir;

    fn meta(tags: Vec<(&str, &str)>) -> EnvelopeMeta {
        EnvelopeMeta {
            author: vec![1, 2, 3],
            tags: tags
                .into_iter()
                .map(|(s, l)| (s.to_string(), l.to_string()))
                .collect(),
            wall_ns: 100,
            ..Default::default()
        }
    }

    #[test]
    fn delete_sigchain_blocks_removes_only_sigchain() {
        let dir = TempDir::new().unwrap();
        let s = MemvaultStore::open(dir.path().join("db.redb")).unwrap();

        // Two sigchain blocks + one ordinary doc block.
        let cid = |d: &[u8]| memvault_core::cid_from_bytes(d).to_bytes();
        s.insert_envelope(&cid(b"att"), b"att", &meta(vec![("sigchain", "node_att")]))
            .unwrap();
        s.insert_envelope(&cid(b"rev"), b"rev", &meta(vec![("sigchain", "node_rev")]))
            .unwrap();
        s.insert_envelope(&cid(b"doc"), b"doc", &meta(vec![("doc", "abcd")]))
            .unwrap();

        let removed = s.delete_sigchain_blocks().unwrap();
        assert_eq!(removed, 2, "both sigchain blocks removed");

        assert!(s.get_block(&cid(b"att")).unwrap().is_none());
        assert!(s.get_block(&cid(b"rev")).unwrap().is_none());
        assert!(
            s.get_block(&cid(b"doc")).unwrap().is_some(),
            "non-sigchain block preserved"
        );

        // Idempotent: a second run removes nothing.
        assert_eq!(s.delete_sigchain_blocks().unwrap(), 0);
    }
}
