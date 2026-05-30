//! Block put/get/has/delete operations.

use redb::ReadableTable;

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::tables::BLOCKS;

impl MemvaultStore {
    /// Store a raw block by CID bytes.
    ///
    /// Verifies the CID's embedded hash matches the data before writing.
    /// Supports all hash algorithms known to `multihash-codetable` (Blake3, SHA2-256, etc.).
    pub fn put_block(&self, cid: &[u8], data: &[u8]) -> Result<(), StoreError> {
        match memvault_core::verify_cid(cid, data) {
            Ok(true) => {}
            Ok(false) => {
                return Err(StoreError::CidMismatch {
                    expected: format!("hash of {} bytes", data.len()),
                    got: format!("CID {}", hex::encode(&cid[..cid.len().min(16)])),
                });
            }
            Err(_) => {
                // Unsupported hash algorithm — allow the write but log.
                tracing::debug!(
                    cid_len = cid.len(),
                    "put_block: CID uses unknown hash, skipping validation"
                );
            }
        }
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
        s.insert_envelope(b"cid_att", b"{}", &meta(vec![("sigchain", "node_att")]))
            .unwrap();
        s.insert_envelope(b"cid_rev", b"{}", &meta(vec![("sigchain", "node_rev")]))
            .unwrap();
        s.insert_envelope(b"cid_doc", b"{}", &meta(vec![("doc", "abcd")]))
            .unwrap();

        let removed = s.delete_sigchain_blocks().unwrap();
        assert_eq!(removed, 2, "both sigchain blocks removed");

        assert!(s.get_block(b"cid_att").unwrap().is_none());
        assert!(s.get_block(b"cid_rev").unwrap().is_none());
        assert!(
            s.get_block(b"cid_doc").unwrap().is_some(),
            "non-sigchain block preserved"
        );

        // Idempotent: a second run removes nothing.
        assert_eq!(s.delete_sigchain_blocks().unwrap(), 0);
    }
}
