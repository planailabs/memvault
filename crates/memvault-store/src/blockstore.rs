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
}
