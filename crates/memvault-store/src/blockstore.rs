//! Block put/get/has/delete operations.

use crate::error::StoreError;
use crate::tables::BLOCKS;
use crate::MemvaultStore;

impl MemvaultStore {
    /// Store a raw block by CID bytes.
    pub fn put_block(&self, cid: &[u8], data: &[u8]) -> Result<(), StoreError> {
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

    /// Delete a block by CID bytes.
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
