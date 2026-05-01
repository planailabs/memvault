//! Retraction tracking.

use crate::error::StoreError;
use crate::tables::RETRACTED;
use crate::MemvaultStore;

impl MemvaultStore {
    /// Record that a CID has been retracted with the given tombstone CID.
    pub fn record_retraction(
        &self,
        retracted_cid: &[u8],
        tombstone_cid: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(RETRACTED)?;
            table.insert(retracted_cid, tombstone_cid)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Check if a CID has been retracted.
    pub fn is_retracted(&self, cid: &[u8]) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(RETRACTED)?;
        Ok(table.get(cid)?.is_some())
    }
}
