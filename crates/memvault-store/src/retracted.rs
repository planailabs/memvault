//! Retraction tracking.

use redb::ReadableTable;

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::tables::RETRACTED;

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

    /// All recorded retractions as `(retracted_cid, tombstone_cid)` pairs. Used
    /// by the migration that backfills syncable retraction blocks for local-only
    /// `RETRACTED` entries.
    pub fn iter_retracted(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(RETRACTED)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(out)
    }
}
