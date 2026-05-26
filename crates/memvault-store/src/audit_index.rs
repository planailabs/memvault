//! Audit record projection from envelopes.
//!
//! Revocations are tracked separately from retractions: a revocation invalidates
//! a credential/capability, while a retraction hides content.

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::tables::REVOCATIONS;

impl MemvaultStore {
    /// Record a revocation: marks `target_cid` as revoked with the given revocation block.
    pub fn record_revocation(
        &self,
        target_cid: &[u8],
        revocation_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(REVOCATIONS)?;
            table.insert(target_cid, revocation_bytes)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Check if a CID has been revoked.
    pub fn is_revoked(&self, cid: &[u8]) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(REVOCATIONS)?;
        Ok(table.get(cid)?.is_some())
    }

    /// Get the revocation block for a revoked CID.
    pub fn get_revocation(&self, cid: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(REVOCATIONS)?;
        Ok(table.get(cid)?.map(|v| v.value().to_vec()))
    }
}
