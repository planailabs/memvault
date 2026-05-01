//! Heads tracking for CRDT-style document convergence.

use crate::error::StoreError;
use crate::keys;
use crate::tables::HEADS;
use crate::MemvaultStore;

impl MemvaultStore {
    /// Set the head CID for a (doc_id, peer_id) pair.
    pub fn set_head(
        &self,
        doc_id: &[u8],
        peer_id: &[u8],
        head_cid: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(HEADS)?;
            let key = keys::pack_heads_key(doc_id, peer_id);
            table.insert(key.as_slice(), head_cid)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Get the head CID for a (doc_id, peer_id) pair.
    pub fn get_head(&self, doc_id: &[u8], peer_id: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HEADS)?;
        let key = keys::pack_heads_key(doc_id, peer_id);
        Ok(table.get(key.as_slice())?.map(|v| v.value().to_vec()))
    }
}
