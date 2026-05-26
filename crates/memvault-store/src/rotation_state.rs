//! Current admin key state reconstructed on startup from rotation blocks.

use redb::ReadableTable;

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::keys;
use crate::tables::ROTATIONS;

impl MemvaultStore {
    /// Store a rotation entry.
    pub fn store_rotation(
        &self,
        rotation_id: &[u8],
        wall_ns: u64,
        block_cid: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ROTATIONS)?;
            let key = keys::pack_rotation_key(rotation_id, wall_ns);
            table.insert(key.as_slice(), block_cid)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Get all rotation entries as (rotation_id, wall_ns, block_cid) tuples.
    pub fn get_all_rotations(&self) -> Result<Vec<(Vec<u8>, u64, Vec<u8>)>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ROTATIONS)?;

        let mut results = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let (key, value) = entry?;
            let (rotation_id, wall_ns) = keys::unpack_rotation_key(key.value())?;
            let block_cid = value.value().to_vec();
            results.push((rotation_id, wall_ns, block_cid));
        }
        Ok(results)
    }
}
