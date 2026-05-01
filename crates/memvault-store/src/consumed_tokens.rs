//! Token consumption tracking.

use redb::ReadableTable;

use crate::error::StoreError;
use crate::keys;
use crate::tables::CONSUMED_TOKENS;
use crate::MemvaultStore;

impl MemvaultStore {
    /// Record a token consumption. Returns the new consumption count.
    pub fn record_token_consumption(
        &self,
        token_cid: &[u8],
        consumer: &[u8],
        at_ns: u64,
    ) -> Result<u32, StoreError> {
        let txn = self.db.begin_write()?;
        let new_count = {
            let mut table = txn.open_table(CONSUMED_TOKENS)?;
            let current_count = match table.get(token_cid)? {
                Some(v) => {
                    let (count, _, _) = keys::unpack_consumed_value(v.value())?;
                    count
                }
                None => 0,
            };
            let new_count = current_count + 1;
            let value = keys::pack_consumed_value(new_count, consumer, at_ns);
            table.insert(token_cid, value.as_slice())?;
            new_count
        };
        txn.commit()?;
        Ok(new_count)
    }

    /// Get the current consumption count for a token.
    pub fn get_token_consumption_count(&self, token_cid: &[u8]) -> Result<u32, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CONSUMED_TOKENS)?;
        match table.get(token_cid)? {
            Some(v) => {
                let (count, _, _) = keys::unpack_consumed_value(v.value())?;
                Ok(count)
            }
            None => Ok(0),
        }
    }
}
