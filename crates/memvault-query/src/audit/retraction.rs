//! Retraction support — soft-delete of blocks.

use memvault_store::MemvaultStore;

use crate::error::QueryError;

/// Check if a CID has been retracted.
pub fn is_retracted(store: &MemvaultStore, cid: &[u8]) -> Result<bool, QueryError> {
    Ok(store.is_retracted(cid)?)
}

/// Retract a CID by recording a tombstone.
pub fn retract(
    store: &MemvaultStore,
    target_cid: &[u8],
    tombstone_cid: &[u8],
) -> Result<(), QueryError> {
    if store.is_retracted(target_cid)? {
        return Err(QueryError::AlreadyRetracted);
    }
    store.record_retraction(target_cid, tombstone_cid)?;
    Ok(())
}
