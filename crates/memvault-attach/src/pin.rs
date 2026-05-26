//! Pin/unpin lifecycle for attachments.

use serde::{Deserialize, Serialize};

use crate::error::AttachError;
use memvault_store::MemvaultStore;

/// Prefix for pin entries in the block store.
const PIN_PREFIX: &[u8] = b"__pin:";

/// Reason an attachment is pinned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PinReason {
    /// Pinned by eager replication policy.
    EagerByPolicy,
    /// Manually pinned by user.
    Manual,
    /// Pinned by a grant (CID of the grant).
    PinnedByGrant(Vec<u8>),
}

fn pin_key(manifest_cid: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PIN_PREFIX.len() + manifest_cid.len());
    key.extend_from_slice(PIN_PREFIX);
    key.extend_from_slice(manifest_cid);
    key
}

/// Pin an attachment (records in store).
pub fn pin(
    store: &MemvaultStore,
    manifest_cid: &[u8],
    reason: PinReason,
) -> Result<(), AttachError> {
    let key = pin_key(manifest_cid);
    let value = serde_json::to_vec(&reason).unwrap();
    store.put_block(&key, &value)?;
    Ok(())
}

/// Unpin an attachment.
pub fn unpin(store: &MemvaultStore, manifest_cid: &[u8]) -> Result<(), AttachError> {
    let key = pin_key(manifest_cid);
    store.delete_block(&key)?;
    Ok(())
}

/// Check if an attachment is pinned.
pub fn is_pinned(store: &MemvaultStore, manifest_cid: &[u8]) -> Result<bool, AttachError> {
    let key = pin_key(manifest_cid);
    Ok(store.has_block(&key)?)
}

/// List all pinned attachments.
///
/// Note: This is a simplified implementation that requires scanning.
/// In practice, a dedicated table would be more efficient.
pub fn list_pinned(
    store: &MemvaultStore,
    known_cids: &[Vec<u8>],
) -> Result<Vec<(Vec<u8>, PinReason)>, AttachError> {
    let mut result = Vec::new();
    for cid in known_cids {
        let key = pin_key(cid);
        if let Some(data) = store.get_block(&key)? {
            let reason: PinReason = serde_json::from_slice(&data)
                .map_err(|e| AttachError::InvalidUnixFs(format!("bad pin data: {e}")))?;
            result.push((cid.clone(), reason));
        }
    }
    Ok(result)
}
