//! Pin/unpin lifecycle for attachments.
//!
//! Pins are local replication policy, not content: they live in the
//! store's dedicated pin table, never in BLOCKS (which holds only
//! content-addressed blocks).

use serde::{Deserialize, Serialize};

use crate::error::AttachError;
use memvault_store::MemvaultStore;

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

/// Pin an attachment (records in store).
pub fn pin(
    store: &MemvaultStore,
    manifest_cid: &[u8],
    reason: PinReason,
) -> Result<(), AttachError> {
    let value = serde_json::to_vec(&reason)
        .map_err(|e| AttachError::InvalidUnixFs(format!("encode pin reason: {e}")))?;
    store.set_pin(manifest_cid, &value)?;
    Ok(())
}

/// Unpin an attachment.
pub fn unpin(store: &MemvaultStore, manifest_cid: &[u8]) -> Result<(), AttachError> {
    store.remove_pin(manifest_cid)?;
    Ok(())
}

/// Check if an attachment is pinned.
pub fn is_pinned(store: &MemvaultStore, manifest_cid: &[u8]) -> Result<bool, AttachError> {
    Ok(store.get_pin(manifest_cid)?.is_some())
}

/// List every pinned attachment with its reason.
pub fn list_pinned(store: &MemvaultStore) -> Result<Vec<(Vec<u8>, PinReason)>, AttachError> {
    let mut result = Vec::new();
    for (cid, data) in store.list_pins()? {
        let reason: PinReason = serde_json::from_slice(&data)
            .map_err(|e| AttachError::InvalidUnixFs(format!("bad pin data: {e}")))?;
        result.push((cid, reason));
    }
    Ok(result)
}
