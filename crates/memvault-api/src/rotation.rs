//! Rotation operation helpers.

use memvault_store::MemvaultStore;

use crate::error::Result;
use crate::types::RotationInfo;

/// List all rotations stored in the system.
pub fn list_rotations(store: &MemvaultStore) -> Result<Vec<RotationInfo>> {
    let raw = store.get_all_rotations()?;
    let mut infos = Vec::new();

    for (rotation_id, wall_ns, _block_cid) in raw {
        infos.push(RotationInfo {
            rotation_id: rotation_id.clone(),
            kind: "unknown".to_string(),
            valid_from_ns: wall_ns,
            overlap_until_ns: 0,
            aborted: false,
        });
    }

    // Deduplicate by rotation_id, keeping the latest entry
    infos.sort_by_key(|r| (r.rotation_id.clone(), r.valid_from_ns));
    infos.dedup_by_key(|r| r.rotation_id.clone());

    Ok(infos)
}
