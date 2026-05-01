use crate::snapshot::Snapshot;

/// Identify ops that can be garbage collected (covered by a snapshot).
pub fn collectible_ops(snapshot: &Snapshot, all_op_cids: &[Vec<u8>]) -> Vec<Vec<u8>> {
    all_op_cids
        .iter()
        .filter(|cid| snapshot.covers_ops.contains(cid))
        .cloned()
        .collect()
}
