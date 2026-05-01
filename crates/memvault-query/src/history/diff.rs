//! Compute diff between two operation sets.

use memvault_doc::Op;

/// A single diff entry.
#[derive(Debug, Clone)]
pub enum DiffEntry {
    Added(Op),
    Removed(Op),
}

/// Compute structural diff between two operation points.
///
/// Returns ops present in `ops_after` but not in `ops_before` as `Added`,
/// and ops present in `ops_before` but not in `ops_after` as `Removed`.
///
/// Comparison is done by serialized JSON equality since Op doesn't implement Eq.
pub fn diff_doc(ops_before: &[Op], ops_after: &[Op]) -> Vec<DiffEntry> {
    let serialize = |op: &Op| serde_json::to_string(op).unwrap_or_default();

    let before_set: std::collections::HashSet<String> =
        ops_before.iter().map(|op| serialize(op)).collect();
    let after_set: std::collections::HashSet<String> =
        ops_after.iter().map(|op| serialize(op)).collect();

    let mut result = Vec::new();

    // Ops in before but not in after -> Removed
    for op in ops_before {
        let key = serialize(op);
        if !after_set.contains(&key) {
            result.push(DiffEntry::Removed(op.clone()));
        }
    }

    // Ops in after but not in before -> Added
    for op in ops_after {
        let key = serialize(op);
        if !before_set.contains(&key) {
            result.push(DiffEntry::Added(op.clone()));
        }
    }

    result
}
