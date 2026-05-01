use crate::apply::apply_doc_ops;
use crate::document::Document;
use crate::error::{DocError, Result};
use crate::op::Op;

/// Reconstruct document state at a specific operation index.
pub fn doc_at_op(ops: &[Op], op_index: usize) -> Result<Document> {
    if op_index > ops.len() {
        return Err(DocError::IndexOutOfBounds {
            index: op_index,
            max: ops.len(),
        });
    }
    apply_doc_ops(&ops[..op_index])
}

/// Get ops between two indices (the diff).
pub fn doc_diff(ops: &[Op], from_index: usize, to_index: usize) -> Result<Vec<Op>> {
    if from_index > ops.len() {
        return Err(DocError::IndexOutOfBounds {
            index: from_index,
            max: ops.len(),
        });
    }
    if to_index > ops.len() {
        return Err(DocError::IndexOutOfBounds {
            index: to_index,
            max: ops.len(),
        });
    }
    if from_index > to_index {
        return Err(DocError::InvalidOp(
            "from_index must be <= to_index".to_string(),
        ));
    }
    Ok(ops[from_index..to_index].to_vec())
}
