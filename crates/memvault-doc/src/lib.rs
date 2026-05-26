#[cfg(test)]
mod tests;

pub mod apply;
pub mod bucket;
pub mod compaction;
pub mod crdt;
pub mod document;
pub mod error;
pub mod gc;
pub mod graph;
pub mod head;
pub mod history;
pub mod log;
pub mod op;
pub mod snapshot;

pub use apply::{GraphState, apply_doc_ops, apply_graph_ops, apply_text_patch};
pub use bucket::{BucketBinding, BucketDecl, BucketRole};
pub use compaction::compact;
pub use crdt::{CrdtDocument, CrdtError};
pub use document::Document;
pub use error::{DocError, Result};
pub use gc::collectible_ops;
pub use graph::{Edge, Entity};
pub use head::DocumentHead;
pub use history::{doc_at_op, doc_diff};
pub use log::{OpEntry, OpLog};
pub use op::{Op, TextOp, TextPatch};
pub use snapshot::Snapshot;
