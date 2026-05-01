#[cfg(test)]
mod tests;

pub mod apply;
pub mod crdt;
pub mod attachment;
pub mod compaction;
pub mod document;
pub mod error;
pub mod gc;
pub mod graph;
pub mod head;
pub mod history;
pub mod log;
pub mod op;
pub mod snapshot;

pub use apply::{apply_doc_ops, apply_graph_ops, apply_text_patch};
pub use crdt::{CrdtDocument, CrdtError};
pub use attachment::{chunk_file, reassemble_file, Attachment, AttachmentRef, ChunkRef, MAX_CHUNK_SIZE};
pub use compaction::compact;
pub use document::Document;
pub use error::{DocError, Result};
pub use gc::collectible_ops;
pub use graph::{Edge, Entity};
pub use head::DocumentHead;
pub use history::{doc_at_op, doc_diff};
pub use log::{OpEntry, OpLog};
pub use op::{Op, TextOp, TextPatch};
pub use snapshot::Snapshot;
