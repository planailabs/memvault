//! `memvault-attach` — First-class attachment storage for memvault using
//! UnixFS-compatible file DAGs.
//!
//! Files are stored as content-addressed UnixFS DAGs (IPFS-compatible):
//! - Small files (<=64 KiB) are stored inline as a single raw block
//! - Larger files are chunked (256 KiB) into a balanced DAG-PB tree
//! - Replication is either Eager (auto-replicate <=10MB) or Lazy (fetch on demand)

pub mod cache;
pub mod chunk;
pub mod cid;
pub mod error;
pub mod manifest;
pub mod pin;
pub mod proto;
pub mod read_range;
pub mod replication;
pub mod unixfs;

pub use cache::AttachmentCache;
pub use chunk::{ChunkLayout, UnixFsLayout, chunk_file, decide_layout, default_replication};
pub use error::AttachError;
pub use manifest::{AttachmentHeadRef, AttachmentManifest, ManifestUpdate};
pub use pin::PinReason;
pub use replication::ReplicationHint;
