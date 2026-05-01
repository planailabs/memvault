//! Chunking engine: layout decisions and file chunking.

use serde::{Deserialize, Serialize};

use crate::error::AttachError;
use crate::replication::ReplicationHint;
use crate::unixfs;

/// Files at or below this size are stored as a single inline block.
pub const INLINE_THRESHOLD: u64 = 64 * 1024; // 64 KiB

/// Default chunk size for UnixFS DAG leaves.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024; // 256 KiB

/// Files at or below this size use Eager replication.
pub const EAGER_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MiB

/// Describes how a file's content is laid out in blocks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChunkLayout {
    /// File stored as a single raw block (<= inline_threshold).
    Inline { size: u32 },
    /// UnixFS balanced tree of fixed-size chunks.
    UnixFs {
        chunk_size: u32,
        layout: UnixFsLayout,
        num_chunks: u32,
    },
}

/// UnixFS tree layout strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnixFsLayout {
    Balanced,
    Trickle,
}

/// Decide chunk layout based on file size.
pub fn decide_layout(size: u64) -> ChunkLayout {
    if size <= INLINE_THRESHOLD {
        ChunkLayout::Inline { size: size as u32 }
    } else {
        let num_chunks = ((size + DEFAULT_CHUNK_SIZE as u64 - 1) / DEFAULT_CHUNK_SIZE as u64) as u32;
        ChunkLayout::UnixFs {
            chunk_size: DEFAULT_CHUNK_SIZE as u32,
            layout: UnixFsLayout::Balanced,
            num_chunks,
        }
    }
}

/// Determine replication hint from file size.
pub fn default_replication(size: u64) -> ReplicationHint {
    crate::replication::default_replication(size)
}

/// Chunk a file into blocks. Returns (root_cid, Vec<(cid, block_bytes)>).
///
/// For inline files: single raw block with CID.
/// For chunked files: leaf chunks + intermediate DAG-PB nodes + root node.
pub fn chunk_file(data: &[u8]) -> Result<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>), AttachError> {
    if data.is_empty() {
        return Err(AttachError::EmptyInput);
    }

    let size = data.len() as u64;
    if size <= INLINE_THRESHOLD {
        // Inline: single raw block
        let cid = crate::cid::raw_cid(data);
        Ok((cid.clone(), vec![(cid, data.to_vec())]))
    } else {
        // UnixFS DAG
        unixfs::build_unixfs_dag(data, DEFAULT_CHUNK_SIZE)
    }
}
