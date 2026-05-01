//! Streaming range reads via chunk walk.
//!
//! This module provides a higher-level API that works with the store,
//! handling both inline (raw) and UnixFS (chunked) layouts.

use crate::chunk::ChunkLayout;
use crate::error::AttachError;
use crate::unixfs;
use memvault_store::MemvaultStore;

/// Read the full content of an attachment from the store.
///
/// For inline attachments, returns the raw block directly.
/// For UnixFS attachments, walks the DAG and concatenates chunks.
pub fn read_full_with_layout(
    store: &MemvaultStore,
    root_cid: &[u8],
    layout: &ChunkLayout,
) -> Result<Vec<u8>, AttachError> {
    match layout {
        ChunkLayout::Inline { .. } => {
            // Inline: the root CID points to raw bytes directly
            store
                .get_block(root_cid)
                .map_err(AttachError::Store)?
                .ok_or_else(|| AttachError::BlockNotFound("content root".into()))
        }
        ChunkLayout::UnixFs { .. } => {
            let get_block = |cid: &[u8]| -> Option<Vec<u8>> {
                store.get_block(cid).ok().flatten()
            };
            unixfs::read_unixfs(root_cid, &get_block)
        }
    }
}

/// Read a byte range from an attachment stored in the given store.
pub fn read_range_with_layout(
    store: &MemvaultStore,
    root_cid: &[u8],
    layout: &ChunkLayout,
    start: u64,
    end: u64,
) -> Result<Vec<u8>, AttachError> {
    match layout {
        ChunkLayout::Inline { .. } => {
            let data = store
                .get_block(root_cid)
                .map_err(AttachError::Store)?
                .ok_or_else(|| AttachError::BlockNotFound("content root".into()))?;
            let start = start as usize;
            let end = (end as usize).min(data.len());
            if start >= data.len() {
                return Ok(vec![]);
            }
            Ok(data[start..end].to_vec())
        }
        ChunkLayout::UnixFs { .. } => {
            let get_block = |cid: &[u8]| -> Option<Vec<u8>> {
                store.get_block(cid).ok().flatten()
            };
            unixfs::read_unixfs_range(root_cid, start, end, &get_block)
        }
    }
}

/// Read the full content (legacy convenience — tries UnixFS first, falls back to raw).
pub fn read_full(store: &MemvaultStore, root_cid: &[u8]) -> Result<Vec<u8>, AttachError> {
    let get_block = |cid: &[u8]| -> Option<Vec<u8>> {
        store.get_block(cid).ok().flatten()
    };
    // Try UnixFS first; if protobuf decode fails, treat as raw inline block
    match unixfs::read_unixfs(root_cid, &get_block) {
        Ok(data) => Ok(data),
        Err(_) => store
            .get_block(root_cid)
            .map_err(AttachError::Store)?
            .ok_or_else(|| AttachError::BlockNotFound("content root".into())),
    }
}

/// Read a byte range (legacy convenience — tries UnixFS first, falls back to raw).
pub fn read_range(
    store: &MemvaultStore,
    root_cid: &[u8],
    start: u64,
    end: u64,
) -> Result<Vec<u8>, AttachError> {
    let get_block = |cid: &[u8]| -> Option<Vec<u8>> {
        store.get_block(cid).ok().flatten()
    };
    match unixfs::read_unixfs_range(root_cid, start, end, &get_block) {
        Ok(data) => Ok(data),
        Err(_) => {
            let data = store
                .get_block(root_cid)
                .map_err(AttachError::Store)?
                .ok_or_else(|| AttachError::BlockNotFound("content root".into()))?;
            let s = start as usize;
            let e = (end as usize).min(data.len());
            if s >= data.len() {
                return Ok(vec![]);
            }
            Ok(data[s..e].to_vec())
        }
    }
}
