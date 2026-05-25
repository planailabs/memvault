//! Block exchange protocol — request blocks by CID, receive block data.
//!
//! Used for syncing: when a peer announces a new head via gossipsub,
//! other peers that don't have it use this protocol to fetch the block.

pub mod codec;

pub use codec::BlockCodec;

use serde::{Deserialize, Serialize};

/// Protocol identifier for block exchange.
pub const BLOCK_PROTOCOL: &str = "/ai-memvault/block/1.0";

/// Request one or more blocks by CID, or list recent heads.
///
/// Two modes:
/// - **Fetch**: `cids` is non-empty → response contains block data.
/// - **List heads**: `cids` is empty and `since_ns` is set → response
///   contains recent CIDs (with `found=true, data=[]`) so the requester
///   can pick which ones to fetch in a follow-up request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub cids: Vec<Vec<u8>>,
    /// When set and `cids` is empty, return CIDs of blocks stored since
    /// this wall-clock timestamp (nanoseconds). Added for initial sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_ns: Option<u64>,
    /// Max number of CIDs to return in a list-heads response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Response with the requested blocks.
/// Each entry is `(cid, data)`. If a CID is not found, data is empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub blocks: Vec<BlockEntry>,
}

/// A single block in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub cid: Vec<u8>,
    pub data: Vec<u8>,
    /// True if the block was found. When false, `data` is empty.
    pub found: bool,
}
