//! Block exchange protocol — request blocks by CID, receive block data.
//!
//! Used for syncing: when a peer announces a new head via gossipsub,
//! other peers that don't have it use this protocol to fetch the block.

pub mod codec;

pub use codec::BlockCodec;

use serde::{Deserialize, Serialize};

/// Protocol identifier for block exchange.
pub const BLOCK_PROTOCOL: &str = "/ai-memvault/block/1.0";

/// Request one or more blocks by CID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub cids: Vec<Vec<u8>>,
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
