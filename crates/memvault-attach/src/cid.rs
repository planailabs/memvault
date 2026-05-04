//! CID (Content Identifier) computation using proper multiformats crates.
//!
//! File chunks use CIDv1 with:
//! - Raw codec (0x55) for inline/raw blocks
//! - DAG-PB codec (0x70) for UnixFS nodes
//! - SHA-256 multihash (0x12)

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

/// Multicodec for raw binary.
const RAW_CODEC: u64 = 0x55;

/// Multicodec for DAG-PB (protobuf-based DAG).
const DAG_PB_CODEC: u64 = 0x70;

/// Compute a CIDv1 with raw codec + SHA2-256 for inline blocks.
pub fn raw_cid(data: &[u8]) -> Cid {
    let hash = Code::Sha2_256.digest(data);
    Cid::new_v1(RAW_CODEC, hash)
}

/// Compute a CIDv1 with dag-pb codec + SHA2-256 for UnixFS nodes.
pub fn dag_pb_cid(block: &[u8]) -> Cid {
    let hash = Code::Sha2_256.digest(block);
    Cid::new_v1(DAG_PB_CODEC, hash)
}
