//! CID (Content Identifier) computation.
//!
//! We use CIDv1 with:
//! - Raw codec (0x55) for inline/raw blocks
//! - DAG-PB codec (0x70) for UnixFS nodes
//! - SHA-256 multihash (0x12)

use sha2::{Digest, Sha256};

/// Multicodec for raw binary.
const RAW_CODEC: u64 = 0x55;

/// Multicodec for DAG-PB.
const DAG_PB_CODEC: u64 = 0x70;

/// Multihash code for SHA-256.
const SHA2_256: u64 = 0x12;

/// CID version 1.
const CID_V1: u64 = 1;

/// Encode an unsigned varint.
fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

/// Build a CIDv1 from codec and data hash.
fn make_cid(codec: u64, data: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(data);
    let mut cid = Vec::with_capacity(64);
    encode_varint(CID_V1, &mut cid);
    encode_varint(codec, &mut cid);
    // Multihash: hash_code + digest_length + digest
    encode_varint(SHA2_256, &mut cid);
    encode_varint(32, &mut cid);
    cid.extend_from_slice(&hash);
    cid
}

/// Compute a CIDv1 with raw codec for inline blocks.
pub fn raw_cid(data: &[u8]) -> Vec<u8> {
    make_cid(RAW_CODEC, data)
}

/// Compute a CIDv1 with dag-pb codec for UnixFS nodes.
pub fn dag_pb_cid(block: &[u8]) -> Vec<u8> {
    make_cid(DAG_PB_CODEC, block)
}
