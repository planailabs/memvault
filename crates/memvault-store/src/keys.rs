//! Key packing/unpacking helpers for composite redb keys.
//!
//! Format: length-prefixed segments for variable-length fields,
//! big-endian u64 for timestamps (preserves sort order).

use crate::error::StoreError;

/// Pack a tag index key: [scope_len:u16][scope][label_len:u16][label][wall_ns:u64][cid]
pub fn pack_tag_key(scope: &str, label: &str, wall_ns: u64, cid: &[u8]) -> Vec<u8> {
    let scope_bytes = scope.as_bytes();
    let label_bytes = label.as_bytes();
    let mut buf = Vec::with_capacity(2 + scope_bytes.len() + 2 + label_bytes.len() + 8 + cid.len());
    buf.extend_from_slice(&(scope_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_bytes);
    buf.extend_from_slice(&(label_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(label_bytes);
    buf.extend_from_slice(&wall_ns.to_be_bytes());
    buf.extend_from_slice(cid);
    buf
}

/// Build a tag prefix for range scanning: [scope_len:u16][scope][label_len:u16][label][wall_ns:u64]
pub fn pack_tag_prefix(scope: &str, label: &str, after_ns: u64) -> Vec<u8> {
    let scope_bytes = scope.as_bytes();
    let label_bytes = label.as_bytes();
    let mut buf = Vec::with_capacity(2 + scope_bytes.len() + 2 + label_bytes.len() + 8);
    buf.extend_from_slice(&(scope_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_bytes);
    buf.extend_from_slice(&(label_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(label_bytes);
    buf.extend_from_slice(&after_ns.to_be_bytes());
    buf
}

/// Build a tag upper bound (exclusive) for range scanning.
pub fn pack_tag_prefix_end(scope: &str, label: &str) -> Vec<u8> {
    let scope_bytes = scope.as_bytes();
    let label_bytes = label.as_bytes();
    let mut buf = Vec::with_capacity(2 + scope_bytes.len() + 2 + label_bytes.len() + 8);
    buf.extend_from_slice(&(scope_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_bytes);
    buf.extend_from_slice(&(label_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(label_bytes);
    buf.extend_from_slice(&u64::MAX.to_be_bytes());
    // Append 0xFF to ensure we go past any CID suffix
    buf.push(0xFF);
    buf
}

/// Build a scope-only prefix for scanning all labels under a scope.
pub fn pack_scope_prefix(scope: &str) -> Vec<u8> {
    let scope_bytes = scope.as_bytes();
    let mut buf = Vec::with_capacity(2 + scope_bytes.len());
    buf.extend_from_slice(&(scope_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_bytes);
    buf
}

/// Build a scope-only upper bound (exclusive).
pub fn pack_scope_prefix_end(scope: &str) -> Vec<u8> {
    let scope_bytes = scope.as_bytes();
    let mut buf = Vec::with_capacity(2 + scope_bytes.len() + 1);
    buf.extend_from_slice(&(scope_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_bytes);
    // Increment last byte to get exclusive upper bound for this scope.
    buf.push(0xFF);
    buf
}

/// Extract the label from a tag key.
pub fn unpack_tag_label(key: &[u8]) -> Result<&[u8], StoreError> {
    if key.len() < 4 {
        return Err(StoreError::KeyEncoding("tag key too short".into()));
    }
    let scope_len = u16::from_be_bytes([key[0], key[1]]) as usize;
    let offset = 2 + scope_len;
    if key.len() < offset + 2 {
        return Err(StoreError::KeyEncoding(
            "tag key too short for label".into(),
        ));
    }
    let label_len = u16::from_be_bytes([key[offset], key[offset + 1]]) as usize;
    let label_start = offset + 2;
    if key.len() < label_start + label_len {
        return Err(StoreError::KeyEncoding(
            "tag key too short for label data".into(),
        ));
    }
    Ok(&key[label_start..label_start + label_len])
}

/// Extract the CID from a tag key (everything after the prefix).
pub fn unpack_tag_cid(key: &[u8]) -> Result<&[u8], StoreError> {
    if key.len() < 4 {
        return Err(StoreError::KeyEncoding("tag key too short".into()));
    }
    let scope_len = u16::from_be_bytes([key[0], key[1]]) as usize;
    let offset = 2 + scope_len;
    if key.len() < offset + 2 {
        return Err(StoreError::KeyEncoding(
            "tag key too short for label".into(),
        ));
    }
    let label_len = u16::from_be_bytes([key[offset], key[offset + 1]]) as usize;
    let cid_start = offset + 2 + label_len + 8;
    if key.len() < cid_start {
        return Err(StoreError::KeyEncoding("tag key too short for cid".into()));
    }
    Ok(&key[cid_start..])
}

/// Pack an author index key: [peer_id_len:u16][peer_id][wall_ns:u64][cid]
pub fn pack_author_key(peer_id: &[u8], wall_ns: u64, cid: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + peer_id.len() + 8 + cid.len());
    buf.extend_from_slice(&(peer_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(peer_id);
    buf.extend_from_slice(&wall_ns.to_be_bytes());
    buf.extend_from_slice(cid);
    buf
}

/// Build an author prefix for range scanning.
pub fn pack_author_prefix(peer_id: &[u8], after_ns: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + peer_id.len() + 8);
    buf.extend_from_slice(&(peer_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(peer_id);
    buf.extend_from_slice(&after_ns.to_be_bytes());
    buf
}

/// Build an author upper bound.
pub fn pack_author_prefix_end(peer_id: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + peer_id.len() + 8 + 1);
    buf.extend_from_slice(&(peer_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(peer_id);
    buf.extend_from_slice(&u64::MAX.to_be_bytes());
    buf.push(0xFF);
    buf
}

/// Extract the CID from an author key.
pub fn unpack_author_cid(key: &[u8]) -> Result<&[u8], StoreError> {
    if key.len() < 2 {
        return Err(StoreError::KeyEncoding("author key too short".into()));
    }
    let peer_len = u16::from_be_bytes([key[0], key[1]]) as usize;
    let cid_start = 2 + peer_len + 8;
    if key.len() < cid_start {
        return Err(StoreError::KeyEncoding(
            "author key too short for cid".into(),
        ));
    }
    Ok(&key[cid_start..])
}

/// Pack a time index key: [wall_ns:u64][cid]
pub fn pack_time_key(wall_ns: u64, cid: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + cid.len());
    buf.extend_from_slice(&wall_ns.to_be_bytes());
    buf.extend_from_slice(cid);
    buf
}

/// Extract the CID from a time key.
pub fn unpack_time_cid(key: &[u8]) -> Result<&[u8], StoreError> {
    if key.len() < 8 {
        return Err(StoreError::KeyEncoding("time key too short".into()));
    }
    Ok(&key[8..])
}

/// Pack a causal/provenance key: [parent_cid_len:u16][parent_cid][child_cid]
pub fn pack_link_key(parent: &[u8], child: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + parent.len() + child.len());
    buf.extend_from_slice(&(parent.len() as u16).to_be_bytes());
    buf.extend_from_slice(parent);
    buf.extend_from_slice(child);
    buf
}

/// Pack a heads key: [doc_id_len:u16][doc_id][peer_id]
pub fn pack_heads_key(doc_id: &[u8], peer_id: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + doc_id.len() + peer_id.len());
    buf.extend_from_slice(&(doc_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(doc_id);
    buf.extend_from_slice(peer_id);
    buf
}

/// Pack a cluster origin key: [cluster_id_len:u16][cluster_id][wall_ns:u64][cid]
pub fn pack_cluster_key(cluster_id: &[u8], wall_ns: u64, cid: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + cluster_id.len() + 8 + cid.len());
    buf.extend_from_slice(&(cluster_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(cluster_id);
    buf.extend_from_slice(&wall_ns.to_be_bytes());
    buf.extend_from_slice(cid);
    buf
}

/// Pack consumed tokens value: [count:u32][last_consumer][last_consumed_at_ns:u64]
pub fn pack_consumed_value(count: u32, consumer: &[u8], at_ns: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 2 + consumer.len() + 8);
    buf.extend_from_slice(&count.to_be_bytes());
    buf.extend_from_slice(&(consumer.len() as u16).to_be_bytes());
    buf.extend_from_slice(consumer);
    buf.extend_from_slice(&at_ns.to_be_bytes());
    buf
}

/// Unpack consumed tokens value.
pub fn unpack_consumed_value(data: &[u8]) -> Result<(u32, Vec<u8>, u64), StoreError> {
    if data.len() < 4 + 2 {
        return Err(StoreError::KeyEncoding("consumed value too short".into()));
    }
    let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let consumer_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let consumer_end = 6 + consumer_len;
    if data.len() < consumer_end + 8 {
        return Err(StoreError::KeyEncoding(
            "consumed value too short for timestamp".into(),
        ));
    }
    let consumer = data[6..consumer_end].to_vec();
    let at_ns = u64::from_be_bytes(data[consumer_end..consumer_end + 8].try_into().unwrap());
    Ok((count, consumer, at_ns))
}

/// Pack a rotation key: [rotation_id_len:u16][rotation_id][wall_ns:u64]
pub fn pack_rotation_key(rotation_id: &[u8], wall_ns: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + rotation_id.len() + 8);
    buf.extend_from_slice(&(rotation_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(rotation_id);
    buf.extend_from_slice(&wall_ns.to_be_bytes());
    buf
}

/// Unpack a rotation key into (rotation_id, wall_ns).
pub fn unpack_rotation_key(key: &[u8]) -> Result<(Vec<u8>, u64), StoreError> {
    if key.len() < 2 {
        return Err(StoreError::KeyEncoding("rotation key too short".into()));
    }
    let id_len = u16::from_be_bytes([key[0], key[1]]) as usize;
    let ts_start = 2 + id_len;
    if key.len() < ts_start + 8 {
        return Err(StoreError::KeyEncoding(
            "rotation key too short for timestamp".into(),
        ));
    }
    let rotation_id = key[2..ts_start].to_vec();
    let wall_ns = u64::from_be_bytes(key[ts_start..ts_start + 8].try_into().unwrap());
    Ok((rotation_id, wall_ns))
}

// ── Bucket keys (added B1) ─────────────────────────────────────────

/// Pack a bucket index key: [bucket_id (32 bytes)][wall_ns:u64][cid]
///
/// Bucket IDs are fixed-size (32 bytes), so no length prefix is needed.
pub fn pack_bucket_key(bucket_id: &[u8], wall_ns: u64, cid: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 8 + cid.len());
    buf.extend_from_slice(bucket_id);
    buf.extend_from_slice(&wall_ns.to_be_bytes());
    buf.extend_from_slice(cid);
    buf
}

/// Build a bucket prefix for range scanning: [bucket_id][after_ns]
pub fn pack_bucket_prefix(bucket_id: &[u8], after_ns: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 8);
    buf.extend_from_slice(bucket_id);
    buf.extend_from_slice(&after_ns.to_be_bytes());
    buf
}

/// Build a bucket upper bound: [bucket_id][u64::MAX][0xFF]
pub fn pack_bucket_prefix_end(bucket_id: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 8 + 1);
    buf.extend_from_slice(bucket_id);
    buf.extend_from_slice(&u64::MAX.to_be_bytes());
    buf.push(0xFF);
    buf
}

/// Extract the CID from a bucket index key.
pub fn unpack_bucket_cid(key: &[u8]) -> Result<&[u8], StoreError> {
    let cid_start = 32 + 8; // bucket_id + wall_ns
    if key.len() < cid_start {
        return Err(StoreError::KeyEncoding(
            "bucket key too short for cid".into(),
        ));
    }
    Ok(&key[cid_start..])
}
