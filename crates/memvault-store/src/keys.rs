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

/// Extract the packed `wall_ns` from a tag index key (the 8 bytes preceding
/// the cid). Lets callers recover a block's index time without reading the
/// block body (sigchain blocks carry no `wall_ns` in their content).
pub fn unpack_tag_ts(key: &[u8]) -> Result<u64, StoreError> {
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
    let ts_start = offset + 2 + label_len;
    if key.len() < ts_start + 8 {
        return Err(StoreError::KeyEncoding("tag key too short for ts".into()));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&key[ts_start..ts_start + 8]);
    Ok(u64::from_be_bytes(b))
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

// ── Scope member-set keys (scoped-indexes Phase 2) ─────────────────

/// Pack a scope member key: [scope_id][node_id_bytes].
///
/// `scope_id` is a fixed-width opaque digest; `node_id` is the textual node id
/// (e.g. "doc:<hex>"). Keying by `(scope_id, node_id)` makes membership
/// insert / remove / retraction-flip O(1).
pub fn pack_scope_member_key(scope_id: &[u8], node_id: &str) -> Vec<u8> {
    let nid = node_id.as_bytes();
    let mut buf = Vec::with_capacity(scope_id.len() + nid.len());
    buf.extend_from_slice(scope_id);
    buf.extend_from_slice(nid);
    buf
}

/// Build a scope member prefix for range scanning all members of a scope.
pub fn pack_scope_member_prefix(scope_id: &[u8]) -> Vec<u8> {
    scope_id.to_vec()
}

/// Build a scope member upper bound (exclusive) for range scanning.
/// Relies on `scope_id` being fixed-width: appending 0xFF goes past any
/// node_id suffix without colliding with the next scope_id.
pub fn pack_scope_member_prefix_end(scope_id: &[u8]) -> Vec<u8> {
    let mut buf = scope_id.to_vec();
    buf.push(0xFF);
    buf
}

/// Extract the node_id bytes from a scope member key, given the fixed
/// `scope_id` width used to pack it.
pub fn unpack_scope_member_node_id(key: &[u8], scope_id_len: usize) -> Result<&[u8], StoreError> {
    if key.len() < scope_id_len {
        return Err(StoreError::KeyEncoding(
            "scope member key shorter than scope_id".into(),
        ));
    }
    Ok(&key[scope_id_len..])
}

/// Pack a scope member value: [retracted_byte:1][wall_ns:8].
pub fn pack_scope_member_value(retracted: bool, wall_ns: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(if retracted { 1 } else { 0 });
    buf.extend_from_slice(&wall_ns.to_be_bytes());
    buf
}

/// Unpack a scope member value into (retracted, wall_ns).
pub fn unpack_scope_member_value(data: &[u8]) -> Result<(bool, u64), StoreError> {
    if data.len() < 9 {
        return Err(StoreError::KeyEncoding(
            "scope member value too short".into(),
        ));
    }
    let retracted = data[0] != 0;
    let wall_ns = u64::from_be_bytes(data[1..9].try_into().unwrap());
    Ok((retracted, wall_ns))
}

/// Pack a scope registry value:
/// [kind:1][active_count:8][retracted_count:8][built_ns:8]
/// [view_cid_len:u16][view_cid][bucket_id_len:u16][bucket_id]
pub fn pack_scope_registry_value(
    kind: u8,
    active_count: u64,
    retracted_count: u64,
    built_ns: u64,
    view_cid: &[u8],
    bucket_id: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 8 + 8 + 2 + view_cid.len() + 2 + bucket_id.len());
    buf.push(kind);
    buf.extend_from_slice(&active_count.to_be_bytes());
    buf.extend_from_slice(&retracted_count.to_be_bytes());
    buf.extend_from_slice(&built_ns.to_be_bytes());
    buf.extend_from_slice(&(view_cid.len() as u16).to_be_bytes());
    buf.extend_from_slice(view_cid);
    buf.extend_from_slice(&(bucket_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(bucket_id);
    buf
}

/// Unpack a scope registry value into
/// (kind, active, retracted, built_ns, view_cid, bucket_id).
#[allow(clippy::type_complexity)]
pub fn unpack_scope_registry_value(
    data: &[u8],
) -> Result<(u8, u64, u64, u64, Vec<u8>, Vec<u8>), StoreError> {
    if data.len() < 1 + 8 + 8 + 8 + 2 {
        return Err(StoreError::KeyEncoding(
            "scope registry value too short".into(),
        ));
    }
    let kind = data[0];
    let active = u64::from_be_bytes(data[1..9].try_into().unwrap());
    let retracted = u64::from_be_bytes(data[9..17].try_into().unwrap());
    let built_ns = u64::from_be_bytes(data[17..25].try_into().unwrap());
    let vlen = u16::from_be_bytes([data[25], data[26]]) as usize;
    let v_start = 27;
    if data.len() < v_start + vlen + 2 {
        return Err(StoreError::KeyEncoding(
            "scope registry value truncated (view_cid)".into(),
        ));
    }
    let view_cid = data[v_start..v_start + vlen].to_vec();
    let b_len_off = v_start + vlen;
    let blen = u16::from_be_bytes([data[b_len_off], data[b_len_off + 1]]) as usize;
    let b_start = b_len_off + 2;
    if data.len() < b_start + blen {
        return Err(StoreError::KeyEncoding(
            "scope registry value truncated (bucket_id)".into(),
        ));
    }
    let bucket_id = data[b_start..b_start + blen].to_vec();
    Ok((kind, active, retracted, built_ns, view_cid, bucket_id))
}
