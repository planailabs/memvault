use redb::{TableDefinition};

/// Primary block storage: CID bytes -> raw block bytes.
pub const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");

/// Index by tag: packed(scope, label, wall_ns, cid) -> ().
pub const BY_TAG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_tag");

/// Index by author: packed(peer_id, wall_ns, cid) -> ().
pub const BY_AUTHOR: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_author");

/// Index by time: packed(wall_ns, cid) -> ().
pub const BY_TIME: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_time");

/// Causal links: packed(parent_cid, child_cid) -> ().
pub const BY_CAUSAL: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_causal");

/// Provenance links: packed(parent_cid, child_cid) -> ().
pub const BY_PROVENANCE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_provenance");

/// Edges: packed(edge_kind, source, target, wall_ns) -> cid.
pub const EDGES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("edges");

/// Heads: packed(doc_id, peer_id) -> head_cid.
pub const HEADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("heads");

/// Revocations: target_cid -> revocation_block_bytes.
pub const REVOCATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("revocations");

/// Retracted: retracted_cid -> tombstone_cid.
pub const RETRACTED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("retracted");

/// Cluster origin: packed(cluster_id, wall_ns, cid) -> ().
pub const CLUSTER_ORIGIN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("cluster_origin");

/// Consumed tokens: token_cid -> packed(count_u32, last_consumer_peer_id, last_consumed_at_ns).
pub const CONSUMED_TOKENS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("consumed_tokens");

/// Rotations: packed(rotation_id, wall_ns) -> rotation_block_cid.
pub const ROTATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rotations");
