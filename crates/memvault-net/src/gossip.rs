//! Gossipsub topic definitions and message types for memvault.

use libp2p::gossipsub::IdentTopic;
use serde::{Deserialize, Serialize};

/// Topic for DAG head announcements.
pub const HEADS_TOPIC: &str = "ai-memvault/heads/v1";

/// Topic for admin announcements (key rotations, revocations, etc.).
pub const ADMIN_TOPIC: &str = "ai-memvault/admin/v1";

/// Prefix for federation gossipsub topics between two clusters.
pub const FEDERATION_TOPIC_PREFIX: &str = "ai-memvault/federation/v1/";

/// Build a deterministic federation gossipsub topic name for two clusters.
///
/// The two cluster IDs are hex-encoded and sorted lexicographically so that
/// `federation_topic(a, b) == federation_topic(b, a)`.
pub fn federation_topic(cluster_a: &[u8], cluster_b: &[u8]) -> String {
    let hex_a = hex::encode(cluster_a);
    let hex_b = hex::encode(cluster_b);
    if hex_a <= hex_b {
        format!("{}{}/{}", FEDERATION_TOPIC_PREFIX, hex_a, hex_b)
    } else {
        format!("{}{}/{}", FEDERATION_TOPIC_PREFIX, hex_b, hex_a)
    }
}

/// Returns the gossipsub `IdentTopic` for federation between two clusters.
pub fn federation_ident_topic(cluster_a: &[u8], cluster_b: &[u8]) -> IdentTopic {
    IdentTopic::new(federation_topic(cluster_a, cluster_b))
}

/// Returns the gossipsub topic for DAG head announcements.
pub fn heads_topic() -> IdentTopic {
    IdentTopic::new(HEADS_TOPIC)
}

/// Returns the gossipsub topic for admin announcements.
pub fn admin_topic() -> IdentTopic {
    IdentTopic::new(ADMIN_TOPIC)
}

/// A head announcement: tells peers about a new block in the store.
/// Published on the `HEADS_TOPIC` gossipsub topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadAnnouncement {
    /// CID of the new block.
    pub cid: Vec<u8>,
    /// Cluster that produced it.
    pub cluster_id: Vec<u8>,
    /// Wall-clock timestamp (nanoseconds).
    pub wall_ns: u64,
    /// Optional bucket this block belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_id: Option<Vec<u8>>,
}

/// Admin announcements broadcast over gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminAnnouncement {
    /// A join token has been consumed (CID bytes).
    TokenConsumed(Vec<u8>),
    /// An admin key was rotated (new public key bytes).
    AdminKeyRotated(Vec<u8>),
    /// An agent key was rotated (new public key bytes).
    AgentKeyRotated(Vec<u8>),
    /// A key rotation was aborted (rotation ID bytes).
    RotationAborted(Vec<u8>),
    /// A membership was revoked (attestation CID bytes).
    Revoked(Vec<u8>),
    // ── Bucket announcements (added B3) ─────────────────────────
    /// A new bucket was created (BucketDecl envelope CID).
    BucketCreated(Vec<u8>),
    /// A bucket was attached to the cluster (BucketAttach op CID).
    BucketAttached(Vec<u8>),
    /// A bucket was archived (BucketArchive op CID).
    BucketArchived(Vec<u8>),
    /// A cross-cluster BucketTrust was established (BucketTrust envelope CID).
    BucketTrustEstablished(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_topic_deterministic() {
        let a = b"cluster-alpha";
        let b = b"cluster-beta";

        // Order shouldn't matter
        let topic_ab = federation_topic(a, b);
        let topic_ba = federation_topic(b, a);
        assert_eq!(topic_ab, topic_ba);

        // Starts with prefix
        assert!(topic_ab.starts_with(FEDERATION_TOPIC_PREFIX));

        // Contains both hex-encoded cluster IDs
        assert!(topic_ab.contains(&hex::encode(a)));
        assert!(topic_ab.contains(&hex::encode(b)));
    }

    #[test]
    fn test_federation_topic_same_cluster() {
        let a = b"same";
        let topic = federation_topic(a, a);
        // Should still work, just has same ID twice
        assert!(topic.starts_with(FEDERATION_TOPIC_PREFIX));
    }

    #[test]
    fn test_federation_topic_format() {
        let a = b"\x01\x02";
        let b = b"\x03\x04";
        let topic = federation_topic(a, b);
        assert_eq!(topic, "ai-memvault/federation/v1/0102/0304");
    }
}
