//! Gossipsub topic definitions and message types for memvault.

use libp2p::gossipsub::IdentTopic;
use serde::{Deserialize, Serialize};

/// Topic for DAG head announcements.
pub const HEADS_TOPIC: &str = "ai-memvault/heads/v1";

/// Topic for admin announcements (key rotations, revocations, etc.).
pub const ADMIN_TOPIC: &str = "ai-memvault/admin/v1";

/// Returns the gossipsub topic for DAG head announcements.
pub fn heads_topic() -> IdentTopic {
    IdentTopic::new(HEADS_TOPIC)
}

/// Returns the gossipsub topic for admin announcements.
pub fn admin_topic() -> IdentTopic {
    IdentTopic::new(ADMIN_TOPIC)
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
}
