pub mod codec;
pub mod handler;

pub use codec::JoinCodec;

use serde::{Deserialize, Serialize};

/// Protocol identifier for the join (token redemption) protocol.
pub const JOIN_PROTOCOL: &str = "/ai-memvault/join/1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub version: u8,
    pub token_block: Vec<u8>,
    pub peer_id: Vec<u8>,
    pub requested_ttl: Option<u64>,
    /// Agent identifier for enrollment (e.g. "openclaw").
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Agent's Ed25519 public key (32 bytes) for enrollment.
    #[serde(default)]
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub version: u8,
    pub result: JoinResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JoinResult {
    Success {
        attestation_block: Vec<u8>,
        /// AgentEnrollment block (CBOR), present when the request included agent_id + public_key.
        #[serde(default)]
        enrollment_block: Option<Vec<u8>>,
        /// Bootstrap bundle: raw CBOR bytes for sigchain blocks the
        /// joining peer needs to be able to verify cluster trust
        /// before its first block-exchange request. Typically contains
        /// admin's own `NodeAttestation` and the cluster's
        /// `AdminGenesis` block — both of which the peer's block
        /// exchange would otherwise be refused service of (the trust
        /// gate in `serve_block_request` requires the peer to already
        /// be attested). Each entry is dispatched through the same
        /// shape-detection + signature-verification path as a synced
        /// block, so a malicious admin can't inject arbitrary blocks.
        #[serde(default)]
        bootstrap_blocks: Vec<Vec<u8>>,
    },
    Refuse {
        reason: JoinRefuseReason,
        try_peers: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JoinRefuseReason {
    NotAdminPeer,
    TokenInvalidSignature,
    TokenExpired,
    TokenNotYetValid,
    TokenAlreadyConsumed,
    TokenRevoked,
    PeerIdMismatch,
    RoleNotAllowed,
    RateLimited,
}
