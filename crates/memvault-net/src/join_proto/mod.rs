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
    /// Optional admin-admission request: the joiner's admin pubkey to be
    /// admitted as a co-equal cluster admin. Honoured only when the
    /// redeemed token has `admit_as_admin = true` and `admin_pop` verifies.
    #[serde(default)]
    pub admin_pubkey: Option<Vec<u8>>,
    /// Proof-of-possession over (cluster, admin_pubkey, pop_not_after_ns),
    /// signed by `admin_pubkey`. 64 bytes.
    #[serde(default)]
    pub admin_pop: Option<Vec<u8>>,
    /// Expiry the joiner bound into `admin_pop`.
    #[serde(default)]
    pub admin_pop_not_after_ns: Option<u64>,
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
        /// The minted `AdminKeyAdmission` block (CBOR), present only when
        /// the token allowed admin admission and the request carried a
        /// valid POP. The joiner stores it; it also propagates via sync.
        #[serde(default)]
        admission_block: Option<Vec<u8>>,
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
