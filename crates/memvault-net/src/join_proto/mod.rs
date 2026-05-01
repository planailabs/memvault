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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub version: u8,
    pub result: JoinResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JoinResult {
    Success { attestation_block: Vec<u8> },
    Refuse { reason: JoinRefuseReason, try_peers: Vec<String> },
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
