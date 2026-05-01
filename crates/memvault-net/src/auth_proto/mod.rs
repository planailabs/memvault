pub mod codec;
pub mod handler;

pub use codec::AuthCodec;

use serde::{Deserialize, Serialize};

/// Protocol identifier for the auth handshake.
pub const AUTH_PROTOCOL: &str = "/ai-memvault/auth/1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub version: u8,
    pub attestation_block: Vec<u8>,
    pub cluster_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub version: u8,
    pub attestation_block: Vec<u8>,
    pub cluster_id: Vec<u8>,
}
