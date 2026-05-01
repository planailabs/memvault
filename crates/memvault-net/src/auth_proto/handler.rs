//! Server/client logic for the auth handshake protocol.
//!
//! The auth protocol allows two peers that are already members of the same
//! cluster to mutually authenticate by exchanging membership attestations.

use super::{AuthRequest, AuthResponse};

/// Validate an incoming auth request.
/// Returns `Ok(())` if the attestation block is non-empty and version is supported.
pub fn validate_auth_request(req: &AuthRequest) -> Result<(), &'static str> {
    if req.version != 1 {
        return Err("unsupported auth protocol version");
    }
    if req.attestation_block.is_empty() {
        return Err("empty attestation block");
    }
    if req.cluster_id.is_empty() {
        return Err("empty cluster id");
    }
    Ok(())
}

/// Build an auth response from local attestation data.
pub fn build_auth_response(attestation_block: Vec<u8>, cluster_id: Vec<u8>) -> AuthResponse {
    AuthResponse {
        version: 1,
        attestation_block,
        cluster_id,
    }
}
