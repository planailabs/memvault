//! Server/client logic for the join (token redemption) protocol.

use super::{JoinRefuseReason, JoinRequest, JoinResponse, JoinResult};

/// Validate an incoming join request.
pub fn validate_join_request(req: &JoinRequest) -> Result<(), &'static str> {
    if req.version != 1 {
        return Err("unsupported join protocol version");
    }
    if req.token_block.is_empty() {
        return Err("empty token block");
    }
    if req.peer_id.is_empty() {
        return Err("empty peer id");
    }
    Ok(())
}

/// Build a successful join response with the new attestation, optional
/// enrollment, and bootstrap sigchain blocks (admin's NodeAttestation,
/// AdminGenesis, etc.) the joining peer needs to verify cluster trust
/// without an unrestricted block-exchange round.
pub fn build_join_success(
    attestation_block: Vec<u8>,
    enrollment_block: Option<Vec<u8>>,
    bootstrap_blocks: Vec<Vec<u8>>,
) -> JoinResponse {
    JoinResponse {
        version: 1,
        result: JoinResult::Success {
            attestation_block,
            enrollment_block,
            bootstrap_blocks,
        },
    }
}

/// Build a refusal join response.
pub fn build_join_refusal(reason: JoinRefuseReason, try_peers: Vec<String>) -> JoinResponse {
    JoinResponse {
        version: 1,
        result: JoinResult::Refuse { reason, try_peers },
    }
}
