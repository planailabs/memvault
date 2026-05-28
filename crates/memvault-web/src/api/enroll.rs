//! Agent enrollment over HTTP — the wire-protocol equivalent of
//! `memctl agent-enroll`, so agents can be provisioned without
//! shell access to a node.
//!
//! **Unauthenticated by design.** The join token IS the authorisation:
//! the admin issued it, signed it, and bounded its uses. The endpoint
//! verifies the signature, time bounds, cluster_id, and consumption
//! count against the local store before minting.
//!
//! Flow:
//!   1. Client (agent) generates an ed25519 keypair locally.
//!   2. Client POSTs `{ token, agent_id, public_key }` to
//!      `/api/v1/auth/enroll-agent`.
//!   3. Server validates the token, mints an `AgentAttestation` signed
//!      by the node's signing key, publishes it to the sigchain, and
//!      records the token consumption.
//!   4. Server returns the attestation CID + role / expiry. The agent
//!      only needs its private key locally — verifiers look the
//!      attestation up via sigchain sync.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct EnrollAgentRequest {
    /// `mvjoin1:…` join token issued by admin.
    pub token: String,
    /// Human-readable agent identifier (label only; not authoritative).
    pub agent_id: String,
    /// Hex-encoded 32-byte ed25519 public key the agent will sign JWTs
    /// with. The agent's private key stays on the agent side.
    pub public_key: String,
}

#[derive(Serialize)]
pub struct EnrollAgentResponse {
    /// CID hex of the attestation as stored in the sigchain. Clients
    /// can use this to confirm the block reached the cluster; verifiers
    /// look up the attestation by `agent_pubkey`, not by CID.
    pub attestation_cid: String,
    /// Role granted by the token.
    pub role: String,
    /// Attestation expiry in unix nanos.
    pub expires_ns: u64,
}

/// POST /api/v1/auth/enroll-agent
pub async fn enroll_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollAgentRequest>,
) -> Result<Json<EnrollAgentResponse>, ApiError> {
    let _ = state;

    // The web auth path always runs against the daemon's LocalClient.
    let client = crate::ui::state::local_client()
        .map_err(|e| ApiError::bad_request(format!("local client unavailable: {e}")))?;

    // Decode the agent's pubkey.
    let pk_bytes = hex::decode(req.public_key.trim())
        .map_err(|e| ApiError::bad_request(format!("public_key hex: {e}")))?;
    let agent_pubkey: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| ApiError::bad_request("public_key must be 32 bytes"))?;

    // Delegate to memvault-api: signature verify + revocation check +
    // max_uses gate + idempotent mint + sigchain publish + consumption.
    let result = memvault_api::agent_identity::enroll_remote_agent(
        &client,
        &req.token,
        &req.agent_id,
        agent_pubkey,
    )
    .map_err(|e| ApiError::bad_request(format!("enroll: {e}")))?;

    Ok(Json(EnrollAgentResponse {
        attestation_cid: hex::encode(&result.attestation_cid),
        role: format!("{:?}", result.attestation.role),
        expires_ns: result.attestation.not_after_ns,
    }))
}
