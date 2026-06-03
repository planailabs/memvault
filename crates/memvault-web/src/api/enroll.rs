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
    /// Optional attestation lifetime in seconds. Omitted / null = never
    /// expires (the default). Independent of the join token's expiry.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
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
    /// Full attestation as DAG-CBOR, hex-encoded. Remote callers (the
    /// `memctl agent-enroll-remote` flow) use this to populate their
    /// local identity dir without a second round-trip; existing
    /// callers can ignore the field. Empty if the caller went through
    /// the daemon's local enrollment path that already has the
    /// attestation bytes in hand.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attestation_cbor_hex: String,
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
    // None / 0 → never expires; otherwise seconds → nanoseconds.
    let ttl_ns = match req.ttl_secs {
        None | Some(0) => u64::MAX,
        Some(secs) => secs.saturating_mul(1_000_000_000),
    };
    let result = memvault_api::agent_identity::enroll_remote_agent(
        &client,
        &req.token,
        &req.agent_id,
        agent_pubkey,
        ttl_ns,
    )
    .map_err(|e| ApiError::bad_request(format!("enroll: {e}")))?;

    // Ensure the agent's default bucket exists immediately after enrollment,
    // so the agent's first write has a home.
    if let Err(e) = client
        .ensure_agent_bucket_for_pubkey(&agent_pubkey, &req.agent_id)
        .await
    {
        tracing::warn!(agent_id = %req.agent_id, error = %e, "could not ensure agent bucket");
    }

    let attestation_cbor = serde_ipld_dagcbor::to_vec(&result.attestation)
        .map_err(|e| ApiError::internal(format!("encode attestation: {e}")))?;

    Ok(Json(EnrollAgentResponse {
        attestation_cid: hex::encode(&result.attestation_cid),
        role: format!("{:?}", result.attestation.role),
        expires_ns: result.attestation.not_after_ns,
        attestation_cbor_hex: hex::encode(&attestation_cbor),
    }))
}
