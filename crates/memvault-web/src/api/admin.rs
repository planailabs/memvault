//! Admin panel: tokens, rotation, peers, status.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::RequireAdmin;
use crate::error::ApiError;

#[derive(Serialize)]
pub struct NodeStatusResponse {
    pub peer_id: String,
    pub cluster_id: String,
    pub block_count: u64,
    pub doc_count: u64,
    pub peer_count: u32,
    pub uptime_secs: u64,
}

#[derive(Serialize)]
pub struct TokenStatusResponse {
    pub cid: String,
    pub label: Option<String>,
    pub role: String,
    pub max_uses: u32,
    pub consumed_count: u32,
    pub not_after_ns: u64,
    pub revoked: bool,
}

#[derive(Deserialize)]
pub struct IssueTokenRequest {
    pub role: String,
    pub ttl_secs: u64,
    pub max_uses: u32,
    pub label: Option<String>,
    /// Also admit the redeeming node as a co-equal cluster admin. The joiner
    /// must redeem with `cluster-join --admit-as-admin`.
    #[serde(default)]
    pub admit_as_admin: bool,
}

#[derive(Serialize)]
pub struct RotationInfoResponse {
    pub rotation_id: String,
    pub kind: String,
    pub valid_from_ns: u64,
    pub overlap_until_ns: u64,
    pub aborted: bool,
}

/// GET /api/v1/admin/status
pub async fn status(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<NodeStatusResponse>, ApiError> {
    let s = state.client.status().await?;
    Ok(Json(NodeStatusResponse {
        peer_id: hex::encode(&s.peer_id),
        cluster_id: hex::encode(&s.cluster_id),
        block_count: s.block_count,
        doc_count: s.doc_count,
        peer_count: s.peer_count,
        uptime_secs: s.uptime_secs,
    }))
}

/// GET /api/v1/admin/peers
pub async fn peers(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let s = state.client.status().await?;
    Ok(Json(serde_json::json!({
        "peer_count": s.peer_count,
    })))
}

/// POST /api/v1/admin/tokens
pub async fn issue_token(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Json(req): Json<IssueTokenRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let role = parse_role(&req.role)?;
    let token = state
        .client
        .issue_token_ex(role, req.ttl_secs, req.max_uses, req.label, req.admit_as_admin)
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "token": token })),
    ))
}

/// GET /api/v1/admin/tokens
pub async fn list_tokens(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<TokenStatusResponse>>, ApiError> {
    let tokens = state.client.list_tokens().await?;
    let results: Vec<TokenStatusResponse> = tokens
        .into_iter()
        .map(|t| TokenStatusResponse {
            cid: hex::encode(&t.cid),
            label: t.label,
            role: format!("{:?}", t.role).to_lowercase(),
            max_uses: t.max_uses,
            consumed_count: t.consumed_count,
            not_after_ns: t.not_after_ns,
            revoked: t.revoked,
        })
        .collect();
    Ok(Json(results))
}

/// DELETE /api/v1/admin/tokens/:cid
pub async fn revoke_token(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    let cid = hex::decode(&cid_hex).map_err(|_| ApiError::bad_request("Invalid CID hex"))?;
    state.client.revoke_token(&cid, "revoked via API").await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// GET /api/v1/admin/rotations
pub async fn list_rotations(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<RotationInfoResponse>>, ApiError> {
    let rotations = state.client.list_rotations().await?;
    let results: Vec<RotationInfoResponse> = rotations
        .into_iter()
        .map(|r| RotationInfoResponse {
            rotation_id: hex::encode(&r.rotation_id),
            kind: r.kind,
            valid_from_ns: r.valid_from_ns,
            overlap_until_ns: r.overlap_until_ns,
            aborted: r.aborted,
        })
        .collect();
    Ok(Json(results))
}

fn parse_role(s: &str) -> Result<memvault_auth::Role, ApiError> {
    match s {
        "admin" => Ok(memvault_auth::Role::Admin),
        "agent_host" => Ok(memvault_auth::Role::AgentHost),
        "auditor" => Ok(memvault_auth::Role::Auditor),
        "service" => Ok(memvault_auth::Role::Service),
        "node" => Ok(memvault_auth::Role::Node),
        _ => Err(ApiError::bad_request(format!("Unknown role: {s}"))),
    }
}

// ── Multi-admin key management ───────────────────────────────────────

#[derive(Deserialize)]
pub struct AdmitAdminRequest {
    /// New admin verifying key (64 hex chars).
    pub new_pubkey: String,
    /// Proof-of-possession (128 hex chars), produced offline by the
    /// incoming admin via `memctl admin pop`.
    pub pop: String,
    /// POP expiry (ns) the incoming admin bound into the POP.
    pub pop_not_after_ns: u64,
    /// Optional validity start (ns). Defaults to now.
    #[serde(default)]
    pub valid_from_ns: Option<u64>,
}

#[derive(Deserialize)]
pub struct RetireAdminRequest {
    /// Admin verifying key to retire (64 hex chars).
    pub pubkey: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct AdminKeyResponse {
    pub pubkey: String,
    pub is_anchor: bool,
    pub valid_from_ns: u64,
    pub valid_until_ns: u64,
    pub valid_now: bool,
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], ApiError> {
    let v = hex::decode(s).map_err(|_| ApiError::bad_request(format!("{what} not hex")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| ApiError::bad_request(format!("{what} must be 32 bytes")))
}

/// POST /api/v1/admin/keys — admit a new admin key.
pub async fn admit_admin_key(
    _auth: RequireAdmin,
    State(_state): State<Arc<AppState>>,
    Json(req): Json<AdmitAdminRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let client = crate::ui::state::local_client()
        .map_err(|e| ApiError::internal(format!("local client unavailable: {e}")))?;
    let new_pk = parse_hex32(&req.new_pubkey, "new_pubkey")?;
    let pop_bytes = hex::decode(&req.pop).map_err(|_| ApiError::bad_request("pop not hex"))?;
    let pop: [u8; 64] = pop_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::bad_request("pop must be 64 bytes"))?;
    let cid = client
        .admit_admin_key(new_pk, pop, req.pop_not_after_ns, req.valid_from_ns)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "admission_cid": hex::encode(cid) })),
    ))
}

/// POST /api/v1/admin/keys/retire — retire an admin key.
pub async fn retire_admin_key(
    _auth: RequireAdmin,
    State(_state): State<Arc<AppState>>,
    Json(req): Json<RetireAdminRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = crate::ui::state::local_client()
        .map_err(|e| ApiError::internal(format!("local client unavailable: {e}")))?;
    let pk = parse_hex32(&req.pubkey, "pubkey")?;
    let reason = req.reason.unwrap_or_else(|| "retired via API".to_string());
    let cid = client
        .retire_admin_key(pk, reason)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(serde_json::json!({ "retirement_cid": hex::encode(cid) })))
}

/// GET /api/v1/admin/keys — list admin keys and validity windows.
pub async fn list_admin_keys(
    _auth: RequireAdmin,
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Vec<AdminKeyResponse>>, ApiError> {
    let client = crate::ui::state::local_client()
        .map_err(|e| ApiError::internal(format!("local client unavailable: {e}")))?;
    let state = client.admin_key_state();
    let now = memvault_core::wall_ns();
    let anchor = state.anchor;
    let out = state
        .keys
        .iter()
        .map(|(pk, v)| AdminKeyResponse {
            pubkey: hex::encode(pk),
            is_anchor: Some(*pk) == anchor,
            valid_from_ns: v.valid_from_ns,
            valid_until_ns: v.valid_until_ns,
            valid_now: v.valid_at(now),
        })
        .collect();
    Ok(Json(out))
}
