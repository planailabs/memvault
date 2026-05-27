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
        .issue_token(role, req.ttl_secs, req.max_uses, req.label)
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
        _ => Err(ApiError::bad_request(format!("Unknown role: {s}"))),
    }
}
