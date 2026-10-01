//! Cross-cluster share proposals: inbox, outbox, a proposal, its decision.
//! Cluster administration — the admin scope.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use memvault_api::rest::ShareDecideRequest;
use memvault_api::wire::CidWire;

use crate::AppState;
use crate::api::auth::RequireAdmin;
use crate::error::ApiError;

fn parse_cid(s: &str) -> Result<Vec<u8>, ApiError> {
    memvault_core::cid_bytes_lenient(s).map_err(|_| ApiError::bad_request("invalid proposal CID"))
}

/// GET /api/v1/share/inbox — proposals received, as CID strings.
pub async fn inbox(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<CidWire>>, ApiError> {
    let cids = state.client.share_inbox().await?;
    Ok(Json(cids.into_iter().map(CidWire).collect()))
}

/// GET /api/v1/share/outbox — proposals sent, as CID strings.
pub async fn outbox(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<CidWire>>, ApiError> {
    let cids = state.client.share_outbox().await?;
    Ok(Json(cids.into_iter().map(CidWire).collect()))
}

/// GET /api/v1/share/proposals/{cid} — a proposal (`ShareProposalInfo`).
pub async fn proposal(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(cid): Path<String>,
) -> Result<Json<memvault_api::ShareProposalInfo>, ApiError> {
    state
        .client
        .share_get_proposal(&parse_cid(&cid)?)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("Proposal not found"))
}

/// POST /api/v1/share/proposals/{cid}/decide — approve or reject; 204.
pub async fn decide(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(cid): Path<String>,
    Json(req): Json<ShareDecideRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .client
        .share_decide(&parse_cid(&cid)?, req.approve, req.reason.as_deref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
