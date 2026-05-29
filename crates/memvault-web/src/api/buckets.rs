//! Bucket CRUD API routes.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::{RequireAdmin, RequireAuth, RequireWrite};
use crate::error::ApiError;

#[derive(Debug, Deserialize)]
pub struct CreateBucketRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateBucketResponse {
    pub id: String,
}

pub async fn list_buckets(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let buckets = state
        .client
        .bucket_list()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let result: Vec<serde_json::Value> = buckets
        .iter()
        .map(|b| {
            serde_json::json!({
                "id": hex::encode(b.id.0),
                "name": b.name,
                "description": b.description,
                "owner_agent": b.owner_agent.as_ref().map(|a| &a.0),
                "cluster_id": b.cluster_id.as_ref().map(|c| hex::encode(c.0)),
                "is_attached": b.is_attached,
                "envelope_count": b.envelope_count,
                "created_ns": b.created_ns,
            })
        })
        .collect();
    Ok(Json(serde_json::json!(result)))
}

pub async fn get_bucket(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bucket_bytes = hex::decode(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    match state.client.bucket_get(&bucket_id).await {
        Ok(Some(b)) => Ok(Json(serde_json::json!({
            "id": hex::encode(b.id.0),
            "name": b.name,
            "description": b.description,
            "owner_agent": b.owner_agent.as_ref().map(|a| &a.0),
            "cluster_id": b.cluster_id.as_ref().map(|c| hex::encode(c.0)),
            "is_attached": b.is_attached,
            "envelope_count": b.envelope_count,
            "created_ns": b.created_ns,
        }))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn create_bucket(
    auth: RequireWrite,
    State(_state): State<Arc<AppState>>,
    Json(req): Json<CreateBucketRequest>,
) -> Result<Json<CreateBucketResponse>, ApiError> {
    // Resolve the caller's on-chain agent_id so the new bucket records
    // them as `owner_agent`. Without this, the BucketDecl would inherit
    // the daemon's identity and the caller would have no implicit
    // access to a bucket they just created.
    let client = crate::ui::state::local_client()
        .map_err(|e| ApiError::internal(format!("local client unavailable: {e}")))?;
    let pubkey_bytes = hex::decode(&auth.claims.sub)
        .map_err(|e| ApiError::bad_request(format!("claims.sub hex: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::bad_request("claims.sub must be 32 bytes".to_string()))?;
    let attestation = memvault_api::sigchain::find_agent_attestation(&client, &pubkey_arr)
        .map_err(|e| ApiError::internal(format!("attestation lookup: {e}")))?
        .ok_or_else(|| ApiError {
            status: StatusCode::FORBIDDEN,
            message: format!(
                "no agent attestation on chain for pubkey {}",
                auth.claims.sub
            ),
        })?;

    let bucket_id = client
        .bucket_create_as(
            attestation.agent_id,
            Some(pubkey_arr),
            &req.name,
            req.description.as_deref(),
            memvault_core::Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .map_err(|e| ApiError::internal(format!("bucket_create: {e}")))?;

    Ok(Json(CreateBucketResponse {
        id: hex::encode(bucket_id.0),
    }))
}

#[derive(Debug, Deserialize)]
pub struct RenameBucketRequest {
    pub name: String,
}

pub async fn rename_bucket(
    _auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<RenameBucketRequest>,
) -> Result<StatusCode, StatusCode> {
    let bucket_bytes = hex::decode(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    state
        .client
        .bucket_rename(&bucket_id, &req.name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn attach_bucket(
    _auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let bucket_bytes = hex::decode(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    state
        .client
        .bucket_attach(&bucket_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ArchiveBucketRequest {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct EnsureAgentBucketRequest {
    pub agent_id: String,
}

#[derive(Debug, Serialize)]
pub struct EnsureAgentBucketResponse {
    pub id: String,
}

pub async fn ensure_agent_bucket(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnsureAgentBucketRequest>,
) -> Result<Json<EnsureAgentBucketResponse>, StatusCode> {
    // The bucket id is keyed by the agent's pubkey. Use claims.sub (the
    // verified ed25519 pubkey hex) instead of trusting req.agent_id for
    // identity — the name is only a display hint on the BucketDecl.
    let pubkey = hex::decode(&auth.claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;
    if pubkey.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bucket_id = state
        .client
        .ensure_agent_bucket_for_pubkey(&pubkey, &req.agent_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(EnsureAgentBucketResponse {
        id: hex::encode(bucket_id.0),
    }))
}

pub async fn archive_bucket(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ArchiveBucketRequest>,
) -> Result<StatusCode, StatusCode> {
    let bucket_bytes = hex::decode(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    state
        .client
        .bucket_archive(&bucket_id, &req.reason)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}
