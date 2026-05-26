//! Bucket CRUD API routes.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::RequireAuth;

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
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBucketRequest>,
) -> Result<Json<CreateBucketResponse>, StatusCode> {
    let bucket_id = state
        .client
        .bucket_create(
            &req.name,
            req.description.as_deref(),
            memvault_core::Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateBucketResponse {
        id: hex::encode(bucket_id.0),
    }))
}

#[derive(Debug, Deserialize)]
pub struct RenameBucketRequest {
    pub name: String,
}

pub async fn rename_bucket(
    _auth: RequireAuth,
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
    _auth: RequireAuth,
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

pub async fn archive_bucket(
    _auth: RequireAuth,
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
