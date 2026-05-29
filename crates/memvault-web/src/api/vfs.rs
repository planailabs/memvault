//! Virtual filesystem endpoints — organise nodes into a path hierarchy.
//!
//! Each bucket has its own VFS root. Every endpoint requires a `bucket`
//! parameter (hex) — there is no implicit fallback to a "default" bucket
//! in the post-bucket world.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use memvault_api::vfs as vfs_ops;
use memvault_core::{BucketId, NodeRef};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct VfsQuery {
    pub path: String,
    pub bucket: String,
    pub recursive: Option<bool>,
}

#[derive(Deserialize)]
pub struct VfsResolveQuery {
    pub path: String,
    pub bucket: String,
}

#[derive(Deserialize)]
pub struct VfsMkdirRequest {
    pub path: String,
    pub bucket: String,
}

#[derive(Deserialize)]
pub struct VfsLinkRequest {
    pub path: String,
    pub target: String,
    pub bucket: String,
}

#[derive(Deserialize)]
pub struct VfsMvRequest {
    pub from: String,
    pub to: String,
    pub bucket: String,
}

#[derive(Deserialize)]
pub struct VfsUnlinkQuery {
    pub path: String,
    pub bucket: String,
}

#[derive(Serialize)]
pub struct VfsEntry {
    pub name: String,
    pub node_id: String,
    pub node_type: String,
    pub edge_id: String,
}

fn parse_bucket(hex: &str) -> Result<BucketId, ApiError> {
    BucketId::from_hex(hex).map_err(|_| ApiError::bad_request("invalid bucket hex"))
}

// ── Route handlers ─────────────────────────────────────────────────

/// GET /api/v1/vfs?bucket=<hex>&path=/projects&recursive=false
pub async fn vfs_ls(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bucket = parse_bucket(&params.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Read)?;
    let recursive = params.recursive.unwrap_or(false);
    let entries = vfs_ops::ls(state.client.as_ref(), &bucket, &params.path, recursive)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let out: Vec<VfsEntry> = entries
        .into_iter()
        .map(|e| VfsEntry {
            name: e.name,
            node_id: e.node_id,
            node_type: e.node_type,
            edge_id: e.edge_id,
        })
        .collect();
    Ok(Json(serde_json::json!({
        "path": params.path,
        "entries": out,
    })))
}

/// GET /api/v1/vfs/resolve?bucket=<hex>&path=/foo/bar
pub async fn vfs_resolve(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsResolveQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bucket = parse_bucket(&params.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Read)?;
    match vfs_ops::resolve_path(state.client.as_ref(), &bucket, &params.path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        Some((node, edge_id)) => {
            let nt = vfs_ops::resolve_node_type(state.client.as_ref(), &node).await;
            Ok(Json(serde_json::json!({
                "path": params.path,
                "node_id": node.tag_label(),
                "node_type": nt,
                "edge_id": edge_id.map(|e| hex::encode(e.0)),
            })))
        }
        None => Err(ApiError::not_found("path not found")),
    }
}

/// POST /api/v1/vfs/mkdir  body: { path, bucket }
pub async fn vfs_mkdir(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsMkdirRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let bucket = parse_bucket(&req.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Write)?;
    let id = vfs_ops::mkdir(state.client.as_ref(), &bucket, &req.path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "path": req.path,
            "entity_id": format!("entity:{}", hex::encode(id.0)),
            "status": "created",
        })),
    ))
}

/// POST /api/v1/vfs/link  body: { path, target, bucket }
pub async fn vfs_link(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsLinkRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let bucket = parse_bucket(&req.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Write)?;
    let target = NodeRef::from_tag_label(&req.target).ok_or_else(|| {
        ApiError::bad_request("invalid target — expected entity:<hex>, doc:<hex>, or file:<hex>")
    })?;
    let edge_id = vfs_ops::link_at_path(state.client.as_ref(), &bucket, &req.path, &target)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "path": req.path,
            "target": req.target,
            "edge_id": hex::encode(edge_id.0),
            "status": "linked",
        })),
    ))
}

/// DELETE /api/v1/vfs?bucket=<hex>&path=/projects/old.md
pub async fn vfs_unlink(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsUnlinkQuery>,
) -> Result<axum::http::StatusCode, ApiError> {
    let bucket = parse_bucket(&params.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Write)?;
    vfs_ops::unlink_path(state.client.as_ref(), &bucket, &params.path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// POST /api/v1/vfs/mv  body: { from, to, bucket }
pub async fn vfs_mv(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsMvRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bucket = parse_bucket(&req.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Write)?;
    vfs_ops::mv_path(state.client.as_ref(), &bucket, &req.from, &req.to)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "from": req.from,
        "to": req.to,
        "status": "moved",
    })))
}
