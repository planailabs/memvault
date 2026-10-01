//! Virtual filesystem endpoints — organise nodes into a path hierarchy.
//!
//! Each bucket has its own VFS root. Every endpoint requires a `bucket`
//! parameter (hex) — there is no implicit fallback to a "default" bucket
//! in the post-bucket world.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use memvault_api::rest::{
    EdgeCreated, NodeCreated, VfsLinkRequest, VfsMkdirRequest, VfsMvRequest, VfsResolved, VfsTree,
};
use memvault_api::vfs::{self as vfs_ops, VfsEntry};
use memvault_core::{BucketId, NodeRef};
use serde::Deserialize;

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
pub struct VfsUnlinkQuery {
    pub path: String,
    pub bucket: String,
}

#[derive(Deserialize)]
pub struct VfsTreeQuery {
    pub path: String,
    pub bucket: String,
    pub max_depth: Option<usize>,
}

#[derive(Deserialize)]
pub struct VfsFindQuery {
    pub target: String,
    pub bucket: String,
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
) -> Result<Json<Vec<VfsEntry>>, ApiError> {
    let bucket = parse_bucket(&params.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Read)?;
    let recursive = params.recursive.unwrap_or(false);
    // A missing path is a 404 (NotFound), not a server error.
    let entries = vfs_ops::ls(state.client.as_ref(), &bucket, &params.path, recursive).await?;
    Ok(Json(entries))
}

/// GET /api/v1/vfs/resolve?bucket=<hex>&path=/foo/bar
pub async fn vfs_resolve(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsResolveQuery>,
) -> Result<Json<VfsResolved>, ApiError> {
    let bucket = parse_bucket(&params.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Read)?;
    match vfs_ops::resolve_path(state.client.as_ref(), &bucket, &params.path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        Some((node, edge_id)) => {
            let node_type = vfs_ops::resolve_node_type(state.client.as_ref(), &node).await;
            Ok(Json(VfsResolved {
                path: params.path,
                node_id: node.tag_label(),
                node_type,
                edge_id,
            }))
        }
        None => Err(ApiError::not_found("path not found")),
    }
}

/// POST /api/v1/vfs/mkdir  body: { path, bucket } — 201 with the leaf
/// directory's `node_id`.
pub async fn vfs_mkdir(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsMkdirRequest>,
) -> Result<(StatusCode, Json<NodeCreated>), ApiError> {
    let bucket = req.bucket;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Write)?;
    let id = vfs_ops::mkdir(state.client.as_ref(), &bucket, &req.path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(NodeCreated {
            node_id: NodeRef::Entity(id).tag_label(),
        }),
    ))
}

/// POST /api/v1/vfs/link  body: { path, target, bucket } — 201 with the
/// `edge_id`.
pub async fn vfs_link(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsLinkRequest>,
) -> Result<(StatusCode, Json<EdgeCreated>), ApiError> {
    let bucket = req.bucket;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Write)?;
    let target = NodeRef::from_tag_label(&req.target).ok_or_else(|| {
        ApiError::bad_request("invalid target — expected entity:<hex>, doc:<hex>, or file:<hex>")
    })?;
    // Linking shows the target in this bucket's tree: the caller must be
    // able to read it.
    crate::api::auth::enforce_node_action(&auth.claims, &req.target, memvault_auth::Action::Read)?;
    let edge_id = vfs_ops::link_at_path(state.client.as_ref(), &bucket, &req.path, &target)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok((StatusCode::CREATED, Json(EdgeCreated { edge_id })))
}

/// DELETE /api/v1/vfs?bucket=<hex>&path=/projects/old.md
pub async fn vfs_unlink(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsUnlinkQuery>,
) -> Result<StatusCode, ApiError> {
    let bucket = parse_bucket(&params.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Write)?;
    vfs_ops::unlink_path(state.client.as_ref(), &bucket, &params.path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/vfs/tree?bucket=<hex>&path=/&max_depth=10
pub async fn vfs_tree(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsTreeQuery>,
) -> Result<Json<VfsTree>, ApiError> {
    let bucket = parse_bucket(&params.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Read)?;
    let max_depth = params.max_depth.unwrap_or(10);
    let tree = vfs_ops::tree(state.client.as_ref(), &bucket, &params.path, max_depth).await?;
    Ok(Json(VfsTree {
        path: params.path,
        tree,
    }))
}

/// GET /api/v1/vfs/find?bucket=<hex>&target=entity:<hex>
pub async fn vfs_find(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsFindQuery>,
) -> Result<Json<Vec<String>>, ApiError> {
    let bucket = parse_bucket(&params.bucket)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Read)?;
    let target = NodeRef::from_tag_label(&params.target)
        .ok_or_else(|| ApiError::bad_request("invalid target — expected type:hex"))?;
    let paths = vfs_ops::find_paths(state.client.as_ref(), &bucket, &target)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(paths))
}

/// POST /api/v1/vfs/mv  body: { from, to, bucket } — 204.
pub async fn vfs_mv(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsMvRequest>,
) -> Result<StatusCode, ApiError> {
    let bucket = req.bucket;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket, memvault_auth::Action::Write)?;
    vfs_ops::mv_path(state.client.as_ref(), &bucket, &req.from, &req.to)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}
