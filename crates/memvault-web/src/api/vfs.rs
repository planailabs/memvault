//! Virtual filesystem endpoints — organise nodes into a path hierarchy.
//!
//! Each bucket has its own VFS root. All operations use the default bucket
//! unless the client specifies one (future: bucket query param).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use memvault_api::vfs as vfs_ops;
use memvault_core::NodeRef;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::RequireAuth;
use crate::error::ApiError;

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct VfsQuery {
    pub path: String,
    pub recursive: Option<bool>,
}

#[derive(Deserialize)]
pub struct VfsResolveQuery {
    pub path: String,
}

#[derive(Deserialize)]
pub struct VfsMkdirRequest {
    pub path: String,
}

#[derive(Deserialize)]
pub struct VfsLinkRequest {
    pub path: String,
    pub target: String,
}

#[derive(Deserialize)]
pub struct VfsMvRequest {
    pub from: String,
    pub to: String,
}

#[derive(Deserialize)]
pub struct VfsUnlinkQuery {
    pub path: String,
}

#[derive(Serialize)]
pub struct VfsEntry {
    pub name: String,
    pub node_id: String,
    pub node_type: String,
    pub edge_id: String,
}

// ── Route handlers ─────────────────────────────────────────────────

/// GET /api/v1/vfs?path=/projects&recursive=false
pub async fn vfs_ls(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bucket = vfs_ops::default_bucket(state.client.as_ref()).await;
    let (node, _) = vfs_ops::resolve_path(state.client.as_ref(), &bucket, &params.path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("path not found"))?;

    let recursive = params.recursive.unwrap_or(false);
    let entries = ls_entries(state.client.as_ref(), &node, recursive, "").await?;
    Ok(Json(serde_json::json!({
        "path": params.path,
        "entries": entries,
    })))
}

fn ls_entries<'a>(
    client: &'a dyn memvault_api::MemvaultClient,
    node: &'a NodeRef,
    recursive: bool,
    prefix: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<VfsEntry>, ApiError>> + Send + 'a>>
{
    Box::pin(async move {
        let children = vfs_ops::list_children(client, node)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let mut entries = Vec::new();
        for (name, target, eid) in &children {
            let display_name = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let nt = vfs_ops::resolve_node_type(client, target).await;
            entries.push(VfsEntry {
                name: display_name.clone(),
                node_id: target.tag_label(),
                node_type: nt.clone(),
                edge_id: hex::encode(eid.0),
            });
            if recursive && nt == "dir" {
                let sub = ls_entries(client, target, true, &display_name).await?;
                entries.extend(sub);
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    })
}

/// GET /api/v1/vfs/resolve?path=/foo/bar
pub async fn vfs_resolve(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsResolveQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bucket = vfs_ops::default_bucket(state.client.as_ref()).await;
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

/// POST /api/v1/vfs/mkdir
pub async fn vfs_mkdir(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsMkdirRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let bucket = vfs_ops::default_bucket(state.client.as_ref()).await;
    let parent = vfs_ops::ensure_dir_path(state.client.as_ref(), &bucket, &req.path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "path": req.path,
            "entity_id": parent.tag_label(),
            "status": "created",
        })),
    ))
}

/// POST /api/v1/vfs/link
pub async fn vfs_link(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsLinkRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let bucket = vfs_ops::default_bucket(state.client.as_ref()).await;
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

/// DELETE /api/v1/vfs?path=/projects/old.md
pub async fn vfs_unlink(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsUnlinkQuery>,
) -> Result<axum::http::StatusCode, ApiError> {
    let bucket = vfs_ops::default_bucket(state.client.as_ref()).await;
    let components: Vec<&str> = params.path.split('/').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        return Err(ApiError::bad_request("cannot unlink root"));
    }
    let (parent_parts, file_name) = components.split_at(components.len() - 1);
    let file_name = file_name[0];

    let root = vfs_ops::ensure_root(state.client.as_ref(), &bucket)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut current = NodeRef::Entity(root);
    for component in parent_parts {
        current = vfs_ops::find_named_child(state.client.as_ref(), &current, component)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .ok_or_else(|| ApiError::not_found(format!("component '{component}' not found")))?
            .0;
    }
    let (_target, edge_id) = vfs_ops::find_named_child(state.client.as_ref(), &current, file_name)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("'{file_name}' not found in directory")))?;
    state
        .client
        .remove_link_from(&current, &edge_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// POST /api/v1/vfs/mv
pub async fn vfs_mv(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsMvRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bucket = vfs_ops::default_bucket(state.client.as_ref()).await;

    // Resolve source.
    let (source_node, source_edge) =
        vfs_ops::resolve_path(state.client.as_ref(), &bucket, &req.from)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .ok_or_else(|| ApiError::not_found("source path not found"))?;
    let source_edge = source_edge.ok_or_else(|| ApiError::bad_request("cannot move root"))?;

    // Find source's parent to unlink.
    let from_components: Vec<&str> = req.from.split('/').filter(|s| !s.is_empty()).collect();
    let (from_parent_parts, _) = from_components.split_at(from_components.len() - 1);
    let from_parent = {
        let root = vfs_ops::ensure_root(state.client.as_ref(), &bucket)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let mut current = NodeRef::Entity(root);
        for component in from_parent_parts {
            current = vfs_ops::find_named_child(state.client.as_ref(), &current, component)
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?
                .ok_or_else(|| ApiError::not_found("parent not found"))?
                .0;
        }
        current
    };

    // Unlink from source.
    state
        .client
        .remove_link_from(&from_parent, &source_edge)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Link at destination.
    vfs_ops::link_at_path(state.client.as_ref(), &bucket, &req.to, &source_node)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "from": req.from,
        "to": req.to,
        "status": "moved",
    })))
}
