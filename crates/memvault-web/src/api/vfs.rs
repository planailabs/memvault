//! Virtual filesystem endpoints — organise nodes into a path hierarchy.
//!
//! Directories are entities with `kind = "vfs:dir"`.  Parent→child edges
//! use `relation = "vfs:child"` with a `"name"` property.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use memvault_api::MemvaultClient;
use memvault_core::{EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Edge, Entity};
use serde::{Deserialize, Serialize};

use crate::api::auth::RequireAuth;
use crate::error::ApiError;
use crate::AppState;

const VFS_DIR_KIND: &str = "vfs:dir";
const VFS_CHILD_REL: &str = "vfs:child";

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

// ── Helpers ────────────────────────────────────────────────────────

fn split_path(path: &str) -> Result<Vec<&str>, ApiError> {
    let path = path.trim();
    if !path.starts_with('/') {
        return Err(ApiError::bad_request("path must be absolute (start with /)"));
    }
    Ok(path.split('/').filter(|s| !s.is_empty()).collect())
}

/// Find or create the VFS root entity (tagged `vfs:root`).
async fn ensure_root(client: &dyn MemvaultClient) -> Result<EntityId, ApiError> {
    let entities = client.list_entities(500).await.map_err(|e| ApiError::internal(e.to_string()))?;
    let mut candidates: Vec<[u8; 32]> = Vec::new();
    for e in &entities {
        if e.kind == VFS_DIR_KIND {
            let node_id = format!("entity:{}", hex::encode(e.id.0));
            let tags = client.get_tags(&node_id).await.unwrap_or_default();
            if tags.iter().any(|(s, l)| s == "vfs" && l == "root") {
                candidates.push(e.id.0);
            }
        }
    }
    if !candidates.is_empty() {
        candidates.sort();
        return Ok(EntityId(candidates[0]));
    }
    // Create root.
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!("/"));
    let entity = Entity {
        id: EntityId::random(),
        kind: VFS_DIR_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    let id = client.add_entity(entity, Visibility::Internal).await.map_err(|e| ApiError::internal(e.to_string()))?;
    let node_id = format!("entity:{}", hex::encode(id.0));
    client.add_tags(&node_id, vec![("vfs".into(), "root".into())]).await.map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(id)
}

/// Find a child by name under a parent entity.
async fn find_child(
    client: &dyn MemvaultClient,
    parent: &NodeRef,
) -> Result<Vec<(String, NodeRef, EdgeId)>, ApiError> {
    let edges = client.edges_of(parent).await.map_err(|e| ApiError::internal(e.to_string()))?;
    let mut children = Vec::new();
    for (src, edge) in &edges {
        if src != parent {
            continue;
        }
        if edge.relation == VFS_CHILD_REL {
            let name = edge
                .props
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            children.push((name, edge.target.clone(), EdgeId(edge.id.0)));
        }
    }
    Ok(children)
}

/// Find a specific named child.
async fn find_named_child(
    client: &dyn MemvaultClient,
    parent: &NodeRef,
    name: &str,
) -> Result<Option<(NodeRef, EdgeId)>, ApiError> {
    let children = find_child(client, parent).await?;
    let mut best: Option<(NodeRef, EdgeId)> = None;
    for (n, target, eid) in children {
        if n == name {
            match &best {
                Some((_, existing)) if existing.0 <= eid.0 => {}
                _ => best = Some((target, eid)),
            }
        }
    }
    Ok(best)
}

/// Resolve a path to a NodeRef.
async fn resolve_path(
    client: &dyn MemvaultClient,
    path: &str,
) -> Result<Option<(NodeRef, Option<EdgeId>)>, ApiError> {
    let components = split_path(path)?;
    let root = ensure_root(client).await?;
    if components.is_empty() {
        return Ok(Some((NodeRef::Entity(root), None)));
    }
    let mut current = NodeRef::Entity(root);
    let mut last_eid = None;
    for component in &components {
        match find_named_child(client, &current, component).await? {
            Some((child, eid)) => {
                current = child;
                last_eid = Some(eid);
            }
            None => return Ok(None),
        }
    }
    Ok(Some((current, last_eid)))
}

/// Create a vfs:dir entity and link it as a child.
async fn create_dir_and_link(
    client: &dyn MemvaultClient,
    parent: &NodeRef,
    name: &str,
) -> Result<EntityId, ApiError> {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!(name));
    let entity = Entity {
        id: EntityId::random(),
        kind: VFS_DIR_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    let id = client.add_entity(entity, Visibility::Internal).await.map_err(|e| ApiError::internal(e.to_string()))?;
    let id_bytes = id.0;
    let child = NodeRef::Entity(id);
    create_child_edge(client, parent, &child, name).await?;
    Ok(EntityId(id_bytes))
}

/// Create a vfs:child edge with a name prop.
async fn create_child_edge(
    client: &dyn MemvaultClient,
    parent: &NodeRef,
    child: &NodeRef,
    name: &str,
) -> Result<EdgeId, ApiError> {
    // Check for collisions.
    if find_named_child(client, parent, name).await?.is_some() {
        return Err(ApiError::bad_request(format!("entry '{name}' already exists in directory")));
    }
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::Value::String(name.to_string()));
    let edge = Edge {
        id: EdgeId::random(),
        relation: VFS_CHILD_REL.to_string(),
        target: child.clone(),
        weight: None,
        props,
        provenance: None,
    };
    client.add_link(parent, edge, Visibility::Internal).await.map_err(|e| ApiError::internal(e.to_string()))
}

/// Ensure all path components exist as directories, returning the final parent NodeRef.
async fn ensure_parents(
    client: &dyn MemvaultClient,
    components: &[&str],
) -> Result<NodeRef, ApiError> {
    let root = ensure_root(client).await?;
    let mut current = NodeRef::Entity(root);
    for component in components {
        match find_named_child(client, &current, component).await? {
            Some((child, _)) => current = child,
            None => {
                let id = create_dir_and_link(client, &current, component).await?;
                current = NodeRef::Entity(id);
            }
        }
    }
    Ok(current)
}

async fn resolve_vfs_type(client: &dyn MemvaultClient, node: &NodeRef) -> String {
    match node {
        NodeRef::Entity(eid) => {
            if let Ok(Some(e)) = client.get_entity(eid).await {
                if e.kind == VFS_DIR_KIND {
                    return "dir".to_string();
                }
            }
            "entity".to_string()
        }
        NodeRef::Doc(_) => "doc".to_string(),
        NodeRef::Attachment(_) => "attachment".to_string(),
    }
}

// ── Public helper for integration with other endpoints ─────────────

/// Link a node at a VFS path, creating intermediate directories.
/// Used by doc/entity/attachment creation endpoints.
pub async fn link_node_at_path(
    client: &dyn MemvaultClient,
    path: &str,
    node_id: &str,
) -> Result<(), ApiError> {
    let components = split_path(path)?;
    if components.is_empty() {
        return Err(ApiError::bad_request("cannot link to root path"));
    }
    let target = NodeRef::from_tag_label(node_id)
        .ok_or_else(|| ApiError::bad_request("invalid node_id"))?;
    let (parent_parts, file_name) = components.split_at(components.len() - 1);
    let file_name = file_name[0];
    let parent = ensure_parents(client, parent_parts).await?;
    create_child_edge(client, &parent, &target, file_name).await?;
    Ok(())
}

// ── Route handlers ─────────────────────────────────────────────────

/// GET /api/v1/vfs?path=/projects&recursive=false
pub async fn vfs_ls(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<VfsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (node, _) = resolve_path(state.client.as_ref(), &params.path)
        .await?
        .ok_or_else(|| ApiError::not_found("path not found"))?;
    let recursive = params.recursive.unwrap_or(false);
    let entries = ls_entries(state.client.as_ref(), &node, recursive, "").await?;
    Ok(Json(serde_json::json!({
        "path": params.path,
        "entries": entries,
    })))
}

fn ls_entries<'a>(
    client: &'a dyn MemvaultClient,
    node: &'a NodeRef,
    recursive: bool,
    prefix: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<VfsEntry>, ApiError>> + Send + 'a>> {
    Box::pin(async move {
        let children = find_child(client, node).await?;
        let mut entries = Vec::new();
        for (name, target, eid) in &children {
            let display_name = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let nt = resolve_vfs_type(client, target).await;
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
    match resolve_path(state.client.as_ref(), &params.path).await? {
        Some((node, edge_id)) => Ok(Json(serde_json::json!({
            "path": params.path,
            "node_id": node.tag_label(),
            "node_type": resolve_vfs_type(state.client.as_ref(), &node).await,
            "edge_id": edge_id.map(|e| hex::encode(e.0)),
        }))),
        None => Err(ApiError::not_found("path not found")),
    }
}

/// POST /api/v1/vfs/mkdir
pub async fn vfs_mkdir(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsMkdirRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let components = split_path(&req.path)?;
    if components.is_empty() {
        let root = ensure_root(state.client.as_ref()).await?;
        return Ok((
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "path": req.path,
                "entity_id": format!("entity:{}", hex::encode(root.0)),
            })),
        ));
    }
    let parent = ensure_parents(state.client.as_ref(), &components).await?;
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
    let components = split_path(&req.path)?;
    if components.is_empty() {
        return Err(ApiError::bad_request("cannot link to root path"));
    }
    let target = NodeRef::from_tag_label(&req.target)
        .ok_or_else(|| ApiError::bad_request("invalid target — expected entity:<hex>, doc:<hex>, or attachment:<hex>"))?;

    let (parent_parts, file_name) = components.split_at(components.len() - 1);
    let file_name = file_name[0];
    let parent = ensure_parents(state.client.as_ref(), parent_parts).await?;
    let edge_id = create_child_edge(state.client.as_ref(), &parent, &target, file_name).await?;

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
    let components = split_path(&params.path)?;
    if components.is_empty() {
        return Err(ApiError::bad_request("cannot unlink root"));
    }
    let (parent_parts, file_name) = components.split_at(components.len() - 1);
    let file_name = file_name[0];

    let root = ensure_root(state.client.as_ref()).await?;
    let mut current = NodeRef::Entity(root);
    for component in parent_parts {
        current = find_named_child(state.client.as_ref(), &current, component)
            .await?
            .ok_or_else(|| ApiError::not_found(format!("component '{component}' not found")))?
            .0;
    }
    let (_target, edge_id) = find_named_child(state.client.as_ref(), &current, file_name)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("'{file_name}' not found in directory")))?;
    state.client.remove_link_from(&current, &edge_id).await.map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// POST /api/v1/vfs/mv
pub async fn vfs_mv(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VfsMvRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Resolve source.
    let (source_node, source_edge) = resolve_path(state.client.as_ref(), &req.from)
        .await?
        .ok_or_else(|| ApiError::not_found("source path not found"))?;
    let source_edge = source_edge.ok_or_else(|| ApiError::bad_request("cannot move root"))?;

    // Find source's parent to unlink.
    let from_components = split_path(&req.from)?;
    let (from_parent_parts, _) = from_components.split_at(from_components.len() - 1);
    let from_parent = {
        let root = ensure_root(state.client.as_ref()).await?;
        let mut current = NodeRef::Entity(root);
        for component in from_parent_parts {
            current = find_named_child(state.client.as_ref(), &current, component)
                .await?
                .ok_or_else(|| ApiError::not_found("parent not found"))?
                .0;
        }
        current
    };

    // Unlink from source.
    state.client.remove_link_from(&from_parent, &source_edge).await.map_err(|e| ApiError::internal(e.to_string()))?;

    // Link at destination.
    let to_components = split_path(&req.to)?;
    if to_components.is_empty() {
        return Err(ApiError::bad_request("cannot link to root path"));
    }
    let (to_parent_parts, to_name) = to_components.split_at(to_components.len() - 1);
    let to_name = to_name[0];
    let to_parent = ensure_parents(state.client.as_ref(), to_parent_parts).await?;
    create_child_edge(state.client.as_ref(), &to_parent, &source_node, to_name).await?;

    Ok(Json(serde_json::json!({
        "from": req.from,
        "to": req.to,
        "status": "moved",
    })))
}
