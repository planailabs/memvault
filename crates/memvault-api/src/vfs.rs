//! VFS (Virtual Filesystem) helpers — shared logic for managing the directory tree.
//!
//! Each bucket has its own VFS root, identified by tags `(vfs, root)` + `(bucket, <id>)`.
//! All functions require a `bucket_id` parameter. There is no global/unscoped VFS.
//!
//! Free functions take any `MemvaultClient` (including unsized `dyn`) so they
//! can be composed by `MemvaultClient` default trait methods and ordinary
//! callers alike.

use std::collections::BTreeMap;

use memvault_core::{BucketId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Edge, Entity};

use crate::MemvaultClient;
use crate::error::Result;

pub const VFS_DIR_KIND: &str = "vfs:dir";
pub const VFS_CHILD_REL: &str = "vfs:child";

/// Get the default bucket for VFS operations.
/// Returns a zero BucketId as fallback if no buckets exist (pre-genesis).
pub async fn default_bucket<C: MemvaultClient + ?Sized>(client: &C) -> BucketId {
    client
        .default_bucket_id()
        .await
        .unwrap_or(BucketId([0u8; 32]))
}

/// Find or create the VFS root entity for a specific bucket.
pub async fn ensure_root<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
) -> Result<EntityId> {
    let bucket_hex = hex::encode(bucket_id.0);
    let entities = client.list_entities(500, Some(bucket_id)).await?;
    let mut candidates: Vec<[u8; 32]> = Vec::new();

    for e in &entities {
        if e.kind != VFS_DIR_KIND {
            continue;
        }
        let node_id = format!("entity:{}", hex::encode(e.id.0));
        let tags = client.get_tags(&node_id).await.unwrap_or_default();
        let has_root = tags.iter().any(|(s, l)| s == "vfs" && l == "root");
        let has_bucket = tags.iter().any(|(s, l)| s == "bucket" && l == &bucket_hex);
        if has_root && has_bucket {
            candidates.push(e.id.0);
        }
    }

    if !candidates.is_empty() {
        candidates.sort();
        return Ok(EntityId(candidates[0]));
    }

    // Create root for this bucket.
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!("/"));
    let entity = Entity {
        id: EntityId::random(),
        kind: VFS_DIR_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    let id = client
        .add_entity(entity, Visibility::Internal, Some(bucket_id))
        .await?;
    let node_id = format!("entity:{}", hex::encode(id.0));
    client
        .add_tags(
            &node_id,
            vec![("vfs".into(), "root".into()), ("bucket".into(), bucket_hex)],
        )
        .await?;
    Ok(id)
}

/// List all vfs:child entries under a parent node (outgoing edges only).
pub async fn list_children<C: MemvaultClient + ?Sized>(
    client: &C,
    parent: &NodeRef,
) -> Result<Vec<(String, NodeRef, EdgeId)>> {
    let edges = client.edges_of(parent).await?;
    let mut seen: BTreeMap<String, (NodeRef, EdgeId)> = BTreeMap::new();
    for (src, edge) in &edges {
        if src != parent || edge.relation != VFS_CHILD_REL {
            continue;
        }
        let name = edge
            .props
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let eid = EdgeId(edge.id.0);
        match seen.get(&name) {
            Some((_, existing)) if existing.0 <= eid.0 => {}
            _ => {
                seen.insert(name, (edge.target.clone(), eid));
            }
        }
    }
    Ok(seen
        .into_iter()
        .map(|(name, (target, eid))| (name, target, eid))
        .collect())
}

/// Find a named child under a parent.
pub async fn find_named_child<C: MemvaultClient + ?Sized>(
    client: &C,
    parent: &NodeRef,
    name: &str,
) -> Result<Option<(NodeRef, EdgeId)>> {
    let children = list_children(client, parent).await?;
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

/// Resolve a VFS path to its target node within a bucket.
pub async fn resolve_path<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
    path: &str,
) -> Result<Option<(NodeRef, Option<EdgeId>)>> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let root = ensure_root(client, bucket_id).await?;
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

/// Create a vfs:dir entity with the given name.
pub async fn create_dir<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
    name: &str,
) -> Result<EntityId> {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!(name));
    let entity = Entity {
        id: EntityId::random(),
        kind: VFS_DIR_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    client
        .add_entity(entity, Visibility::Internal, Some(bucket_id))
        .await
}

/// Create a vfs:child edge from parent to child with a name prop.
pub async fn create_child_edge<C: MemvaultClient + ?Sized>(
    client: &C,
    parent: &NodeRef,
    child: &NodeRef,
    name: &str,
) -> Result<EdgeId> {
    if find_named_child(client, parent, name).await?.is_some() {
        return Err(crate::error::ApiError::Other(format!(
            "entry '{name}' already exists in directory"
        )));
    }
    let mut props = BTreeMap::new();
    props.insert(
        "name".to_string(),
        serde_json::Value::String(name.to_string()),
    );
    let edge = Edge {
        id: EdgeId::random(),
        relation: VFS_CHILD_REL.to_string(),
        target: child.clone(),
        weight: None,
        props,
        provenance: None,
    };
    client.add_link(parent, edge, Visibility::Internal).await
}

/// Ensure all path components exist as directories within a bucket.
pub async fn ensure_dir_path<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
    path: &str,
) -> Result<NodeRef> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let root = ensure_root(client, bucket_id).await?;
    let mut current = NodeRef::Entity(root);
    for component in &components {
        match find_named_child(client, &current, component).await? {
            Some((child, _)) => current = child,
            None => {
                let id = create_dir(client, bucket_id, component).await?;
                let child = NodeRef::Entity(id);
                match create_child_edge(client, &current, &child, component).await {
                    Ok(_) => {}
                    Err(_) => {
                        if let Some((existing, _)) =
                            find_named_child(client, &current, component).await?
                        {
                            current = existing;
                            continue;
                        }
                        return Err(crate::error::ApiError::Other(format!(
                            "failed to create directory component '{component}'"
                        )));
                    }
                }
                current = child;
            }
        }
    }
    Ok(current)
}

/// Link a node at a VFS path within a bucket, creating intermediate directories as needed.
pub async fn link_at_path<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
    path: &str,
    target: &NodeRef,
) -> Result<EdgeId> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        return Err(crate::error::ApiError::Other(
            "cannot link to root path".into(),
        ));
    }
    let (parent_parts, name) = components.split_at(components.len() - 1);
    let name = name[0];
    let parent_path: String = if parent_parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parent_parts.join("/"))
    };
    let parent = ensure_dir_path(client, bucket_id, &parent_path).await?;
    create_child_edge(client, &parent, target, name).await
}

/// Convenience: link a node (by its "type:hex" ID string) at a VFS path in a bucket.
pub async fn link_node_at_path<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
    path: &str,
    node_id: &str,
) -> Result<()> {
    let target = NodeRef::from_tag_label(node_id)
        .ok_or_else(|| crate::error::ApiError::Other(format!("invalid node_id: {node_id}")))?;
    link_at_path(client, bucket_id, path, &target).await?;
    Ok(())
}

/// Resolve the display type for a node ("dir", "entity", "doc", "file").
pub async fn resolve_node_type<C: MemvaultClient + ?Sized>(
    client: &C,
    node: &NodeRef,
) -> String {
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
        NodeRef::Attachment(_) => "file".to_string(),
    }
}

// ── Higher-level helpers (used by MCP, web UI, CLI) ───────────────────

/// A single entry produced by [`ls`].
#[derive(Debug, serde::Serialize)]
pub struct VfsEntry {
    pub name: String,
    pub node_id: String,
    pub node_type: String,
    pub edge_id: String,
}

fn split_path(path: &str) -> Result<Vec<&str>> {
    let path = path.trim();
    if !path.starts_with('/') {
        return Err(crate::error::ApiError::Other(
            "path must be absolute (start with /)".into(),
        ));
    }
    Ok(path.split('/').filter(|s| !s.is_empty()).collect())
}

/// `mkdir -p` for the VFS — ensures all components exist, returns the
/// EntityId of the leaf directory.
pub async fn mkdir<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
    path: &str,
) -> Result<EntityId> {
    let leaf = ensure_dir_path(client, bucket_id, path).await?;
    match leaf {
        NodeRef::Entity(id) => Ok(id),
        _ => Err(crate::error::ApiError::Other(
            "path resolved to non-entity".into(),
        )),
    }
}

/// Remove an entry from a VFS path. The underlying node is not deleted.
pub async fn unlink_path<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
    path: &str,
) -> Result<()> {
    let components = split_path(path)?;
    if components.is_empty() {
        return Err(crate::error::ApiError::Other("cannot unlink root".into()));
    }
    let (parent_parts, file_name) = components.split_at(components.len() - 1);
    let file_name = file_name[0];
    let parent_path = if parent_parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parent_parts.join("/"))
    };
    let (parent, _) = resolve_path(client, bucket_id, &parent_path)
        .await?
        .ok_or_else(|| crate::error::ApiError::Other(format!("parent not found: {parent_path}")))?;
    match find_named_child(client, &parent, file_name).await? {
        Some((_, edge_id)) => {
            client.remove_link_from(&parent, &edge_id).await?;
            Ok(())
        }
        None => Err(crate::error::ApiError::Other(format!(
            "'{file_name}' not found in directory"
        ))),
    }
}

/// Move/rename: unlink from old path, link target at new path.
pub async fn mv_path<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
    from: &str,
    to: &str,
) -> Result<()> {
    let (node, _) = resolve_path(client, bucket_id, from)
        .await?
        .ok_or_else(|| crate::error::ApiError::Other(format!("source not found: {from}")))?;
    unlink_path(client, bucket_id, from).await?;
    link_at_path(client, bucket_id, to, &node).await?;
    Ok(())
}

/// List entries under a VFS path. When `recursive`, names of nested entries
/// are joined with `/` separators.
pub fn ls<'a, C: MemvaultClient + ?Sized + Sync>(
    client: &'a C,
    bucket_id: &'a BucketId,
    path: &'a str,
    recursive: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<VfsEntry>>> + Send + 'a>> {
    Box::pin(async move {
        let (node, _) = resolve_path(client, bucket_id, path)
            .await?
            .ok_or_else(|| crate::error::ApiError::Other(format!("path not found: {path}")))?;
        ls_node(client, &node, recursive).await
    })
}

fn ls_node<'a, C: MemvaultClient + ?Sized + Sync>(
    client: &'a C,
    node: &'a NodeRef,
    recursive: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<VfsEntry>>> + Send + 'a>> {
    Box::pin(async move {
        let children = list_children(client, node).await?;
        let mut entries = Vec::new();
        for (name, target, edge_id) in &children {
            let node_type = resolve_node_type(client, target).await;
            entries.push(VfsEntry {
                name: name.clone(),
                node_id: target.tag_label(),
                node_type: node_type.clone(),
                edge_id: hex::encode(edge_id.0),
            });
            if recursive && node_type == "dir" {
                let sub = ls_node(client, target, true).await?;
                for mut child in sub {
                    child.name = format!("{name}/{}", child.name);
                    entries.push(child);
                }
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    })
}

/// Render an ASCII tree of the VFS under `path`.
pub fn tree<'a, C: MemvaultClient + ?Sized + Sync>(
    client: &'a C,
    bucket_id: &'a BucketId,
    path: &'a str,
    max_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
    Box::pin(async move {
        let (node, _) = resolve_path(client, bucket_id, path)
            .await?
            .ok_or_else(|| crate::error::ApiError::Other(format!("path not found: {path}")))?;
        let label = if path == "/" || path.is_empty() {
            "/".to_string()
        } else {
            path.rsplit('/').next().unwrap_or(path).to_string()
        };
        let mut buf = String::new();
        buf.push_str(&format!("{label}/\n"));
        tree_recurse(client, &node, &mut buf, "", max_depth, 0).await?;
        Ok(buf)
    })
}

fn tree_recurse<'a, C: MemvaultClient + ?Sized + Sync>(
    client: &'a C,
    node: &'a NodeRef,
    buf: &'a mut String,
    prefix: &'a str,
    max_depth: usize,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        if depth >= max_depth {
            return Ok(());
        }
        let entries = ls_node(client, node, false).await?;
        let count = entries.len();
        for (i, entry) in entries.iter().enumerate() {
            let is_last = i == count - 1;
            let connector = if is_last { "└── " } else { "├── " };
            let child_prefix_str = if is_last { "    " } else { "│   " };
            if entry.node_type == "dir" {
                buf.push_str(&format!("{prefix}{connector}{}/\n", entry.name));
                let next_prefix = format!("{prefix}{child_prefix_str}");
                let child_ref = NodeRef::from_tag_label(&entry.node_id).ok_or_else(|| {
                    crate::error::ApiError::Other(format!("invalid child node id: {}", entry.node_id))
                })?;
                tree_recurse(client, &child_ref, buf, &next_prefix, max_depth, depth + 1).await?;
            } else {
                buf.push_str(&format!(
                    "{prefix}{connector}{} [{}] ({})\n",
                    entry.name, entry.node_type, entry.node_id
                ));
            }
        }
        Ok(())
    })
}

/// Find all VFS paths that lead to a given target node.
pub async fn find_paths<C: MemvaultClient + ?Sized + Sync>(
    client: &C,
    bucket_id: &BucketId,
    target: &NodeRef,
) -> Result<Vec<String>> {
    let root = ensure_root(client, bucket_id).await?;
    let mut paths = Vec::new();
    find_paths_recurse(client, &NodeRef::Entity(root), target, "", &mut paths, 20).await?;
    paths.sort();
    Ok(paths)
}

fn find_paths_recurse<'a, C: MemvaultClient + ?Sized + Sync>(
    client: &'a C,
    current: &'a NodeRef,
    target: &'a NodeRef,
    prefix: &'a str,
    paths: &'a mut Vec<String>,
    max_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        if max_depth == 0 {
            return Ok(());
        }
        let children = list_children(client, current).await?;
        for (name, child, _) in &children {
            let child_path = format!("{prefix}/{name}");
            if child == target {
                paths.push(child_path.clone());
            }
            if resolve_node_type(client, child).await == "dir" {
                find_paths_recurse(client, child, target, &child_path, paths, max_depth - 1).await?;
            }
        }
        Ok(())
    })
}
