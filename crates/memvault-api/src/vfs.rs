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

// Wire constants live in memvault-core so the WASM web build can reach
// them without pulling this server-only crate. Re-exported here for
// back-compat with `memvault_api::vfs::VFS_*` import sites.
pub use memvault_core::{VFS_CHILD_REL, VFS_DIR_KIND};

/// Find or create the VFS root entity for a specific bucket.
pub async fn ensure_root<C: MemvaultClient + ?Sized>(
    client: &C,
    bucket_id: &BucketId,
) -> Result<EntityId> {
    let bucket_hex = hex::encode(bucket_id.0);
    // Scan UNCAPPED: there is exactly one VFS root per bucket and it must be
    // found deterministically. A fixed cap (e.g. 500) could drop the root in a
    // bucket with more entities, making `ensure_root` mint a *second* root —
    // then mkdir writes under one root while resolve/ls/tree read another
    // ("created but not found", 500s). See standards: no correctness-bounding
    // magic limits on lookups that must be exhaustive.
    let entities = client.list_entities(usize::MAX, Some(bucket_id)).await?;
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
        .add_entity_internal(entity, Visibility::Internal, Some(bucket_id))
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
        .add_entity_internal(entity, Visibility::Internal, Some(bucket_id))
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VfsEntry {
    pub name: String,
    pub node_id: String,
    pub node_type: String,
    pub edge_id: String,
}

/// A node in the structured VFS tree returned by [`walk_tree`].
///
/// `name` is the path-component name (empty for the requested root).
/// `edge_id` is the edge from this node's parent to this node, `None` for the root.
/// `children` is populated only for directories; for leaves it is empty.
#[derive(Debug, serde::Serialize)]
pub struct VfsTreeNode {
    pub name: String,
    pub node: NodeRef,
    pub node_type: String,
    pub edge_id: Option<EdgeId>,
    pub children: Vec<VfsTreeNode>,
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

/// Walk the VFS subtree rooted at `path` and return it as a [`VfsTreeNode`].
///
/// `max_depth` bounds the recursion: depth 0 returns just the root with no
/// children; `usize::MAX` walks the full tree. Children are sorted by name.
pub fn walk_tree<'a, C: MemvaultClient + ?Sized + Sync>(
    client: &'a C,
    bucket_id: &'a BucketId,
    path: &'a str,
    max_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<VfsTreeNode>> + Send + 'a>> {
    Box::pin(async move {
        let (node, edge) = resolve_path(client, bucket_id, path)
            .await?
            .ok_or_else(|| crate::error::ApiError::Other(format!("path not found: {path}")))?;
        let name = if path == "/" || path.is_empty() {
            "/".to_string()
        } else {
            path.rsplit('/').next().unwrap_or(path).to_string()
        };
        walk_node(client, name, node, edge, max_depth, 0).await
    })
}

fn walk_node<'a, C: MemvaultClient + ?Sized + Sync>(
    client: &'a C,
    name: String,
    node: NodeRef,
    edge_id: Option<EdgeId>,
    max_depth: usize,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<VfsTreeNode>> + Send + 'a>> {
    Box::pin(async move {
        let node_type = resolve_node_type(client, &node).await;
        let mut children = Vec::new();
        if node_type == "dir" && depth < max_depth {
            let kids = list_children(client, &node).await?;
            for (kid_name, kid_node, kid_edge) in kids {
                let child =
                    walk_node(client, kid_name, kid_node, Some(kid_edge), max_depth, depth + 1)
                        .await?;
                children.push(child);
            }
            children.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Ok(VfsTreeNode {
            name,
            node,
            node_type,
            edge_id,
            children,
        })
    })
}

/// List entries under a VFS path. When `recursive`, names of nested entries
/// are joined with `/` separators.
pub async fn ls<C: MemvaultClient + ?Sized + Sync>(
    client: &C,
    bucket_id: &BucketId,
    path: &str,
    recursive: bool,
) -> Result<Vec<VfsEntry>> {
    let depth = if recursive { usize::MAX } else { 1 };
    let tree = walk_tree(client, bucket_id, path, depth).await?;
    let mut out = Vec::new();
    flatten_children(&tree, "", &mut out);
    Ok(out)
}

fn flatten_children(node: &VfsTreeNode, prefix: &str, out: &mut Vec<VfsEntry>) {
    for child in &node.children {
        let display = if prefix.is_empty() {
            child.name.clone()
        } else {
            format!("{prefix}/{}", child.name)
        };
        out.push(VfsEntry {
            name: display.clone(),
            node_id: child.node.tag_label(),
            node_type: child.node_type.clone(),
            edge_id: child
                .edge_id
                .as_ref()
                .map(|e| hex::encode(e.0))
                .unwrap_or_default(),
        });
        if child.node_type == "dir" {
            flatten_children(child, &display, out);
        }
    }
}

/// Render an ASCII tree of the VFS under `path`.
pub async fn tree<C: MemvaultClient + ?Sized + Sync>(
    client: &C,
    bucket_id: &BucketId,
    path: &str,
    max_depth: usize,
) -> Result<String> {
    let tree = walk_tree(client, bucket_id, path, max_depth).await?;
    let mut buf = String::new();
    buf.push_str(&format!("{}/\n", tree.name));
    render_tree(&tree, &mut buf, "");
    Ok(buf)
}

fn render_tree(node: &VfsTreeNode, buf: &mut String, prefix: &str) {
    let count = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        let is_last = i == count - 1;
        let connector = if is_last { "└── " } else { "├── " };
        let child_prefix_str = if is_last { "    " } else { "│   " };
        if child.node_type == "dir" {
            buf.push_str(&format!("{prefix}{connector}{}/\n", child.name));
            let next_prefix = format!("{prefix}{child_prefix_str}");
            render_tree(child, buf, &next_prefix);
        } else {
            buf.push_str(&format!(
                "{prefix}{connector}{} [{}] ({})\n",
                child.name,
                child.node_type,
                child.node.tag_label()
            ));
        }
    }
}

/// Find all VFS paths that lead to a given target node.
pub async fn find_paths<C: MemvaultClient + ?Sized + Sync>(
    client: &C,
    bucket_id: &BucketId,
    target: &NodeRef,
) -> Result<Vec<String>> {
    let tree = walk_tree(client, bucket_id, "/", 20).await?;
    let mut paths = Vec::new();
    collect_target_paths(&tree, target, "", &mut paths);
    paths.sort();
    Ok(paths)
}

fn collect_target_paths(
    node: &VfsTreeNode,
    target: &NodeRef,
    prefix: &str,
    out: &mut Vec<String>,
) {
    for child in &node.children {
        let child_path = format!("{prefix}/{}", child.name);
        if &child.node == target {
            out.push(child_path.clone());
        }
        if child.node_type == "dir" {
            collect_target_paths(child, target, &child_path, out);
        }
    }
}
