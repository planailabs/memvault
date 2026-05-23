//! VFS (Virtual Filesystem) helpers — shared logic for managing the directory tree.
//!
//! All functions operate on `&dyn MemvaultClient` and can be used from the HTTP API,
//! web UI server functions, CLI (memctl), and MCP tools.

use std::collections::BTreeMap;

use memvault_core::{EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Edge, Entity};

use crate::error::Result;
use crate::MemvaultClient;

pub const VFS_DIR_KIND: &str = "vfs:dir";
pub const VFS_CHILD_REL: &str = "vfs:child";

/// Find or create the VFS root entity.
/// Searches by `vfs:root` tag first, then by `name: "/"` property as fallback.
/// Creates a new root if none exists.
pub async fn ensure_root(client: &dyn MemvaultClient) -> Result<EntityId> {
    let entities = client.list_entities(500).await?;
    let mut candidates: Vec<[u8; 32]> = Vec::new();
    let mut fallback_candidates: Vec<[u8; 32]> = Vec::new();
    for e in &entities {
        if e.kind != VFS_DIR_KIND {
            continue;
        }
        let node_id = format!("entity:{}", hex::encode(e.id.0));
        let tags = client.get_tags(&node_id).await.unwrap_or_default();
        if tags.iter().any(|(s, l)| s == "vfs" && l == "root") {
            candidates.push(e.id.0);
        }
        if e.props.get("name").and_then(|v| v.as_str()) == Some("/") {
            fallback_candidates.push(e.id.0);
        }
    }
    if !candidates.is_empty() {
        candidates.sort();
        return Ok(EntityId(candidates[0]));
    }
    if !fallback_candidates.is_empty() {
        fallback_candidates.sort();
        let id = EntityId(fallback_candidates[0]);
        let node_id = format!("entity:{}", hex::encode(id.0));
        let _ = client.add_tags(&node_id, vec![("vfs".into(), "root".into())]).await;
        return Ok(id);
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
    let id = client.add_entity(entity, Visibility::Internal).await?;
    let node_id = format!("entity:{}", hex::encode(id.0));
    client.add_tags(&node_id, vec![("vfs".into(), "root".into())]).await?;
    Ok(id)
}

/// List all vfs:child entries under a parent node (outgoing edges only).
/// When duplicate edges share the same name (CRDT conflict), only the
/// canonical entry (smallest EdgeId) is returned.
pub async fn list_children(
    client: &dyn MemvaultClient,
    parent: &NodeRef,
) -> Result<Vec<(String, NodeRef, EdgeId)>> {
    let edges = client.edges_of(parent).await?;
    let mut seen: BTreeMap<String, (NodeRef, EdgeId)> = BTreeMap::new();
    for (src, edge) in &edges {
        if src != parent || edge.relation != VFS_CHILD_REL {
            continue;
        }
        let name = edge.props.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let eid = EdgeId(edge.id.0);
        match seen.get(&name) {
            Some((_, existing)) if existing.0 <= eid.0 => {}
            _ => { seen.insert(name, (edge.target.clone(), eid)); }
        }
    }
    Ok(seen.into_iter().map(|(name, (target, eid))| (name, target, eid)).collect())
}

/// Find a named child under a parent. If multiple edges match (CRDT conflict),
/// picks the one with smallest EdgeId.
pub async fn find_named_child(
    client: &dyn MemvaultClient,
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

/// Resolve a VFS path to its target node. Returns `None` if any component is missing.
pub async fn resolve_path(
    client: &dyn MemvaultClient,
    path: &str,
) -> Result<Option<(NodeRef, Option<EdgeId>)>> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
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

/// Create a vfs:dir entity with the given name.
pub async fn create_dir(client: &dyn MemvaultClient, name: &str) -> Result<EntityId> {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!(name));
    let entity = Entity {
        id: EntityId::random(),
        kind: VFS_DIR_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    client.add_entity(entity, Visibility::Internal).await
}

/// Create a vfs:child edge from parent to child with a name prop.
/// Returns error if name already exists.
pub async fn create_child_edge(
    client: &dyn MemvaultClient,
    parent: &NodeRef,
    child: &NodeRef,
    name: &str,
) -> Result<EdgeId> {
    if find_named_child(client, parent, name).await?.is_some() {
        return Err(crate::error::ApiError::Other(
            format!("entry '{name}' already exists in directory"),
        ));
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
    client.add_link(parent, edge, Visibility::Internal).await
}

/// Ensure all path components exist as directories, creating missing ones.
/// Returns the NodeRef of the deepest directory.
pub async fn ensure_dir_path(
    client: &dyn MemvaultClient,
    path: &str,
) -> Result<NodeRef> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let root = ensure_root(client).await?;
    let mut current = NodeRef::Entity(root);
    for component in &components {
        match find_named_child(client, &current, component).await? {
            Some((child, _)) => current = child,
            None => {
                let id = create_dir(client, component).await?;
                let child = NodeRef::Entity(id);
                match create_child_edge(client, &current, &child, component).await {
                    Ok(_) => {}
                    Err(_) => {
                        // Race: another writer created this entry concurrently.
                        // Use the existing one instead of our orphaned dir.
                        if let Some((existing, _)) = find_named_child(client, &current, component).await? {
                            current = existing;
                            continue;
                        }
                        return Err(crate::error::ApiError::Other(
                            format!("failed to create directory component '{component}'"),
                        ));
                    }
                }
                current = child;
            }
        }
    }
    Ok(current)
}

/// Link a node at a VFS path, creating intermediate directories as needed.
pub async fn link_at_path(
    client: &dyn MemvaultClient,
    path: &str,
    target: &NodeRef,
) -> Result<EdgeId> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        return Err(crate::error::ApiError::Other("cannot link to root path".into()));
    }
    let (parent_parts, name) = components.split_at(components.len() - 1);
    let name = name[0];
    let parent_path: String = if parent_parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parent_parts.join("/"))
    };
    let parent = ensure_dir_path(client, &parent_path).await?;
    create_child_edge(client, &parent, target, name).await
}

/// Convenience: link a node (by its "type:hex" ID string) at a VFS path.
pub async fn link_node_at_path(
    client: &dyn MemvaultClient,
    path: &str,
    node_id: &str,
) -> Result<()> {
    let target = NodeRef::from_tag_label(node_id)
        .ok_or_else(|| crate::error::ApiError::Other(format!("invalid node_id: {node_id}")))?;
    link_at_path(client, path, &target).await?;
    Ok(())
}

/// Resolve the display type for a node ("dir", "entity", "doc", "file").
pub async fn resolve_node_type(client: &dyn MemvaultClient, node: &NodeRef) -> String {
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
