//! VFS (Virtual Filesystem) helpers — shared logic for managing the directory tree.
//!
//! Each bucket has its own VFS root, identified by tags `(vfs, root)` + `(bucket, <id>)`.
//! All functions require a `bucket_id` parameter. There is no global/unscoped VFS.

use std::collections::BTreeMap;

use memvault_core::{BucketId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Edge, Entity};

use crate::MemvaultClient;
use crate::error::Result;

pub const VFS_DIR_KIND: &str = "vfs:dir";
pub const VFS_CHILD_REL: &str = "vfs:child";

/// Get the default bucket for VFS operations.
/// Returns a zero BucketId as fallback if no buckets exist (pre-genesis).
pub async fn default_bucket(client: &dyn MemvaultClient) -> BucketId {
    client
        .default_bucket_id()
        .await
        .unwrap_or(BucketId([0u8; 32]))
}

/// Find or create the VFS root entity for a specific bucket.
///
/// Searches by `(vfs, root)` + `(bucket, <bucket_id>)` tags.
/// Creates a new root if none exists for this bucket.
pub async fn ensure_root(client: &dyn MemvaultClient, bucket_id: &BucketId) -> Result<EntityId> {
    let bucket_hex = hex::encode(bucket_id.0);
    let entities = client.list_entities(500, None).await?;
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

/// Resolve a VFS path to its target node within a bucket.
/// Returns `None` if any component is missing.
pub async fn resolve_path(
    client: &dyn MemvaultClient,
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
pub async fn create_dir(
    client: &dyn MemvaultClient,
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
/// Returns error if name already exists.
pub async fn create_child_edge(
    client: &dyn MemvaultClient,
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

/// Ensure all path components exist as directories within a bucket, creating missing ones.
/// Returns the NodeRef of the deepest directory.
pub async fn ensure_dir_path(
    client: &dyn MemvaultClient,
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
pub async fn link_at_path(
    client: &dyn MemvaultClient,
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
pub async fn link_node_at_path(
    client: &dyn MemvaultClient,
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
