//! Deterministic blockstore rebuild.
//!
//! Given the raw BLOCKS table, `rebuild_store` reconstructs **all** derived
//! state: secondary indexes, bucket metadata, legacy adoption, VFS repair,
//! and the full-text search index.
//!
//! A `BLOCKSTORE_VERSION` is stored alongside the data.  On startup, if the
//! stored version is older than the code's version, a full rebuild runs
//! automatically.  `memctl repair-index` forces a rebuild regardless of
//! version.
//!
//! **Determinism**: same BLOCKS + same version + same peer identity =
//! identical derived state on every node.

use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};
use crate::local::LocalClient;
use memvault_core::{BucketId, EntityId};

/// Bump this when index structure, adoption logic, or derived-state
/// semantics change.  Any store with a lower version will be fully
/// rebuilt on next open.
pub const BLOCKSTORE_VERSION: u32 = 1;

/// Summary of what the rebuild did.
#[derive(Debug, Default)]
pub struct RebuildReport {
    pub blocks_total: usize,
    pub envelopes_indexed: usize,
    pub buckets_rebuilt: usize,
    pub entities_adopted: usize,
    pub docs_adopted: usize,
    pub vfs_nodes_adopted: usize,
    pub vfs_roots_retracted: usize,
    pub vfs_orphans_linked: usize,
    pub vfs_pending_migrated: usize,
    pub docs_indexed: usize,
    pub entities_indexed: usize,
    pub attachments_indexed: usize,
}

/// Perform a full deterministic rebuild of all derived state from BLOCKS.
///
/// This is the single source of truth for what a store at
/// `BLOCKSTORE_VERSION` should look like.  Both automatic startup
/// rebuilds and `memctl repair-index` call this function.
pub async fn rebuild_store(client: &LocalClient) -> Result<RebuildReport> {
    let store = client.store();
    let mut report = RebuildReport::default();

    // ── Phase 1: Rebuild secondary indexes ─────────────────────────────

    store
        .clear_secondary_indexes()
        .map_err(|e| ApiError::Other(format!("clear indexes: {e}")))?;

    let blocks = store
        .iter_blocks()
        .map_err(|e| ApiError::Other(format!("iter blocks: {e}")))?;
    report.blocks_total = blocks.len();

    for (cid, data) in &blocks {
        if store.reindex_block(cid, data).unwrap_or(false) {
            report.envelopes_indexed += 1;
        }
    }

    // ── Phase 2: Rebuild bucket metadata ───────────────────────────────

    for (cid, data) in &blocks {
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
            let is_bucket_decl = val
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|tags| {
                    tags.iter().any(|t| {
                        if let Some(arr) = t.as_array() {
                            arr.first().and_then(|v| v.as_str()) == Some("kind")
                                && arr.get(1).and_then(|v| v.as_str()) == Some("bucket-decl")
                        } else {
                            false
                        }
                    })
                })
                .unwrap_or(false);

            if is_bucket_decl {
                if let Some(bucket_id) = val
                    .get("bucket_id")
                    .and_then(|v| serde_json::from_value::<[u8; 32]>(v.clone()).ok())
                {
                    let _ = store.put_bucket(&bucket_id, cid);
                    report.buckets_rebuilt += 1;
                }
            }
        }
    }

    // ── Phase 3: Adopt unbucketed locally-authored data ────────────────

    let legacy_bucket = client
        .legacy_bucket_id()
        .unwrap_or(BucketId([0u8; 32]));

    // 3a: Adopt entities
    let entities = client.list_entities_unscoped(50_000).await?;
    for entity in &entities {
        if client
            .adopt_entity_into_bucket(&entity.id, &legacy_bucket)
            .await?
        {
            report.entities_adopted += 1;
        }
    }

    // 3b: Adopt docs
    let doc_ids = client.list_doc_ids_unscoped(50_000).await?;
    for doc_id in &doc_ids {
        if client
            .adopt_doc_into_bucket(doc_id, &legacy_bucket)
            .await?
        {
            report.docs_adopted += 1;
        }
    }

    // 3c: Adopt VFS nodes
    {
        let bucket_hex = hex::encode(legacy_bucket.0);
        let mut bucketed_root_exists = false;
        let mut unbucketed_roots: Vec<[u8; 32]> = Vec::new();

        for e in &entities {
            if e.kind != crate::vfs::VFS_DIR_KIND {
                continue;
            }
            let node_id = format!("entity:{}", hex::encode(e.id.0));
            let tags = client.get_tags(&node_id).await.unwrap_or_default();
            let has_root = tags.iter().any(|(s, l)| s == "vfs" && l == "root");
            if !has_root {
                continue;
            }
            if tags.iter().any(|(s, _)| s == "bucket") {
                bucketed_root_exists = true;
            } else {
                unbucketed_roots.push(e.id.0);
            }
        }

        if !unbucketed_roots.is_empty() {
            if bucketed_root_exists {
                for root_id in &unbucketed_roots {
                    let node_id = format!("entity:{}", hex::encode(root_id));
                    if client
                        .retract_node(&node_id, "dangling VFS root without bucket")
                        .await
                        .is_ok()
                    {
                        report.vfs_roots_retracted += 1;
                    }
                }
            } else {
                let mut did_adopt = false;
                for root_id in &unbucketed_roots {
                    let eid = EntityId(*root_id);
                    if !did_adopt && client.entity_has_local_author(&eid) {
                        let node_id = format!("entity:{}", hex::encode(root_id));
                        let _ = client
                            .add_tags(
                                &node_id,
                                vec![("bucket".into(), bucket_hex.clone())],
                            )
                            .await;
                        report.vfs_nodes_adopted += 1;
                        did_adopt = true;
                    } else if did_adopt {
                        let dup_id = format!("entity:{}", hex::encode(root_id));
                        if client
                            .retract_node(&dup_id, "duplicate dangling VFS root")
                            .await
                            .is_ok()
                        {
                            report.vfs_roots_retracted += 1;
                        }
                    }
                }
            }
        }

        // Tag unbucketed locally-authored VFS dirs
        for e in &entities {
            if e.kind != crate::vfs::VFS_DIR_KIND {
                continue;
            }
            if !client.entity_has_local_author(&e.id) {
                continue;
            }
            let node_id = format!("entity:{}", hex::encode(e.id.0));
            let tags = client.get_tags(&node_id).await.unwrap_or_default();
            if tags.iter().any(|(s, _)| s == "bucket") {
                continue;
            }
            let idx = client.index_ref().read().await;
            if idx.is_retracted(&node_id) {
                continue;
            }
            drop(idx);
            let _ = client
                .add_tags(&node_id, vec![("bucket".into(), bucket_hex.clone())])
                .await;
            report.vfs_nodes_adopted += 1;
        }
    }

    // ── Phase 4: VFS tree repair ───────────────────────────────────────

    report.vfs_orphans_linked = repair_vfs_tree(client).await?;

    // ── Phase 5: Pending VFS entries ───────────────────────────────────

    let pending_cids = store
        .query_by_tag("vfs_status", "pending_repair", 0, 10_000)
        .unwrap_or_default();
    for cid in &pending_cids {
        if let Ok(Some(data)) = store.get_block(cid) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                let entity_tag = val
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .and_then(|tags| {
                        tags.iter().find_map(|t| {
                            let arr = t.as_array()?;
                            let scope = arr.first()?.as_str()?;
                            let label = arr.get(1)?.as_str()?;
                            if scope == "entity" {
                                Some(label.to_string())
                            } else {
                                None
                            }
                        })
                    });
                let intended_path = val
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .and_then(|tags| {
                        tags.iter().find_map(|t| {
                            let arr = t.as_array()?;
                            let scope = arr.first()?.as_str()?;
                            let label = arr.get(1)?.as_str()?;
                            if scope == "vfs_intended_path" {
                                Some(label.to_string())
                            } else {
                                None
                            }
                        })
                    });
                if let (Some(entity_hex), Some(path)) = (entity_tag, intended_path) {
                    let node_ref = format!("entity:{entity_hex}");
                    let bucket = client
                        .legacy_bucket_id()
                        .unwrap_or(BucketId([0u8; 32]));
                    if crate::vfs::link_node_at_path(client, &bucket, &path, &node_ref)
                        .await
                        .is_ok()
                    {
                        let _ = client
                            .remove_tags(
                                &node_ref,
                                vec![("vfs_status".into(), "pending_repair".into())],
                            )
                            .await;
                        let _ = client
                            .add_tags(
                                &node_ref,
                                vec![("vfs_status".into(), "linked".into())],
                            )
                            .await;
                        report.vfs_pending_migrated += 1;
                    }
                }
            }
        }
    }

    // ── Phase 6: Rebuild full-text search index ────────────────────────

    let (d, e, a) = client.populate_index().await?;
    report.docs_indexed = d;
    report.entities_indexed = e;
    report.attachments_indexed = a;

    // ── Stamp the version ──────────────────────────────────────────────

    store
        .set_schema_version(BLOCKSTORE_VERSION)
        .map_err(|e| ApiError::Other(format!("set blockstore version: {e}")))?;

    Ok(report)
}

/// Check stored version and rebuild if needed.  Returns the report if a
/// rebuild ran, or None if the store was already at the current version.
pub async fn rebuild_if_needed(client: &LocalClient) -> Result<Option<RebuildReport>> {
    let stored = client
        .store()
        .schema_version()
        .map_err(|e| ApiError::Other(format!("read blockstore version: {e}")))?;

    if stored >= BLOCKSTORE_VERSION {
        return Ok(None);
    }

    tracing::info!(
        stored_version = stored,
        target_version = BLOCKSTORE_VERSION,
        "blockstore version mismatch — rebuilding derived state"
    );

    let report = rebuild_store(client).await?;

    tracing::info!(
        stored_version = stored,
        target_version = BLOCKSTORE_VERSION,
        blocks = report.blocks_total,
        envelopes = report.envelopes_indexed,
        entities_adopted = report.entities_adopted,
        docs_adopted = report.docs_adopted,
        "blockstore rebuild complete"
    );

    Ok(Some(report))
}

// ── VFS tree repair (moved from memctl) ────────────────────────────────

async fn repair_vfs_tree(client: &LocalClient) -> Result<usize> {
    use memvault_core::{EdgeId, NodeRef};

    let entities = client.list_entities_unscoped(10_000).await?;
    let mut vfs_dirs: Vec<(EntityId, Vec<(String, String)>)> = Vec::new();

    for e in &entities {
        if e.kind != crate::vfs::VFS_DIR_KIND {
            continue;
        }
        let node_id = format!("entity:{}", hex::encode(e.id.0));
        let idx = client.index_ref().read().await;
        if idx.is_retracted(&node_id) {
            continue;
        }
        drop(idx);
        let tags = client.get_tags(&node_id).await.unwrap_or_default();
        vfs_dirs.push((e.id.clone(), tags));
    }

    // Find the canonical root (the one with vfs:root tag).
    let root_id = vfs_dirs
        .iter()
        .find(|(_, tags)| tags.iter().any(|(s, l)| s == "vfs" && l == "root"))
        .map(|(id, _)| id.clone());

    let root_id = match root_id {
        Some(r) => r,
        None => return Ok(0), // no VFS root — nothing to repair
    };

    // Walk the tree from root, collecting reachable entity IDs.
    let root_ref = NodeRef::Entity(root_id.clone());
    let reachable_set = {
        let mut reachable = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(root_ref.clone());
        reachable.insert(root_id.0);

        while let Some(node) = queue.pop_front() {
            if let Ok(edges) = client.edges_of(&node).await {
                for (target, edge) in &edges {
                    if edge.relation == crate::vfs::VFS_CHILD_REL {
                        if let NodeRef::Entity(eid) = target {
                            if reachable.insert(eid.0) {
                                queue.push_back(target.clone());
                            }
                        }
                    }
                }
            }
        }
        reachable
    };

    // Link orphaned VFS dirs to the root.
    let mut linked = 0usize;
    for (eid, _) in &vfs_dirs {
        if reachable_set.contains(&eid.0) {
            continue;
        }
        let name = format!("orphan-{}", &hex::encode(eid.0)[..8]);
        let edge = memvault_doc::Edge {
            id: EdgeId::random(),
            relation: crate::vfs::VFS_CHILD_REL.to_string(),
            target: NodeRef::Entity(eid.clone()),
            weight: None,
            props: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("name".to_string(), serde_json::json!(name));
                m
            },
            provenance: None,
        };
        if client
            .add_link(&root_ref, edge, memvault_core::Visibility::Internal)
            .await
            .is_ok()
        {
            linked += 1;
        }
    }

    Ok(linked)
}
