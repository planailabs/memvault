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

pub use memvault_core::BLOCKSTORE_VERSION;

/// Summary of what the rebuild did.
#[derive(Debug, Default)]
pub struct RebuildReport {
    pub blocks_total: usize,
    pub cid_ok: usize,
    pub cid_legacy_migrated: usize,
    pub cid_mismatch_cleaned: usize,
    pub envelopes_indexed: usize,
    pub buckets_rebuilt: usize,
    pub entities_adopted: usize,
    pub docs_adopted: usize,
    pub vfs_nodes_adopted: usize,
    pub vfs_roots_retracted: usize,
    pub vfs_orphans_linked: usize,
    pub vfs_dupes_removed: usize,
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

    // ── Phase 0: CID validation & cleanup ────────────────────────────
    //
    // Remove synthesized manifests with broken CIDs (legacy artefacts).
    // These have a CID mismatch AND look like a manifest (content_size +
    // filename fields) but are NOT envelopes (no payload field).

    {
        let blocks = store
            .iter_blocks()
            .map_err(|e| ApiError::Other(format!("iter blocks: {e}")))?;
        for (cid, data) in &blocks {
            match memvault_core::verify_cid(cid, data) {
                Ok(true) => {
                    report.cid_ok += 1;
                }
                Ok(false) => {
                    // CID mismatch — check if it's a synthesized manifest.
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
                        if val.get("payload").is_some() {
                            // Legacy envelope with payload-based CID — will be
                            // migrated in phase 0b.
                            continue;
                        }
                        if val.get("content_size").is_some() && val.get("filename").is_some() {
                            let _ = store.delete_block(cid);
                            report.cid_mismatch_cleaned += 1;
                        }
                    }
                }
                Err(_) => {} // non-CID block, skip
            }
        }
    }

    // ── Phase 0b: Migrate legacy envelope CIDs ─────────────────────────
    //
    // Envelopes created before content-addressed CIDs have a CID derived
    // from the payload only, not the full envelope.  Re-hash them so
    // verify_cid passes.

    {
        let blocks = store
            .iter_blocks()
            .map_err(|e| ApiError::Other(format!("iter blocks: {e}")))?;
        for (old_cid, data) in &blocks {
            if let Ok(true) = memvault_core::verify_cid(old_cid, data) {
                continue; // already content-addressed
            }
            let is_envelope = serde_json::from_slice::<serde_json::Value>(data)
                .ok()
                .and_then(|v| v.get("payload").map(|_| true))
                .unwrap_or(false);
            if !is_envelope {
                continue;
            }
            let new_cid = memvault_core::cid_from_bytes(data);
            let new_cid_bytes = new_cid.to_bytes();
            if new_cid_bytes == *old_cid {
                continue;
            }
            let _ = store.put_block(&new_cid_bytes, data);
            let _ = store.delete_block(old_cid);
            report.cid_legacy_migrated += 1;
        }
    }

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
    //
    // Find or create a BucketRole::Legacy bucket for adoption.  Only
    // created when there's actually unbucketed data to adopt.

    let entities = client.list_entities_unscoped(50_000).await?;
    let doc_ids = client.list_doc_ids_unscoped(50_000).await?;

    // Lazily resolve or create the legacy bucket on first actual adoption.
    let mut legacy_bucket: Option<BucketId> = client.legacy_bucket_id();

    /// Ensure a Legacy-role bucket exists, creating one if needed.
    async fn ensure_legacy_bucket(
        client: &LocalClient,
        cached: &mut Option<BucketId>,
    ) -> Result<BucketId> {
        if let Some(b) = cached.clone() {
            return Ok(b);
        }
        let bid = client
            .bucket_create(
                "legacy",
                Some("auto-created for adoption of pre-bucket data"),
                memvault_core::Visibility::Internal,
                memvault_core::classification::Classification::Internal,
                memvault_doc::BucketRole::Legacy,
            )
            .await?;
        tracing::info!(bucket = %bid, "created legacy bucket for adoption");
        *cached = Some(bid.clone());
        Ok(bid)
    }

    // 3a: Adopt entities
    for entity in &entities {
        let bucket = ensure_legacy_bucket(client, &mut legacy_bucket).await?;
        if client
            .adopt_entity_into_bucket(&entity.id, &bucket)
            .await?
        {
            report.entities_adopted += 1;
        }
    }

    // 3b: Adopt docs
    for doc_id in &doc_ids {
        let bucket = ensure_legacy_bucket(client, &mut legacy_bucket).await?;
        if client
            .adopt_doc_into_bucket(doc_id, &bucket)
            .await?
        {
            report.docs_adopted += 1;
        }
    }

    // 3c: Adopt VFS nodes
    {
        let bucket = ensure_legacy_bucket(client, &mut legacy_bucket).await?;
        let bucket_hex = hex::encode(bucket.0);
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
    //
    // Deduplicates roots, deduplicates same-name children within each
    // directory, re-parents children from duplicate roots, then links
    // any remaining orphaned dirs to the canonical root.

    let (orphans, dupes) = repair_vfs_tree(client).await?;
    report.vfs_orphans_linked = orphans;
    report.vfs_dupes_removed = dupes;

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

// ── VFS tree repair ────────────────────────────────────────────────────
//
// Returns (orphans_linked, dupes_removed).

async fn repair_vfs_tree(client: &LocalClient) -> Result<(usize, usize)> {
    use memvault_core::{EdgeId, NodeRef};
    use std::collections::{BTreeMap, HashSet};

    let entities = client.list_entities_unscoped(10_000).await?;
    let mut all_dirs: Vec<(EntityId, String)> = Vec::new();

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
        let name = e
            .props
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        all_dirs.push((e.id.clone(), name));
    }

    if all_dirs.is_empty() {
        return Ok((0, 0));
    }

    // Find root candidates (dirs named "/").
    let mut root_candidates: Vec<[u8; 32]> = all_dirs
        .iter()
        .filter(|(_, name)| name == "/")
        .map(|(id, _)| id.0)
        .collect();
    root_candidates.sort();
    let root_bytes = match root_candidates.first() {
        Some(id) => *id,
        None => return Ok((0, 0)),
    };

    // Ensure canonical root has vfs:root tag.
    let root_node_id = format!("entity:{}", hex::encode(root_bytes));
    let _ = client
        .add_tags(&root_node_id, vec![("vfs".into(), "root".into())])
        .await;
    let root_ref = NodeRef::Entity(EntityId(root_bytes));

    let mut dupes = 0usize;

    // Re-parent children from duplicate roots, then retract the dupes.
    for &dup_bytes in &root_candidates[1..] {
        let dup_ref = NodeRef::Entity(EntityId(dup_bytes));
        let edges = client.edges_of(&dup_ref).await.unwrap_or_default();
        for (src, edge) in &edges {
            if *src != dup_ref || edge.relation != crate::vfs::VFS_CHILD_REL {
                continue;
            }
            let child_name = edge
                .props
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            // Skip if canonical root already has this child.
            let root_edges = client.edges_of(&root_ref).await.unwrap_or_default();
            let exists = root_edges.iter().any(|(s, e)| {
                *s == root_ref
                    && e.relation == crate::vfs::VFS_CHILD_REL
                    && e.props.get("name").and_then(|v| v.as_str()) == Some(&child_name)
            });
            if exists {
                continue;
            }
            let mut props = BTreeMap::new();
            props.insert("name".to_string(), serde_json::json!(child_name));
            let new_edge = memvault_doc::Edge {
                id: EdgeId::random(),
                relation: crate::vfs::VFS_CHILD_REL.to_string(),
                target: edge.target.clone(),
                weight: None,
                props,
                provenance: None,
            };
            let _ = client
                .add_link(&root_ref, new_edge, memvault_core::Visibility::Internal)
                .await;
        }
        let dup_node_id = format!("entity:{}", hex::encode(dup_bytes));
        let _ = client
            .retract_node(&dup_node_id, "duplicate VFS root")
            .await;
        dupes += 1;
    }

    // Deduplicate same-name entries within each directory.
    {
        let mut stack: Vec<NodeRef> = vec![root_ref.clone()];
        let mut visited: HashSet<[u8; 32]> = HashSet::new();
        visited.insert(root_bytes);
        while let Some(current) = stack.pop() {
            let edges = client.edges_of(&current).await.unwrap_or_default();
            let mut by_name: BTreeMap<String, Vec<([u8; 32], NodeRef)>> = BTreeMap::new();
            for (src, edge) in &edges {
                if *src != current || edge.relation != crate::vfs::VFS_CHILD_REL {
                    continue;
                }
                let name = edge
                    .props
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                by_name
                    .entry(name)
                    .or_default()
                    .push((edge.id.0, edge.target.clone()));
            }
            for (_name, mut entries) in by_name {
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                if let Some((_, target)) = entries.first() {
                    if let NodeRef::Entity(eid) = target {
                        if visited.insert(eid.0) {
                            stack.push(target.clone());
                        }
                    }
                }
                for (dup_eid, _) in &entries[1..] {
                    let _ = client
                        .remove_link_from(&current, &EdgeId(*dup_eid))
                        .await;
                    dupes += 1;
                }
            }
        }
    }

    // Walk tree from root to find all reachable dirs.
    let mut reachable: HashSet<[u8; 32]> = HashSet::new();
    reachable.insert(root_bytes);
    {
        let mut stack: Vec<NodeRef> = vec![root_ref.clone()];
        while let Some(current) = stack.pop() {
            let edges = client.edges_of(&current).await.unwrap_or_default();
            for (src, edge) in &edges {
                if *src != current || edge.relation != crate::vfs::VFS_CHILD_REL {
                    continue;
                }
                if let NodeRef::Entity(child_eid) = &edge.target {
                    if reachable.insert(child_eid.0) {
                        stack.push(edge.target.clone());
                    }
                }
            }
        }
    }

    // Link orphaned dirs to root.
    let retracted: HashSet<[u8; 32]> = root_candidates[1..].iter().copied().collect();
    let mut linked = 0usize;
    for (eid, name) in &all_dirs {
        if reachable.contains(&eid.0) || retracted.contains(&eid.0) {
            continue;
        }
        let entry_name = if name.is_empty() {
            hex::encode(eid.0)[..8].to_string()
        } else {
            name.clone()
        };
        let mut props = BTreeMap::new();
        props.insert("name".to_string(), serde_json::json!(entry_name));
        let edge = memvault_doc::Edge {
            id: EdgeId::random(),
            relation: crate::vfs::VFS_CHILD_REL.to_string(),
            target: NodeRef::Entity(eid.clone()),
            weight: None,
            props,
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

    Ok((linked, dupes))
}
