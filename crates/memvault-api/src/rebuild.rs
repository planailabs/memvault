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
    pub unbucketed_rewritten: usize,
    pub envelopes_indexed: usize,
    pub buckets_rebuilt: usize,
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
                    if let Some(val) = memvault_store::deserialize_block(data) {
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
            let is_envelope = memvault_store::deserialize_block(data)
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

    // ── Phase 0c: Drop legacy extraction blocks ─────────────────────────
    //
    // Old extraction results were stored as standalone blocks (no bucket,
    // no envelope, never synced).  Delete them — text will be re-extracted
    // and stored inline in annotations during populate_index.
    {
        let blocks = store
            .iter_blocks()
            .map_err(|e| ApiError::Other(format!("iter blocks: {e}")))?;
        let mut dropped = 0usize;
        for (cid, data) in &blocks {
            if let Some(val) = memvault_store::deserialize_block(data) {
                // Legacy extraction blocks have "source", "extractor", "text"
                // but no "payload" (not an envelope) and no "kind".
                let has_extractor = val.get("extractor").is_some();
                let has_text = val.get("text").is_some();
                let is_envelope = val.get("payload").is_some();
                if has_extractor && has_text && !is_envelope {
                    let _ = store.delete_block(cid);
                    dropped += 1;
                }
            }
        }
        if dropped > 0 {
            tracing::info!(dropped, "dropped legacy extraction blocks");
        }
    }

    // ── Phase 0d: Rewrite non-bucketed envelopes as CBOR with bucket ──
    //
    // Non-bucketed data predates working sync — it's all locally authored.
    // Rewrite each unbucketed envelope: add bucket_id, encode as CBOR,
    // store under new CID, delete old.  Causal/provenance references are
    // updated via a CID mapping built during the rewrite.
    //
    // After this phase, no unbucketed envelopes remain and Phase 3
    // adoption becomes a no-op.
    {
        // We need a legacy bucket.  If none exists, create one.
        let legacy_bid = match client.legacy_bucket_id() {
            Some(b) => Some(b),
            None => {
                // Check if there are any unbucketed envelopes first.
                let blocks = store
                    .iter_blocks()
                    .map_err(|e| ApiError::Other(format!("iter blocks: {e}")))?;
                let has_unbucketed = blocks.iter().any(|(_, data)| {
                    memvault_store::deserialize_block(data)
                        .map(|v| v.get("payload").is_some() && v.get("bucket_id").is_none())
                        .unwrap_or(false)
                });
                if has_unbucketed {
                    let bid = client
                        .bucket_create(
                            "legacy",
                            Some("auto-created for adoption of pre-bucket data"),
                            memvault_core::Visibility::Internal,
                            memvault_core::classification::Classification::Internal,
                            memvault_doc::BucketRole::Legacy,
                        )
                        .await?;
                    tracing::info!(bucket = %bid, "created legacy bucket for rewrite");
                    Some(bid)
                } else {
                    None
                }
            }
        };

        if let Some(legacy_bucket) = legacy_bid {
            let blocks = store
                .iter_blocks()
                .map_err(|e| ApiError::Other(format!("iter blocks: {e}")))?;

            // Collect unbucketed envelopes, sorted by wall_ns for
            // deterministic causal-chain ordering.
            let mut unbucketed: Vec<(Vec<u8>, Vec<u8>, u64)> = Vec::new(); // (cid, data, wall_ns)
            for (cid, data) in &blocks {
                if let Some(val) = memvault_store::deserialize_block(data) {
                    let has_payload = val.get("payload").is_some();
                    let has_bucket = val
                        .get("bucket_id")
                        .and_then(|v| v.as_array())
                        .map(|a| !a.is_empty())
                        .unwrap_or(false);
                    if has_payload && !has_bucket {
                        let wall_ns = val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);
                        unbucketed.push((cid.clone(), data.clone(), wall_ns));
                    }
                }
            }
            unbucketed.sort_by_key(|(_, _, ns)| *ns);

            // Build CID mapping and rewrite.
            let mut cid_map: std::collections::HashMap<Vec<u8>, Vec<u8>> =
                std::collections::HashMap::new();

            for (old_cid, data, _) in &unbucketed {
                let mut val: serde_json::Value = match memvault_store::deserialize_block(data) {
                    Some(v) => v,
                    None => continue,
                };

                // Set bucket_id.
                val["bucket_id"] = serde_json::json!(legacy_bucket.0);

                // Update causal/provenance references using the CID mapping.
                for field in &["causal", "provenance"] {
                    if let Some(arr) = val.get_mut(field).and_then(|v| v.as_array_mut()) {
                        for entry in arr.iter_mut() {
                            if let Some(old_ref) =
                                serde_json::from_value::<Vec<u8>>(entry.clone()).ok()
                            {
                                if let Some(new_ref) = cid_map.get(&old_ref) {
                                    *entry = serde_json::json!(new_ref);
                                }
                            }
                        }
                    }
                }

                // Re-encode as CBOR.
                let new_bytes = match serde_ipld_dagcbor::to_vec(&val) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let new_cid = memvault_core::cid_from_bytes(&new_bytes);
                let new_cid_bytes = new_cid.to_bytes();

                cid_map.insert(old_cid.clone(), new_cid_bytes.clone());

                let _ = store.put_block(&new_cid_bytes, &new_bytes);
                let _ = store.delete_block(old_cid);
                report.unbucketed_rewritten += 1;
            }

            if report.unbucketed_rewritten > 0 {
                tracing::info!(
                    rewritten = report.unbucketed_rewritten,
                    "rewrote unbucketed envelopes as CBOR with bucket_id"
                );
            }
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
        if let Some(val) = memvault_store::deserialize_block(data) {
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

    // Phase 3 (adoption) removed — Phase 0d rewrites all unbucketed
    // envelopes in-place, making adoption unnecessary.

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
            if let Some(val) = memvault_store::deserialize_block(&data) {
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
        rewritten = report.unbucketed_rewritten,
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
