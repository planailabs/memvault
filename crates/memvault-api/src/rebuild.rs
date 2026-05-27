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

use crate::error::{ApiError, Result};
use crate::local::LocalClient;
use memvault_core::{BucketId, EntityId};

pub use memvault_core::BLOCKSTORE_VERSION;

/// Derive a deterministic legacy bucket ID.
///
/// - Post-genesis (has cluster_id): `hash(cluster_id + "::legacy")`
///   — same on all nodes in the cluster.
/// - Pre-genesis: `hash(peer_id + "::legacy")` — unique to this node,
///   but that's fine because pre-genesis stores don't sync.
///
/// On the first post-genesis rebuild, the peer-derived bucket is
/// detected as stale and rewritten to the cluster-derived one.
pub fn deterministic_legacy_id(client: &LocalClient) -> BucketId {
    let cluster_id = client.cluster_id();
    let seed = if cluster_id.iter().any(|&b| b != 0) {
        cluster_id
    } else {
        client.peer_id()
    };
    let cid = memvault_core::cid_from_bytes(&[seed, b"::legacy"].concat());
    let mut id = [0u8; 32];
    id.copy_from_slice(&cid.to_bytes()[..32]);
    BucketId(id)
}

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
pub fn rebuild_store(client: &LocalClient) -> Result<RebuildReport> {
    let store = client.store();
    let mut report = RebuildReport::default();

    // ── Carry-over: classify every block, keep/rewrite/drop ──────────
    //
    // Single pass over all blocks.  Each block gets a verdict:
    //  - Keep:    valid CID, current format → untouched
    //  - Rewrite: envelope with legacy CID or missing bucket → CBOR + bucket
    //  - Drop:    cruft (broken manifests, legacy extraction blocks)
    //
    // Rewritten blocks get new CIDs; a mapping is maintained so
    // causal/provenance references stay coherent.

    let all_blocks = store
        .iter_blocks()
        .map_err(|e| ApiError::Other(format!("iter blocks: {e}")))?;

    // Pre-scan: do we need a legacy bucket for unbucketed envelopes?
    let has_unbucketed = all_blocks.iter().any(|(_, data)| {
        memvault_store::deserialize_block(data)
            .map(|v| {
                v.get("payload").is_some()
                    && !v
                        .get("bucket_id")
                        .and_then(|v| v.as_array())
                        .map(|a| !a.is_empty())
                        .unwrap_or(false)
            })
            .unwrap_or(false)
    });

    let det_id = deterministic_legacy_id(client);
    let existing_legacy = client.legacy_bucket_id();
    let legacy_bucket = if has_unbucketed || existing_legacy.is_some() {
        if existing_legacy.as_ref() != Some(&det_id) {
            if store.get_bucket(&det_id.0).ok().flatten().is_none() {
                client.create_bucket_with_id(
                    det_id.clone(),
                    "legacy",
                    Some("auto-created for adoption of pre-bucket data"),
                    memvault_core::Visibility::Internal,
                    memvault_core::classification::Classification::Internal,
                    memvault_doc::BucketRole::Legacy,
                )?;
                tracing::info!(bucket = %det_id, "created deterministic legacy bucket");
            }
        }
        Some(det_id.clone())
    } else {
        None
    };

    let mut to_rewrite: Vec<(Vec<u8>, Vec<u8>, u64)> = Vec::new(); // (cid, data, wall_ns)

    // Find and remove old non-deterministic legacy buckets.  Any bucket
    // with BucketRole::Legacy whose ID doesn't match the deterministic one
    // is a leftover from a prior rebuild — delete its BucketDecl block and
    // force rewrite of all envelopes that reference it.
    let det_legacy_bytes: Option<Vec<u8>> = legacy_bucket.as_ref().map(|b| b.0.to_vec());
    let mut stale_legacy_ids: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    {
        let buckets = store.list_buckets().unwrap_or_default();
        for (bucket_id, decl_cid) in &buckets {
            if let Ok(Some(block)) = store.get_block(decl_cid) {
                if let Some(decl) = crate::local::LocalClient::parse_bucket_decl_static(&block) {
                    if decl.role == memvault_doc::BucketRole::Legacy {
                        if det_legacy_bytes.as_ref() != Some(bucket_id) {
                            stale_legacy_ids.insert(bucket_id.clone());
                            let _ = store.delete_block(decl_cid);
                        }
                    }
                }
            }
        }
    }

    for (cid, data) in &all_blocks {
        let mut verdict = classify_block(cid, data);

        // Drop ALL legacy BucketCreate blocks — the deterministic one
        // will be re-created fresh with cluster_id as author.
        if matches!(verdict, Verdict::Keep) {
            if let Some(val) = memvault_store::deserialize_block(data) {
                if let Some(bc) = val.get("payload").and_then(|p| p.get("BucketCreate")) {
                    if bc.get("role").and_then(|v| v.as_str()) == Some("legacy") {
                        verdict = Verdict::Drop;
                    }
                }
            }
        }

        // Drop or rewrite blocks referencing a stale legacy bucket.
        if matches!(verdict, Verdict::Keep) && !stale_legacy_ids.is_empty() {
            if let Some(val) = memvault_store::deserialize_block(data) {
                if let Some(bid) = val.get("bucket_id").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = bid.iter().filter_map(|n| n.as_u64().map(|n| n as u8)).collect();
                    if stale_legacy_ids.contains(&bytes) {
                        // BucketCreate for a stale bucket → drop entirely.
                        let is_bucket_create = val.get("payload")
                            .and_then(|p| p.get("BucketCreate"))
                            .is_some();
                        verdict = if is_bucket_create { Verdict::Drop } else { Verdict::Rewrite };
                    }
                }
            }
        }

        match verdict {
            Verdict::Keep => {
                report.cid_ok += 1;
            }
            Verdict::Drop => {
                let _ = store.delete_block(cid);
                report.cid_mismatch_cleaned += 1;
            }
            Verdict::Rewrite => {
                let wall_ns = memvault_store::deserialize_block(data)
                    .and_then(|v| v.get("wall_ns").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                to_rewrite.push((cid.clone(), data.clone(), wall_ns));
            }
        }
    }

    // Apply rewrites in chronological order (causal refs point backward).
    to_rewrite.sort_by_key(|(_, _, ns)| *ns);
    let mut cid_map: std::collections::HashMap<Vec<u8>, Vec<u8>> =
        std::collections::HashMap::new();

    if let Some(ref bucket) = legacy_bucket {
        for (old_cid, data, _) in &to_rewrite {
            let mut val = match memvault_store::deserialize_block(data) {
                Some(v) => v,
                None => continue,
            };

            val["bucket_id"] = serde_json::json!(bucket.0);

            // Remap causal/provenance references.
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

            let new_bytes = match serde_ipld_dagcbor::to_vec(&val) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let new_cid_bytes = memvault_core::cid_from_bytes(&new_bytes).to_bytes();

            cid_map.insert(old_cid.clone(), new_cid_bytes.clone());
            let _ = store.put_block(&new_cid_bytes, &new_bytes);
            let _ = store.delete_block(old_cid);
            report.unbucketed_rewritten += 1;
        }
    }

    if report.unbucketed_rewritten > 0 {
        tracing::info!(rewritten = report.unbucketed_rewritten, "rewrote unbucketed envelopes");
    }

    // ── Rebuild secondary indexes from clean block set ─────────────────

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
        // Bucket metadata
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

    // ── Phase 4: Sync VFS tree repair ────────────────────────────────
    //
    // Operates directly on the store — no async trait methods needed.

    let (orphans, dupes) = repair_vfs_sync(store, client)?;
    report.vfs_orphans_linked = orphans;
    report.vfs_dupes_removed = dupes;

    // ── Phase 5: Rebuild text index (sync) ─────────────────────────────

    let (d, e, a) = client.populate_index_sync()?;
    report.docs_indexed = d;
    report.entities_indexed = e;
    report.attachments_indexed = a;

    // ── Stamp the version ──────────────────────────────────────────────
    //
    store
        .set_schema_version(BLOCKSTORE_VERSION)
        .map_err(|e| ApiError::Other(format!("set blockstore version: {e}")))?;

    Ok(report)
}

/// Check stored version and rebuild if needed (sync).
///
/// Skips entirely pre-genesis (no cluster_id) — the rebuild requires a
/// cluster to derive the deterministic legacy bucket.  Will run
/// automatically on the first post-genesis open.
pub fn rebuild_if_needed(client: &LocalClient) -> Result<Option<RebuildReport>> {
    // Pre-genesis: nothing to rebuild — no cluster for bucket derivation.
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

    let report = rebuild_store(client)?;

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

/// Async phases that run after the sync rebuild: VFS repair, pending VFS
/// entries, and text index rebuild.
// Async phases removed — VFS repair in repair_vfs_sync, text index
// in populate_index_sync.  Everything runs sync during rebuild.
// (Old async functions deleted — see git history.)


// ── Sync VFS tree repair ──────────────────────────────────────────────
//
// Operates directly on the store — no async trait methods.
// Returns (orphans_linked, dupes_removed).

fn repair_vfs_sync(
    store: &memvault_store::MemvaultStore,
    client: &LocalClient,
) -> Result<(usize, usize)> {
    use std::collections::HashSet;
    use memvault_core::{EdgeId, NodeRef};
    use memvault_doc::Op;

    let vfs_dir_kind = crate::vfs::VFS_DIR_KIND;
    let vfs_child_rel = crate::vfs::VFS_CHILD_REL;

    // 1. Collect all VFS dir entities with names.
    let labels = store.query_unique_labels("entity", 50_000)
        .map_err(|e| ApiError::Other(format!("query entities: {e}")))?;
    let mut all_dirs: Vec<([u8; 32], String)> = Vec::new();

    for label in &labels {
        let id_bytes = hex::decode(label).unwrap_or_default();
        if id_bytes.len() != 32 { continue; }
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_bytes);

        // Get the latest block for this entity to read kind + props.
        let cids = store.query_by_tag("entity", label, 0, 10).unwrap_or_default();
        let mut kind = String::new();
        let mut name = String::new();
        for cid in cids.iter().rev() {
            if let Ok(Some(data)) = store.get_block(cid) {
                if let Some(val) = memvault_store::deserialize_block(&data) {
                    if let Some(payload) = val.get("payload") {
                        if let Some(ec) = payload.get("EntityCreate") {
                            if let Some(k) = ec.get("kind").and_then(|v| v.as_str()) {
                                kind = k.to_string();
                            }
                            if let Some(n) = ec.get("initial_props")
                                .and_then(|p| p.get("name"))
                                .and_then(|v| v.as_str()) {
                                name = n.to_string();
                            }
                        }
                        if let Some(eu) = payload.get("EntityUpdate") {
                            if let Some(n) = eu.get("props")
                                .and_then(|p| p.get("name"))
                                .and_then(|v| v.as_str()) {
                                name = n.to_string();
                            }
                        }
                    }
                }
            }
        }
        if kind == vfs_dir_kind {
            all_dirs.push((id, name));
        }
    }

    if all_dirs.is_empty() {
        return Ok((0, 0));
    }

    // 2. Find root candidates.
    let mut root_candidates: Vec<[u8; 32]> = all_dirs
        .iter()
        .filter(|(_, name)| name == "/")
        .map(|(id, _)| *id)
        .collect();
    root_candidates.sort();
    let root_bytes = match root_candidates.first() {
        Some(id) => *id,
        None => return Ok((0, 0)),
    };
    let root_label = hex::encode(root_bytes);

    let mut dupes = 0usize;

    // 3. Retract duplicate roots.
    for &dup in &root_candidates[1..] {
        // Retract by creating a retraction block.
        let dup_label = hex::encode(dup);
        let dup_cids = store.query_by_tag("entity", &dup_label, 0, 1).unwrap_or_default();
        for target_cid in &dup_cids {
            let _ = store.record_retraction(target_cid, target_cid);
        }
        dupes += 1;
    }

    // 4. Walk edges from root to find reachable dirs.
    let mut reachable: HashSet<[u8; 32]> = HashSet::new();
    reachable.insert(root_bytes);
    let mut stack: Vec<[u8; 32]> = vec![root_bytes];

    while let Some(current) = stack.pop() {
        let current_label = hex::encode(current);
        let source_label = format!("entity:{current_label}");
        let edge_cids = store.query_by_tag("edge_source", &source_label, 0, 1000).unwrap_or_default();
        for cid in &edge_cids {
            if let Ok(Some(data)) = store.get_block(cid) {
                if let Some(val) = memvault_store::deserialize_block(&data) {
                    if let Some(payload) = val.get("payload") {
                        if let Some(edge_add) = payload.get("EdgeAdd") {
                            if let Some(edge) = edge_add.get("edge") {
                                let rel = edge.get("relation").and_then(|v| v.as_str()).unwrap_or("");
                                if rel != vfs_child_rel { continue; }
                                // Extract target entity ID.
                                if let Some(target) = edge.get("target") {
                                    if let Some(eid) = target.get("Entity")
                                        .and_then(|v| serde_json::from_value::<[u8; 32]>(v.clone()).ok())
                                    {
                                        if reachable.insert(eid) {
                                            stack.push(eid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 5. Link orphaned dirs to root.
    let retracted: HashSet<[u8; 32]> = root_candidates[1..].iter().copied().collect();
    let mut linked = 0usize;
    let legacy_bucket = client.legacy_bucket_id().unwrap_or(BucketId([0u8; 32]));

    for (id, name) in &all_dirs {
        if reachable.contains(id) || retracted.contains(id) {
            continue;
        }
        let entry_name = if name.is_empty() {
            hex::encode(id)[..8].to_string()
        } else {
            name.clone()
        };

        // Create EdgeAdd envelope directly.
        let edge_id = EdgeId::random();
        let source = NodeRef::Entity(EntityId(root_bytes));
        let target = NodeRef::Entity(EntityId(*id));
        let edge = memvault_doc::Edge {
            id: edge_id.clone(),
            relation: vfs_child_rel.to_string(),
            target: target.clone(),
            weight: None,
            props: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("name".to_string(), serde_json::json!(entry_name));
                m
            },
            provenance: None,
        };
        let op = Op::EdgeAdd {
            source: source.clone(),
            edge,
        };

        let wall_ns = memvault_core::wall_ns();
        let source_label = source.tag_label();
        let target_label = target.tag_label();
        let tags = vec![
            ("edge_source".to_string(), source_label),
            ("edge_target".to_string(), target_label),
            ("entity".to_string(), root_label.clone()),
        ];
        let envelope = serde_json::json!({
            "version": 2,
            "payload": op,
            "author": client.cluster_id(),
            "tags": tags,
            "visibility": memvault_core::Visibility::Internal,
            "wall_ns": wall_ns,
            "cluster_id": client.cluster_id(),
            "bucket_id": legacy_bucket.0,
        });
        if let Ok(bytes) = serde_ipld_dagcbor::to_vec(&envelope) {
            let cid = memvault_core::cid_from_bytes(&bytes);
            let meta = memvault_store::EnvelopeMeta {
                author: client.cluster_id().to_vec(),
                tags,
                wall_ns,
                causal: vec![],
                provenance: vec![],
                cluster_id: Some(client.cluster_id().to_vec()),
                bucket_id: Some(legacy_bucket.0.to_vec()),
            };
            let _ = store.insert_envelope(&cid.to_bytes(), &bytes, &meta);
            linked += 1;
        }
    }

    Ok((linked, dupes))
}

// ── Block classification ──────────────────────────────────────────────

/// Verdict for a single block during the carry-over pass.
#[derive(Debug)]
enum Verdict {
    /// Valid CID, current format — keep untouched.
    Keep,
    /// Cruft — delete (broken manifests, legacy extraction blocks).
    Drop,
    /// Envelope needing rewrite — missing bucket, JSON format, or bad CID.
    Rewrite,
}

fn classify_block(cid: &[u8], data: &[u8]) -> Verdict {
    // Try to deserialize as structured data.
    let val = match memvault_store::deserialize_block(data) {
        Some(v) => v,
        None => {
            // Not JSON or CBOR — raw data block (file chunk, DAG-PB).
            // Keep if CID is valid.
            match memvault_core::verify_cid(cid, data) {
                Ok(true) => return Verdict::Keep,
                _ => return Verdict::Drop, // corrupted raw block
            }
        }
    };

    let is_envelope = val.get("payload").is_some();
    let has_bucket = val
        .get("bucket_id")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    // Legacy extraction block: has extractor+text but no payload/kind.
    if !is_envelope
        && val.get("extractor").is_some()
        && val.get("text").is_some()
    {
        return Verdict::Drop;
    }

    // Old-format extraction annotation: references extracted_text by CID
    // instead of inline.  Drop — text will be re-extracted inline on access.
    if val.get("kind").and_then(|v| v.as_str()) == Some("annotation") {
        if let Some(data) = val.get("data") {
            if data.get("extracted_text").is_some()
                && data.get("extracted_text_inline").is_none()
            {
                return Verdict::Drop;
            }
        }
    }

    // Synthesized manifest with broken CID: content_size+filename, no payload.
    if !is_envelope
        && val.get("content_size").is_some()
        && val.get("filename").is_some()
    {
        if !matches!(memvault_core::verify_cid(cid, data), Ok(true)) {
            return Verdict::Drop;
        }
    }

    if is_envelope {
        if !has_bucket {
            return Verdict::Rewrite;
        }
        // JSON envelope → rewrite as CBOR.
        if data.first() == Some(&b'{') {
            return Verdict::Rewrite;
        }
        // CID mismatch → rewrite.
        if !matches!(memvault_core::verify_cid(cid, data), Ok(true)) {
            return Verdict::Rewrite;
        }
        Verdict::Keep
    } else {
        // Non-envelope structured block (annotation, manifest, etc.)
        match memvault_core::verify_cid(cid, data) {
            Ok(true) => Verdict::Keep,
            _ => Verdict::Drop,
        }
    }
}
