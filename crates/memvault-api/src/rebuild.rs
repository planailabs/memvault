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

use memvault_core::BLOCKSTORE_VERSION;

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
    // Always per-node: each node owns its own legacy bucket (seeded from
    // its peer id), so it can delegate access to its own pre-bucket data
    // without a cluster admin. There is no cluster-wide legacy bucket.
    let seed = client.peer_id();
    let cid = memvault_core::cid_from_bytes(&[seed, b"::legacy"].concat());
    let mut id = [0u8; 32];
    id.copy_from_slice(&cid.to_bytes()[..32]);
    BucketId(id)
}

/// Deterministic agent-bucket ID — a stable function of the agent
/// **pubkey alone**. The pubkey *is* the agent identity, so the bucket id
/// is stable for the life of that identity across genesis, standalone→
/// cluster join, and re-genesis / cluster_id rotation. (Previously the
/// `cluster_id` was mixed in, so the same agent mapped to a *different*
/// bucket whenever the cluster_id changed, orphaning prior data; the
/// bucket-merge auto-alias pass folds those legacy ids into this one.)
///
/// The `AgentName` string label can be reused or re-claimed and is
/// therefore unsafe as a primary key — only the pubkey is.
pub fn deterministic_agent_bucket_id(agent_pubkey: &[u8]) -> BucketId {
    let mut payload: Vec<u8> = Vec::with_capacity(agent_pubkey.len() + 16);
    payload.extend_from_slice(b"::agent::");
    payload.extend_from_slice(agent_pubkey);
    let cid = memvault_core::cid_from_bytes(&payload);
    let mut id = [0u8; 32];
    id.copy_from_slice(&cid.to_bytes()[..32]);
    BucketId(id)
}

/// The **legacy** agent-bucket ID: a function of `(cluster_id,
/// agent_pubkey)`. Retained only to recompute the bucket ids an agent's
/// data was historically stored under, so the auto-alias migration can
/// map them onto the stable [`deterministic_agent_bucket_id`]. Never used
/// for new writes.
pub fn legacy_agent_bucket_id(cluster_id: &[u8], agent_pubkey: &[u8]) -> BucketId {
    let mut payload: Vec<u8> = Vec::with_capacity(cluster_id.len() + agent_pubkey.len() + 16);
    payload.extend_from_slice(cluster_id);
    payload.extend_from_slice(b"::agent::");
    payload.extend_from_slice(agent_pubkey);
    let cid = memvault_core::cid_from_bytes(&payload);
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
    pub bucket_merges_reindexed: usize,
    pub retractions_backfilled: usize,
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

    // Both passes stream one block at a time (standards/bounded-memory.md).
    let iter_err = |e: memvault_store::StoreError| ApiError::Other(format!("iter blocks: {e}"));

    // Pre-scan: do we need a legacy bucket for unbucketed envelopes?
    let mut has_unbucketed = false;
    for block in store.blocks() {
        let (_, data) = block.map_err(iter_err)?;
        has_unbucketed = memvault_store::deserialize_block(&data)
            .map(|v| {
                v.get("payload").is_some()
                    && !bucketless_by_design(&v)
                    && !v
                        .get("bucket_id")
                        .and_then(|v| v.as_array())
                        .map(|a| !a.is_empty())
                        .unwrap_or(false)
            })
            .unwrap_or(false);
        if has_unbucketed {
            break;
        }
    }

    // Use existing legacy bucket if any, otherwise create the deterministic one.
    // No stale detection — once created, the legacy bucket is kept forever.
    let legacy_bucket = if has_unbucketed {
        Some(match client.find_legacy_bucket() {
            Some(b) => b,
            None => {
                let det_id = deterministic_legacy_id(client);
                if store.get_bucket(&det_id.0).ok().flatten().is_none() {
                    client.create_bucket_with_id(
                        det_id.clone(),
                        "legacy",
                        Some("auto-created for adoption of pre-bucket data"),
                        memvault_core::Visibility::Internal,
                        memvault_core::classification::Classification::Internal,
                        memvault_core::BucketRole::Legacy,
                        // Node key isn't available during rebuild; the daemon
                        // stamps owner_node_pubkey later via
                        // ensure_legacy_bucket_node_owner.
                        None,
                    )?;
                    // Bind to cluster if one exists.
                    if client.cluster_id().iter().any(|&b| b != 0) {
                        let _ = store.bind_bucket(&det_id.0, client.cluster_id());
                    }
                    tracing::info!(bucket = %det_id, "created legacy bucket");
                }
                det_id
            }
        })
    } else {
        client.find_legacy_bucket()
    };

    let mut to_rewrite: Vec<(Vec<u8>, Vec<u8>, u64)> = Vec::new();

    // ponytail: rewrites are held in memory; bounded by the pre-bucket
    // legacy data, not the store. Stream them too if that ever gets large.
    for block in store.blocks() {
        let (cid, data) = block.map_err(iter_err)?;
        let (cid, data) = (&cid, &data);
        let verdict = classify_block(cid, data);
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
    let mut cid_map: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();

    if let Some(ref bucket) = legacy_bucket {
        // Re-sign rewritten envelopes with the local node key so they
        // match the production envelope shape. The unsigned-fallback
        // path was removed in build_signed_envelope; leaving rewrites
        // unsigned would re-introduce a divergent shape and reproduce
        // exactly the bug class that motivated the removal. If no node
        // key is installed, bail out of the rebuild entirely rather
        // than silently committing unsigned blocks — the operator can
        // re-run after wiring up the key.
        let node_signing_key = client.node_signing_key().ok_or_else(|| {
            ApiError::Other(format!(
                "rebuild has {} unbucketed envelope(s) to rewrite but no node signing key is \
                 configured; call set_node_signing_key before running repair-index so \
                 migrated envelopes can be re-signed",
                to_rewrite.len()
            ))
        })?;
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
                        if let Some(old_ref) = serde_json::from_value::<Vec<u8>>(entry.clone()).ok()
                        {
                            if let Some(new_ref) = cid_map.get(&old_ref) {
                                *entry = serde_json::json!(new_ref);
                            }
                        }
                    }
                }
            }

            // Re-sign as a Signed<T> envelope. The legacy author
            // attribution is replaced by the local node's pubkey — the
            // original signature was already invalidated by the
            // bucket_id mutation, so there's nothing meaningful to
            // preserve. If we can't even shape the payload into a
            // Signed<T> for this specific block, skip it rather than
            // commit an unsigned variant.
            let new_bytes =
                match resign_legacy_envelope(&val, bucket, node_signing_key, client.peer_id()) {
                    Some(b) => b,
                    None => {
                        tracing::warn!(
                            old_cid = %hex::encode(old_cid),
                            "skipping legacy envelope: could not coerce to Signed<T> shape"
                        );
                        continue;
                    }
                };
            let new_cid_bytes = memvault_core::cid_from_bytes(&new_bytes).to_bytes();

            cid_map.insert(old_cid.clone(), new_cid_bytes.clone());
            let _ = store.put_block(&new_cid_bytes, &new_bytes);
            let _ = store.delete_block(old_cid);
            report.unbucketed_rewritten += 1;
        }
    }

    if report.unbucketed_rewritten > 0 {
        tracing::info!(
            rewritten = report.unbucketed_rewritten,
            "rewrote unbucketed envelopes"
        );
    }

    // ── Rebuild secondary indexes from clean block set ─────────────────

    store
        .clear_secondary_indexes()
        .map_err(|e| ApiError::Other(format!("clear indexes: {e}")))?;
    // The per-scope member-sets (SCOPE_MEMBERS/SCOPE_REGISTRY) are derived
    // indexes too. A rebuild that re-derives BY_BUCKET/BY_TAG but leaves a
    // previously-registered bucket partition in place would keep its stale
    // membership: `ensure_bucket_partition` skips any already-registered
    // scope, so a node adopted into a bucket during this rebuild (e.g. a
    // legacy unbucketed entity) would be found by the authoritative scan
    // yet missing from the member-set. Discard them so they rebuild lazily
    // with correct membership on next access.
    store
        .scope_clear_all()
        .map_err(|e| ApiError::Other(format!("clear scope member-sets: {e}")))?;

    let blocks = store
        .iter_blocks()
        .map_err(|e| ApiError::Other(format!("iter blocks: {e}")))?;
    report.blocks_total = blocks.len();

    // Bare sigchain records (attestations, grants, merges, token
    // redemptions, …) carry no envelope tags; the admission module derives
    // their index metadata from the record exactly as it does for a local
    // write or a synced copy.
    let record_keys = client.record_keys();
    for (cid, data) in &blocks {
        if crate::admission::reindex_any_block(store, cid, data, &record_keys) {
            report.envelopes_indexed += 1;
        }
    }

    // ── Bucket metadata: which decl is current ───────────────────────
    // Reindexing registered every bucket (first decl seen); the current
    // decl is decided from all of a bucket's decls, not iteration order.
    // An update stored by older builds as a bare, unsigned decl can't win
    // against a signed chain, so re-sign it first where this node may.
    resign_legacy_current_decls(client);
    report.buckets_rebuilt = store
        .resolve_all_bucket_decls(&crate::admission::ClientDeclAuthority(client))
        .map_err(|e| ApiError::Other(format!("resolve bucket decls: {e}")))?;
    // The share inbox status is derived from the signed decision blocks.
    client.rebuild_share_inbox();

    // ── Phase 4: Sync VFS tree repair ────────────────────────────────
    //
    // Operates directly on the store — no async trait methods needed.

    let (orphans, dupes) = repair_vfs_sync(store, client)?;
    report.vfs_orphans_linked = orphans;
    report.vfs_dupes_removed = dupes;

    // ── Phase 4b: Re-tag untagged bucket-merge records (v14) ───────────
    // Bare BucketMergeRecord blocks that synced in before the sync classifier
    // knew about them never got their `bucket_merge` lookup tag; the generic
    // reindex can't recover it from the struct body. Re-apply it so the alias
    // overlay sees them.
    match client.reindex_bucket_merges() {
        Ok(n) => report.bucket_merges_reindexed = n,
        Err(e) => tracing::warn!("bucket-merge reindex during rebuild failed: {e}"),
    }

    // ── Phase 4c: Backfill syncable retraction blocks (v15) ────────────
    // Local-only RETRACTED entries (e.g. unmerges) never propagated; publish a
    // signed retraction block per entry so peers converge.
    match client.backfill_retraction_blocks() {
        Ok(n) => report.retractions_backfilled = n,
        Err(e) => tracing::warn!("retraction backfill during rebuild failed: {e}"),
    }

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

/// Older builds stored bucket renames/attaches/archives as bare, unsigned
/// `BucketDecl` blocks and pointed `BUCKETS` at them. Such a decl cannot
/// override a bucket's signed decl chain, so a bucket whose current
/// pointer is one would fall back to its last signed state. Re-issue the
/// current decl as a signed update (ordered after the bucket's newest
/// signed decl, so every node derives the same order) wherever this node
/// is authorised to; buckets with only unsigned decls are left as they
/// are. Idempotent: afterwards the current decl is signed.
fn resign_legacy_current_decls(client: &LocalClient) {
    let store = client.store();
    let Ok(buckets) = store.list_buckets() else {
        return;
    };
    for (bid, current) in buckets {
        let Ok(bid) = <[u8; 32]>::try_from(bid.as_slice()) else {
            continue;
        };
        let Ok(candidates) = store.bucket_decl_candidates(&bid) else {
            continue;
        };
        let Some(cur) = candidates.iter().find(|c| c.cid == current) else {
            continue;
        };
        if !cur.signers.is_empty() {
            continue;
        }
        let Some(newest_signed) = candidates
            .iter()
            .filter(|c| !c.signers.is_empty())
            .map(|c| c.wall_ns)
            .max()
        else {
            continue; // legacy-only bucket: the unsigned pointer stands
        };
        if let Err(e) = client.write_bucket_decl(&cur.decl, newest_signed.saturating_add(1)) {
            tracing::warn!(
                bucket = %hex::encode(bid),
                "could not re-sign legacy bucket decl: {e}"
            );
        }
    }
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
    use memvault_core::{EdgeId, NodeRef};
    use memvault_doc::Op;
    use std::collections::{BTreeMap, HashSet};

    let vfs_dir_kind = memvault_core::VFS_DIR_KIND;
    let vfs_child_rel = memvault_core::VFS_CHILD_REL;

    struct Dir {
        id: [u8; 32],
        name: String,
        /// wall_ns of the entity's first block (its creation).
        created_ns: u64,
        /// CID of that first block.
        first_cid: Vec<u8>,
    }

    // 1. Every VFS dir entity, grouped by bucket (VFS is per bucket: each
    //    bucket has its own root). Exhaustive (see standards:
    //    exhaustive-lookups) — a cap would drop dirs, or read an entity's
    //    oldest blocks and miss its latest name.
    let labels = store
        .query_unique_labels("entity", usize::MAX)
        .map_err(|e| ApiError::Other(format!("query entities: {e}")))?;
    let mut by_bucket: BTreeMap<Option<[u8; 32]>, Vec<Dir>> = BTreeMap::new();

    for label in &labels {
        let Ok(id) = <[u8; 32]>::try_from(hex::decode(label).unwrap_or_default().as_slice()) else {
            continue;
        };
        // Oldest first, so a later EntityUpdate's name wins.
        let cids = store
            .query_by_tag("entity", label, 0, usize::MAX)
            .unwrap_or_default();
        let mut kind = String::new();
        let mut name = String::new();
        let mut bucket: Option<[u8; 32]> = None;
        let mut first: Option<(u64, Vec<u8>)> = None;
        let mut deleted = false;
        for cid in &cids {
            let Ok(Some(data)) = store.get_block(cid) else {
                continue;
            };
            let Some(val) = memvault_store::deserialize_block(&data) else {
                continue;
            };
            let Some(payload) = val.get("payload") else {
                continue;
            };
            if payload.get("EntityDelete").is_some() {
                deleted = true;
            }
            if let Some(ec) = payload.get("EntityCreate") {
                // `{entity: {kind, props}}` (Op::EntityCreate); older blocks
                // carried `kind`/`initial_props` directly.
                let ent = ec.get("entity").unwrap_or(ec);
                if let Some(k) = ent.get("kind").and_then(|v| v.as_str()) {
                    kind = k.to_string();
                }
                if let Some(n) = ent
                    .get("props")
                    .or_else(|| ent.get("initial_props"))
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                {
                    name = n.to_string();
                }
                bucket = val
                    .get("bucket_id")
                    .and_then(|v| serde_json::from_value::<[u8; 32]>(v.clone()).ok());
                let wall = val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);
                first = Some((wall, cid.clone()));
            }
            if let Some(n) = payload
                .get("EntityUpdate")
                .and_then(|eu| eu.get("props"))
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
            {
                name = n.to_string();
            }
        }
        if kind != vfs_dir_kind || deleted {
            continue;
        }
        let Some((created_ns, first_cid)) = first else {
            continue;
        };
        by_bucket.entry(bucket).or_default().push(Dir {
            id,
            name,
            created_ns,
            first_cid,
        });
    }

    let legacy_bucket = client.find_legacy_bucket();
    let mut dupes = 0usize;
    let mut linked = 0usize;

    for (bucket, dirs) in &by_bucket {
        // 2. The bucket's root: the sorted-first dir named "/" (the same
        //    choice `vfs::ensure_root` makes).
        let mut roots: Vec<&Dir> = dirs.iter().filter(|d| d.name == "/").collect();
        roots.sort_by_key(|d| d.id);
        let Some(root) = roots.first() else {
            continue;
        };

        // 3. Retract the bucket's duplicate roots with a syncable retraction
        //    (dated from the duplicate itself, so a re-run is a no-op).
        for dup in &roots[1..] {
            let exists = store
                .query_by_tag("retraction", &hex::encode(&dup.first_cid), 0, 1)
                .map(|c| !c.is_empty())
                .unwrap_or(false);
            if !exists {
                client.publish_retraction_block_at(
                    &dup.first_cid,
                    "vfs: duplicate root",
                    None,
                    dup.created_ns,
                )?;
            }
            let _ = store.record_retraction(&dup.first_cid, &dup.first_cid);
            dupes += 1;
        }

        // 4. Dirs reachable from the root over vfs child edges. Exhaustive.
        let mut reachable: HashSet<[u8; 32]> = HashSet::new();
        reachable.insert(root.id);
        let mut stack: Vec<[u8; 32]> = vec![root.id];
        while let Some(current) = stack.pop() {
            let source_label = format!("entity:{}", hex::encode(current));
            let edge_cids = store
                .query_by_tag("edge_source", &source_label, 0, usize::MAX)
                .unwrap_or_default();
            for cid in &edge_cids {
                let Ok(Some(data)) = store.get_block(cid) else {
                    continue;
                };
                let Some(edge) = memvault_store::deserialize_block(&data)
                    .and_then(|v| v.get("payload")?.get("EdgeAdd")?.get("edge").cloned())
                else {
                    continue;
                };
                if edge.get("relation").and_then(|v| v.as_str()) != Some(vfs_child_rel) {
                    continue;
                }
                if let Some(eid) = edge
                    .get("target")
                    .and_then(|t| t.get("Entity"))
                    .and_then(|v| serde_json::from_value::<[u8; 32]>(v.clone()).ok())
                {
                    if reachable.insert(eid) {
                        stack.push(eid);
                    }
                }
            }
        }

        // 5. Link orphaned dirs under the root with a signed EdgeAdd whose
        //    EdgeId and wall_ns derive from (root, orphan): every rebuild of
        //    this store writes the same block, and an existing one is kept.
        let dup_ids: HashSet<[u8; 32]> = roots[1..].iter().map(|d| d.id).collect();
        let edge_bucket = bucket.map(BucketId).or_else(|| legacy_bucket.clone());
        for dir in dirs {
            if reachable.contains(&dir.id) || dup_ids.contains(&dir.id) {
                continue;
            }
            // Only a dir nothing ever linked is an orphan. One that had a
            // parent and was unlinked (rmdir/mv) stays where its owner put
            // it; the repair's own edge (same CID every run) counts too.
            let ever_linked = store
                .query_by_tag(
                    "edge_target",
                    &format!("entity:{}", hex::encode(dir.id)),
                    0,
                    1,
                )
                .map(|c| !c.is_empty())
                .unwrap_or(false);
            if ever_linked {
                continue;
            }
            let entry_name = if dir.name.is_empty() {
                hex::encode(dir.id)[..8].to_string()
            } else {
                dir.name.clone()
            };
            let mut seed = b"vfs-repair-link:".to_vec();
            seed.extend_from_slice(&root.id);
            seed.extend_from_slice(&dir.id);
            let mut edge_id = [0u8; 32];
            edge_id.copy_from_slice(&memvault_core::cid_from_bytes(&seed).hash().digest()[..32]);
            let source = NodeRef::Entity(EntityId(root.id));
            let target = NodeRef::Entity(EntityId(dir.id));
            let op = Op::EdgeAdd {
                source: source.clone(),
                edge: memvault_doc::Edge {
                    id: EdgeId(edge_id),
                    relation: vfs_child_rel.to_string(),
                    target: target.clone(),
                    weight: None,
                    props: std::collections::BTreeMap::from([(
                        "name".to_string(),
                        serde_json::json!(entry_name),
                    )]),
                    provenance: None,
                },
            };
            let tags = vec![
                ("edge_source".to_string(), source.tag_label()),
                ("edge_target".to_string(), target.tag_label()),
                ("entity".to_string(), hex::encode(root.id)),
            ];
            let wall_ns = root.created_ns.max(dir.created_ns).saturating_add(1);
            client.store_op_at(
                &op,
                &tags,
                &memvault_core::Visibility::Internal,
                edge_bucket.as_ref(),
                wall_ns,
            )?;
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
    // v12 migration: drop legacy `GrantAudience::Agent(string)` bucket grants.
    // Their string audience is ambiguous across nodes (two nodes' same-named
    // agents both match), so they're poisoned. New grants use `AgentKey(pubkey)`,
    // which survive. A non-grant block won't deserialize as `Grant` (required
    // fields), so this can't false-positive. Revocation isn't an option here —
    // it needs an admin/owner key that may be absent; dropping in the rebuild
    // needs no authority.
    if let Ok(grant) = serde_ipld_dagcbor::from_slice::<memvault_auth::Grant>(data) {
        if matches!(grant.audience, memvault_auth::GrantAudience::Agent(_)) {
            return Verdict::Drop;
        }
    }

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
    if !is_envelope && val.get("extractor").is_some() && val.get("text").is_some() {
        return Verdict::Drop;
    }

    // Old-format extraction annotation: references extracted_text by CID
    // instead of inline.  Drop — text will be re-extracted inline on access.
    if let Some(view) = memvault_store::EnvelopeView::from_value(val.clone()) {
        if view.str_field("kind") == Some("annotation") {
            if let Some(data) = view.field("data") {
                if data.get("extracted_text").is_some()
                    && data.get("extracted_text_inline").is_none()
                {
                    return Verdict::Drop;
                }
            }
        }
    }

    // Synthesized manifest with broken CID: content_size+filename, no payload.
    if !is_envelope && val.get("content_size").is_some() && val.get("filename").is_some() {
        if !matches!(memvault_core::verify_cid(cid, data), Ok(true)) {
            return Verdict::Drop;
        }
    }

    if is_envelope {
        if !has_bucket && !bucketless_by_design(&val) {
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

/// Envelopes current builds write without a bucket on purpose: cluster
/// state that belongs to no bucket (retractions, agent relabels, share
/// decisions) and views spanning all buckets. Adopting them into the
/// legacy bucket would re-sign them under a new CID on every node that
/// rebuilds — breaking references to them (a trust's `from_reply`, an
/// unmerge's retraction) and making each node hold a different block.
fn bucketless_by_design(val: &serde_json::Value) -> bool {
    let Some(payload) = val.get("payload") else {
        return false;
    };
    ["ShareDecision", "AgentRename", "ViewCreate"]
        .iter()
        .any(|k| payload.get(k).is_some())
        || payload.get("kind").and_then(|k| k.as_str()) == Some("retraction")
}

/// Re-sign a legacy / mutated envelope as a `Signed<T>` block using the
/// node's signing key. The legacy author attribution is replaced by the
/// local peer_id (the original signature was already invalidated by
/// adding `bucket_id`); the payload, tags, visibility, and timestamp
/// from the source envelope are preserved verbatim. Returns the encoded
/// envelope bytes on success, `None` if the source can't be coerced
/// into the canonical shape (in which case the caller falls back to a
/// raw CBOR re-encode and the block remains unsigned).
fn resign_legacy_envelope(
    val: &serde_json::Value,
    bucket: &memvault_core::BucketId,
    node_signing_key: &ed25519_dalek::SigningKey,
    peer_id: &[u8],
) -> Option<Vec<u8>> {
    let payload = val.get("payload")?.clone();
    let wall_ns = val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);
    let visibility: memvault_core::Visibility = val
        .get("visibility")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or(memvault_core::Visibility::Internal);

    // tags may be either the Signed<T> struct shape or the legacy tuple
    // shape — coerce to Vec<Tag> so the re-signed envelope speaks the
    // canonical wire format.
    let tags_value = val.get("tags").cloned().unwrap_or(serde_json::json!([]));
    let tags: Vec<memvault_core::Tag> =
        serde_json::from_value::<Vec<memvault_core::Tag>>(tags_value.clone())
            .or_else(|_| {
                serde_json::from_value::<Vec<(String, String)>>(tags_value).map(|v| {
                    v.into_iter()
                        .map(|(s, l)| memvault_core::Tag::new(s, l))
                        .collect()
                })
            })
            .ok()?;

    let envelope = memvault_core::Signed::sign(
        payload,
        node_signing_key,
        memvault_core::PeerId(peer_id.to_vec()),
        vec![], // causal — drop legacy refs (already remapped above)
        vec![], // provenance
        tags,
        visibility,
        0, // lamport — not tracked in legacy envelopes
        wall_ns,
        None, // capability
        Some(bucket.clone()),
        None, // node_attestation — wire up via trust_state when present
        None, // agent_attestation — legacy envelopes pre-date agent attribution
        None, // agent_signing_key
    )
    .ok()?;

    serde_ipld_dagcbor::to_vec(&envelope).ok()
}

#[cfg(test)]
mod classify_tests {
    use super::*;

    fn grant_with(audience: memvault_auth::GrantAudience) -> Vec<u8> {
        let grant = memvault_auth::Grant {
            issuer: memvault_core::PeerId(vec![1, 2, 3]),
            issuing_cluster: memvault_core::ClusterId([7u8; 32]),
            admin_pubkey: [9u8; 32],
            audience,
            scopes: vec![],
            actions: vec![memvault_auth::Action::Read],
            not_before_ns: 0,
            not_after_ns: u64::MAX,
            parent: None,
            nonce: [0u8; 16],
            bucket_scopes: vec![],
            signature: [0u8; 64],
        };
        serde_ipld_dagcbor::to_vec(&grant).unwrap()
    }

    #[test]
    fn drops_agent_string_grant() {
        let bytes = grant_with(memvault_auth::GrantAudience::Agent(
            memvault_core::AgentName("alice".into()),
        ));
        let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
        assert!(matches!(classify_block(&cid, &bytes), Verdict::Drop));
    }

    #[test]
    fn keeps_pubkey_and_role_grants() {
        for audience in [
            memvault_auth::GrantAudience::AgentKey([5u8; 32]),
            memvault_auth::GrantAudience::Peer(memvault_core::PeerId(vec![4u8; 32])),
            memvault_auth::GrantAudience::Role(memvault_auth::AgentRole::AgentHost),
        ] {
            let bytes = grant_with(audience);
            let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
            assert!(
                matches!(classify_block(&cid, &bytes), Verdict::Keep),
                "non-Agent(string) grants must survive the v12 rebuild"
            );
        }
    }
}
