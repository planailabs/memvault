//! Tests for block sync divergence reproduction and remediation.
//!
//! Reproduces the scenario where node A has 4175 blocks but node B only
//! received 936 due to:
//!   1. RBSR per-window CID cap (was 1000, now usize::MAX)
//!   2. Unbounded follow-up fetch exceeding codec message limit
//!   3. No periodic re-sync to heal partial sync
//!
//! Tests simulate the RBSR protocol at the store level (no real network)
//! using the same approach as basic.rs.

use std::sync::Arc;

use memvault_attach::chunk_file;
use memvault_core::cid_from_bytes;
use memvault_store::MemvaultStore;
use prost::Message;

fn open_temp_store(dir: &tempfile::TempDir, name: &str) -> Arc<MemvaultStore> {
    let path = dir.path().join(format!("{name}.redb"));
    Arc::new(MemvaultStore::open(&path).unwrap())
}

/// Create a fake envelope block with the given wall_ns and a unique payload.
/// Returns (cid_bytes, block_data).
fn make_block(wall_ns: u64, seq: usize) -> (Vec<u8>, Vec<u8>) {
    let data = serde_json::json!({
        "author": vec![0u8; 32],
        "wall_ns": wall_ns,
        "tags": [["seq", seq.to_string()]],
        "body": format!("block-{seq}"),
    });
    let bytes = serde_json::to_vec(&data).unwrap();
    let cid = cid_from_bytes(&bytes);
    let mut cid_bytes = Vec::new();
    cid.write_bytes(&mut cid_bytes).unwrap();
    (cid_bytes, bytes)
}

/// Insert a block into a store and index it.
fn insert_and_index(store: &MemvaultStore, cid: &[u8], data: &[u8]) {
    store.put_block(cid, data).unwrap();
    store.reindex_block(cid, data).unwrap();
}

/// Simulate the RBSR server side: compute fingerprints for `windows` time
/// windows from 0..now, compare against the requester's fingerprints, and
/// return CIDs from mismatched windows (with an optional per-window cap).
fn simulate_rbsr_serve(
    server_store: &MemvaultStore,
    client_fingerprints: &[(u64, u64, usize, [u8; 32])],
    per_window_limit: usize,
) -> Vec<Vec<u8>> {
    let mut diff_cids = Vec::new();
    for (start, end, client_count, client_xor) in client_fingerprints {
        let (local_count, local_xor) = server_store
            .range_fingerprint(*start, *end)
            .unwrap_or((0, [0u8; 32]));
        if local_count as u32 == *client_count as u32 && local_xor == *client_xor {
            continue;
        }
        if let Ok(cids) = server_store.query_by_time(*start, *end, per_window_limit) {
            diff_cids.extend(cids);
        }
    }
    diff_cids
}

/// Compute RBSR fingerprints for a store over `windows` time windows.
fn compute_fingerprints(
    store: &MemvaultStore,
    windows: usize,
    now_ns: u64,
) -> Vec<(u64, u64, usize, [u8; 32])> {
    let window_size = now_ns / windows as u64;
    if window_size == 0 {
        return vec![];
    }
    let mut fps = Vec::with_capacity(windows);
    for i in 0..windows {
        let start = (i as u64) * window_size;
        let end = if i == windows - 1 {
            u64::MAX
        } else {
            start + window_size
        };
        let (count, xor) = store.range_fingerprint(start, end).unwrap_or((0, [0u8; 32]));
        fps.push((start, end, count, xor));
    }
    fps
}

/// Simulate the full sync: RBSR phase 1 (get CID list) + phase 2 (fetch blocks).
fn simulate_full_sync(
    server: &MemvaultStore,
    client: &MemvaultStore,
    per_window_limit: usize,
    fetch_chunk_size: usize,
    now_ns: u64,
) -> usize {
    let client_fps = compute_fingerprints(client, 64, now_ns);
    let diff_cids = simulate_rbsr_serve(server, &client_fps, per_window_limit);

    // Client filters for CIDs it doesn't have.
    let missing: Vec<_> = diff_cids
        .into_iter()
        .filter(|cid| !client.has_block(cid).unwrap_or(true))
        .collect();

    // Phase 2: fetch in chunks.
    let mut stored = 0;
    for chunk in missing.chunks(fetch_chunk_size) {
        for cid in chunk {
            if let Ok(Some(data)) = server.get_block(cid) {
                if client.get_block(cid).ok().flatten().is_none() {
                    client.put_block(cid, &data).unwrap();
                    let _ = client.reindex_block(cid, &data);
                    stored += 1;
                }
            }
        }
    }
    stored
}

// ── Reproduction tests ──────────────────────────────────────────────

/// Reproduce: with the OLD per-window limit of 1000, a burst of >1000
/// blocks in a single time window causes silent data loss.
#[tokio::test]
async fn rbsr_window_cap_causes_divergence() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    for i in 0..2000 {
        let (cid, data) = make_block(base_ns + i as u64, i);
        insert_and_index(&store_a, &cid, &data);
    }

    let now_ns = base_ns + 10_000;
    let synced = simulate_full_sync(&store_a, &store_b, 1000, 500, now_ns);

    assert!(
        synced < 2000,
        "old cap should cause data loss: synced {synced} (expected < 2000)"
    );
    assert!(
        synced <= 1000,
        "old cap truncates at 1000 per window: synced {synced}"
    );
}

/// Reproduce: even without the per-window cap, requesting all missing
/// blocks in a single fetch can exceed the 16 MiB message limit.
#[tokio::test]
async fn unbounded_fetch_request_size() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    for i in 0..3000 {
        let (cid, data) = make_block(base_ns + (i as u64) * 1000, i);
        insert_and_index(&store_a, &cid, &data);
    }

    let now_ns = base_ns + 3_000_001;
    let client_fps = compute_fingerprints(&store_b, 64, now_ns);
    let diff_cids = simulate_rbsr_serve(&store_a, &client_fps, usize::MAX);
    let missing: Vec<_> = diff_cids
        .iter()
        .filter(|cid| !store_b.has_block(cid).unwrap_or(true))
        .collect();

    assert_eq!(missing.len(), 3000);

    let chunk_count = (missing.len() + 499) / 500;
    assert!(
        chunk_count >= 6,
        "3000 blocks should produce at least 6 chunks of 500: got {chunk_count}"
    );
}

// ── Remediation tests ───────────────────────────────────────────────

/// After fix: RBSR with no per-window cap achieves full convergence.
#[tokio::test]
async fn rbsr_full_sync_converges() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    for i in 0..2000 {
        let (cid, data) = make_block(base_ns + i as u64, i);
        insert_and_index(&store_a, &cid, &data);
    }

    let now_ns = base_ns + 10_000;
    let synced = simulate_full_sync(&store_a, &store_b, usize::MAX, 500, now_ns);

    assert_eq!(synced, 2000, "all blocks should sync with no cap");
}

/// After fix: chunked fetch handles large block counts.
#[tokio::test]
async fn chunked_fetch_syncs_all_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    for i in 0..4175 {
        let (cid, data) = make_block(base_ns + (i as u64) * 100, i);
        insert_and_index(&store_a, &cid, &data);
    }

    for i in 0..936 {
        let (cid, data) = make_block(base_ns + (i as u64) * 100, i);
        insert_and_index(&store_b, &cid, &data);
    }

    let now_ns = base_ns + 500_000;

    let a_count = store_a.query_by_time(0, u64::MAX, usize::MAX).unwrap().len();
    let b_count = store_b.query_by_time(0, u64::MAX, usize::MAX).unwrap().len();
    assert_eq!(a_count, 4175);
    assert_eq!(b_count, 936);

    let synced = simulate_full_sync(&store_a, &store_b, usize::MAX, 500, now_ns);

    assert_eq!(synced, 4175 - 936, "should sync exactly the missing blocks");

    let fps_a = compute_fingerprints(&store_a, 64, now_ns);
    let fps_b = compute_fingerprints(&store_b, 64, now_ns);
    for (a, b) in fps_a.iter().zip(fps_b.iter()) {
        assert_eq!(a.2, b.2, "block count mismatch in window [{}, {})", a.0, a.1);
        assert_eq!(a.3, b.3, "XOR fingerprint mismatch in window [{}, {})", a.0, a.1);
    }
}

/// Periodic re-sync heals divergence that initial sync missed.
#[tokio::test]
async fn periodic_resync_heals_divergence() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    for i in 0..1500 {
        let (cid, data) = make_block(base_ns + i as u64, i);
        insert_and_index(&store_a, &cid, &data);
    }

    let now_ns = base_ns + 10_000;

    let synced1 = simulate_full_sync(&store_a, &store_b, 1000, 500, now_ns);
    assert!(synced1 <= 1000, "initial sync capped at 1000");

    let b_count = store_b.query_by_time(0, u64::MAX, usize::MAX).unwrap().len();
    assert!(b_count < 1500, "node B should be behind after capped sync");

    let synced2 = simulate_full_sync(&store_a, &store_b, usize::MAX, 500, now_ns);
    assert!(synced2 > 0, "resync should fetch remaining blocks");

    let b_count_after = store_b.query_by_time(0, u64::MAX, usize::MAX).unwrap().len();
    assert_eq!(
        b_count_after, 1500,
        "node B should have all blocks after resync"
    );
}

/// Bidirectional divergence: both nodes have blocks the other lacks.
#[tokio::test]
async fn bidirectional_divergence_converges() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    for i in 0..500 {
        let (cid, data) = make_block(base_ns + (i as u64) * 100, i);
        insert_and_index(&store_a, &cid, &data);
    }

    for i in 500..800 {
        let (cid, data) = make_block(base_ns + (i as u64) * 100, i);
        insert_and_index(&store_b, &cid, &data);
    }

    let now_ns = base_ns + 100_000;

    let synced_a_to_b = simulate_full_sync(&store_a, &store_b, usize::MAX, 500, now_ns);
    assert_eq!(synced_a_to_b, 500);

    let synced_b_to_a = simulate_full_sync(&store_b, &store_a, usize::MAX, 500, now_ns);
    assert_eq!(synced_b_to_a, 300);

    let a_count = store_a.query_by_time(0, u64::MAX, usize::MAX).unwrap().len();
    let b_count = store_b.query_by_time(0, u64::MAX, usize::MAX).unwrap().len();
    assert_eq!(a_count, 800);
    assert_eq!(b_count, 800);

    let fps_a = compute_fingerprints(&store_a, 64, now_ns);
    let fps_b = compute_fingerprints(&store_b, 64, now_ns);
    for (a, b) in fps_a.iter().zip(fps_b.iter()) {
        assert_eq!(a.2, b.2, "count mismatch");
        assert_eq!(a.3, b.3, "fingerprint mismatch");
    }
}

// ── File chunk sync tests ───────────────────────────────────────────

/// Helper: upload a file to a store, returning (envelope_cid, manifest_cid, all_cids).
fn upload_file_to_store(
    store: &MemvaultStore,
    data: &[u8],
    wall_ns: u64,
) -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
    let mut all_cids = Vec::new();

    let (root_cid, blocks) = chunk_file(data).unwrap();
    for (block_cid, block_data) in &blocks {
        store.put_block(block_cid, block_data).unwrap();
        all_cids.push(block_cid.clone());
    }

    let manifest = serde_json::json!({
        "content_root": root_cid,
        "content_size": data.len(),
        "chunk_layout": "UnixFs",
        "mime_type": "application/octet-stream",
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_cid = cid_from_bytes(&manifest_bytes);
    let manifest_cid_bytes = manifest_cid.to_bytes();
    store.put_block(&manifest_cid_bytes, &manifest_bytes).unwrap();
    all_cids.push(manifest_cid_bytes.clone());

    let envelope = serde_json::json!({
        "version": 1,
        "kind": "attachment",
        "manifest_cid": manifest_cid_bytes,
        "filename": "test.bin",
        "mime_type": "application/octet-stream",
        "size": data.len(),
        "wall_ns": wall_ns,
        "author": vec![0u8; 32],
        "tags": [["kind", "attachment"]],
    });
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let env_cid = cid_from_bytes(&envelope_bytes);
    let env_cid_bytes = env_cid.to_bytes();

    let meta = memvault_store::EnvelopeMeta {
        author: vec![0u8; 32],
        tags: vec![("kind".into(), "attachment".into())],
        wall_ns,
        causal: vec![],
        provenance: vec![],
        cluster_id: Some(vec![0u8; 32]),
        bucket_id: None,
    };
    store
        .insert_envelope(&env_cid_bytes, &envelope_bytes, &meta)
        .unwrap();
    all_cids.push(env_cid_bytes.clone());

    (env_cid_bytes, manifest_cid_bytes, all_cids)
}

/// Reproduce: RBSR only sees the envelope (BY_TIME), NOT manifest or
/// data chunks. After RBSR sync, file data is silently missing.
#[tokio::test]
async fn file_chunks_invisible_to_rbsr() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    let file_data = vec![42u8; 512 * 1024];
    let (env_cid, manifest_cid, all_cids) =
        upload_file_to_store(&store_a, &file_data, base_ns);

    let total_blocks = all_cids.len();
    assert!(total_blocks >= 3, "file should produce envelope + manifest + chunks, got {total_blocks}");

    let now_ns = base_ns + 10_000;
    let synced = simulate_full_sync(&store_a, &store_b, usize::MAX, 500, now_ns);

    assert_eq!(synced, 1, "RBSR should only sync the envelope (BY_TIME)");

    assert!(store_b.has_block(&env_cid).unwrap(), "node B should have envelope");
    assert!(!store_b.has_block(&manifest_cid).unwrap(), "node B should NOT have manifest (not in BY_TIME)");

    let missing = all_cids.iter().filter(|c| !store_b.has_block(c).unwrap()).count();
    assert!(missing >= 2, "node B should be missing manifest + chunks: missing {missing}");
}

/// Extract dependent CIDs from a block (mirrors extract_dependent_cids in swarm).
fn extract_deps(data: &[u8]) -> Vec<Vec<u8>> {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
        let mut deps = Vec::new();
        if let Some(mcid) = val.get("manifest_cid")
            .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
        {
            deps.push(mcid);
        }
        if let Some(root) = val.get("content_root")
            .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
        {
            deps.push(root);
        }
        return deps;
    }
    if let Ok(node) = memvault_attach::proto::PbNode::decode(data) {
        return node.links.into_iter().filter_map(|l| l.hash).collect();
    }
    vec![]
}

/// Helper: simulate reference-chasing sync.
fn simulate_chasing_sync(
    server: &MemvaultStore,
    client: &MemvaultStore,
    seed_cids: &[Vec<u8>],
) -> usize {
    let mut to_process: Vec<Vec<u8>> = Vec::new();
    let mut total_stored = 0;

    for cid in seed_cids {
        if let Some(data) = client.get_block(cid).ok().flatten() {
            for dep in extract_deps(&data) {
                if client.get_block(&dep).ok().flatten().is_none() {
                    to_process.push(dep);
                }
            }
        } else {
            to_process.push(cid.clone());
        }
    }

    while !to_process.is_empty() {
        let mut next = Vec::new();
        for cid in &to_process {
            if client.get_block(cid).ok().flatten().is_some() {
                continue;
            }
            if let Ok(Some(data)) = server.get_block(cid) {
                client.put_block(cid, &data).unwrap();
                let _ = client.reindex_block(cid, &data);
                total_stored += 1;

                for dep in extract_deps(&data) {
                    if client.get_block(&dep).ok().flatten().is_none() {
                        next.push(dep);
                    }
                }
            }
        }
        to_process = next;
    }
    total_stored
}

/// Remediation: reference-chasing sync fetches manifest + all chunks.
#[tokio::test]
async fn reference_chasing_syncs_file_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    let file_data = vec![42u8; 512 * 1024];
    let (env_cid, manifest_cid, all_cids) =
        upload_file_to_store(&store_a, &file_data, base_ns);

    let total_blocks = all_cids.len();

    let env_data = store_a.get_block(&env_cid).unwrap().unwrap();
    store_b.put_block(&env_cid, &env_data).unwrap();
    store_b.reindex_block(&env_cid, &env_data).unwrap();

    let synced = simulate_chasing_sync(&store_a, &store_b, &[env_cid.clone()]);

    assert!(synced >= 1, "should sync at least manifest: synced {synced}");
    assert!(store_b.has_block(&manifest_cid).unwrap(), "node B should now have manifest");

    let still_missing: Vec<_> = all_cids.iter()
        .filter(|c| !store_b.has_block(c).unwrap())
        .collect();
    assert!(
        still_missing.is_empty(),
        "node B should have all {} blocks, missing {}",
        total_blocks,
        still_missing.len()
    );
}

/// Full scenario: multiple files + documents, RBSR + reference chasing
/// achieves complete convergence.
#[tokio::test]
async fn mixed_docs_and_files_converge() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = open_temp_store(&dir, "node_a");
    let store_b = open_temp_store(&dir, "node_b");

    let base_ns: u64 = 1_700_000_000_000_000_000;

    for i in 0..100 {
        let (cid, data) = make_block(base_ns + (i as u64) * 1000, i);
        insert_and_index(&store_a, &cid, &data);
    }

    let mut file_seed_cids = Vec::new();
    let mut total_file_blocks = 0;
    for (idx, size) in [64 * 1024, 256 * 1024, 512 * 1024].iter().enumerate() {
        let file_data = vec![(idx + 1) as u8; *size];
        let (env_cid, _, all_cids) =
            upload_file_to_store(&store_a, &file_data, base_ns + 200_000 + idx as u64);
        file_seed_cids.push(env_cid);
        total_file_blocks += all_cids.len();
    }

    let now_ns = base_ns + 500_000;

    let rbsr_synced = simulate_full_sync(&store_a, &store_b, usize::MAX, 500, now_ns);

    assert_eq!(rbsr_synced, 103, "RBSR should sync docs + envelopes");

    let chase_synced = simulate_chasing_sync(&store_a, &store_b, &file_seed_cids);
    assert!(chase_synced > 0, "chasing should sync manifest + chunks");

    let a_block_count = store_a.query_by_time(0, u64::MAX, usize::MAX).unwrap().len();
    let b_block_count = store_b.query_by_time(0, u64::MAX, usize::MAX).unwrap().len();

    assert_eq!(a_block_count, b_block_count, "BY_TIME indexed block counts should match");

    let a_all = store_a.iter_blocks().unwrap();
    let mut b_missing = 0;
    for (cid, _) in &a_all {
        if !store_b.has_block(cid).unwrap() {
            b_missing += 1;
        }
    }
    assert_eq!(b_missing, 0, "node B should have ALL blocks including file chunks");
}
