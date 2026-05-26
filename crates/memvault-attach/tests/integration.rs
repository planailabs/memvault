//! Integration tests for memvault-attach.

use std::collections::HashMap;

use memvault_attach::chunk::{DEFAULT_CHUNK_SIZE, EAGER_THRESHOLD, INLINE_THRESHOLD};
use memvault_attach::pin::{PinReason, is_pinned, pin, unpin};
use memvault_attach::unixfs::{read_unixfs, read_unixfs_range};
use memvault_attach::{
    AttachmentCache, AttachmentManifest, ChunkLayout, ManifestUpdate, ReplicationHint, chunk_file,
    decide_layout, default_replication,
};
use sha2::{Digest, Sha256};

/// Helper: build a block map from chunking output.
fn block_map(blocks: &[(Vec<u8>, Vec<u8>)]) -> HashMap<Vec<u8>, Vec<u8>> {
    blocks.iter().cloned().collect()
}

// --- Inline file tests ---

#[test]
fn test_inline_small_file() {
    let data = vec![42u8; 1024]; // 1 KiB
    let (root_cid, blocks) = chunk_file(&data).unwrap();

    // Should be a single block.
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].0, root_cid);

    // Layout should be Inline.
    let layout = decide_layout(data.len() as u64);
    assert_eq!(layout, ChunkLayout::Inline { size: 1024 });
}

#[test]
fn test_inline_at_threshold() {
    let data = vec![0xAB; INLINE_THRESHOLD as usize];
    let (_, blocks) = chunk_file(&data).unwrap();
    assert_eq!(blocks.len(), 1);

    let layout = decide_layout(INLINE_THRESHOLD);
    assert!(matches!(layout, ChunkLayout::Inline { .. }));
}

#[test]
fn test_inline_roundtrip() {
    let data = vec![7u8; 1024];
    let (root_cid, blocks) = chunk_file(&data).unwrap();
    let map = block_map(&blocks);

    // The inline block is raw, stored directly. For inline files the root is a raw CID.
    // But our chunk_file for inline stores raw data without UnixFS wrapping.
    // Actually no — for inline we store raw bytes. read_unixfs expects dag-pb.
    // Inline files are NOT UnixFS — they're raw blocks. So read_full won't work on them via unixfs.
    // This is correct: inline files are read directly from the block store.
    assert_eq!(map.get(&root_cid).unwrap(), &data);
}

// --- Medium file tests (UnixFS) ---

#[test]
fn test_medium_file_chunk_and_read() {
    // 500 KiB -> ceil(500/256) = 2 chunks
    let data: Vec<u8> = (0..500 * 1024).map(|i| (i % 251) as u8).collect();
    let (root_cid, blocks) = chunk_file(&data).unwrap();
    let map = block_map(&blocks);

    // Layout check.
    let layout = decide_layout(data.len() as u64);
    match layout {
        ChunkLayout::UnixFs { num_chunks, .. } => assert_eq!(num_chunks, 2),
        _ => panic!("expected UnixFs layout"),
    }

    // 2 leaf blocks + 1 root = 3 total blocks.
    assert_eq!(blocks.len(), 3);

    // Read back.
    let recovered = read_unixfs(&root_cid, &|cid| map.get(cid).cloned()).unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn test_large_file_chunk_and_read() {
    // 2 MiB -> ceil(2*1024/256) = 8 chunks
    let data: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 199) as u8).collect();
    let (root_cid, blocks) = chunk_file(&data).unwrap();
    let map = block_map(&blocks);

    let layout = decide_layout(data.len() as u64);
    match layout {
        ChunkLayout::UnixFs { num_chunks, .. } => assert_eq!(num_chunks, 8),
        _ => panic!("expected UnixFs layout"),
    }

    // 8 leaves + 1 root = 9 blocks.
    assert_eq!(blocks.len(), 9);

    let recovered = read_unixfs(&root_cid, &|cid| map.get(cid).cloned()).unwrap();
    assert_eq!(recovered, data);
}

// --- Range read tests ---

#[test]
fn test_range_read_partial_first_chunk() {
    let data: Vec<u8> = (0..500 * 1024).map(|i| (i % 251) as u8).collect();
    let (root_cid, blocks) = chunk_file(&data).unwrap();
    let map = block_map(&blocks);

    // Read first 100 bytes.
    let range = read_unixfs_range(&root_cid, 0, 100, &|cid| map.get(cid).cloned()).unwrap();
    assert_eq!(range, &data[0..100]);
}

#[test]
fn test_range_read_spanning_chunks() {
    let data: Vec<u8> = (0..500 * 1024).map(|i| (i % 251) as u8).collect();
    let (root_cid, blocks) = chunk_file(&data).unwrap();
    let map = block_map(&blocks);

    // Read across chunk boundary (256 KiB boundary).
    let start = 256 * 1024 - 50;
    let end = 256 * 1024 + 50;
    let range = read_unixfs_range(&root_cid, start, end, &|cid| map.get(cid).cloned()).unwrap();
    assert_eq!(range, &data[start as usize..end as usize]);
}

#[test]
fn test_range_read_second_chunk_only() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let data: Vec<u8> = (0..500 * 1024).map(|i| (i % 251) as u8).collect();
    let (root_cid, blocks) = chunk_file(&data).unwrap();
    let map = block_map(&blocks);

    let fetch_count = AtomicUsize::new(0);
    let start = 256 * 1024 + 10;
    let end = 256 * 1024 + 200;

    let range = read_unixfs_range(&root_cid, start, end, &|cid| {
        fetch_count.fetch_add(1, Ordering::Relaxed);
        map.get(cid).cloned()
    })
    .unwrap();

    assert_eq!(range, &data[start as usize..end as usize]);
    // Should have fetched root + second leaf only (not first leaf).
    assert_eq!(fetch_count.load(Ordering::Relaxed), 2);
}

// --- Pin tests ---

#[test]
fn test_pin_unpin_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let store = memvault_store::MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    let cid = b"test-manifest-cid";

    assert!(!is_pinned(&store, cid).unwrap());

    pin(&store, cid, PinReason::Manual).unwrap();
    assert!(is_pinned(&store, cid).unwrap());

    unpin(&store, cid).unwrap();
    assert!(!is_pinned(&store, cid).unwrap());
}

#[test]
fn test_pin_reasons() {
    let dir = tempfile::tempdir().unwrap();
    let store = memvault_store::MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    let cid1 = b"cid-eager";
    let cid2 = b"cid-grant";

    pin(&store, cid1, PinReason::EagerByPolicy).unwrap();
    pin(
        &store,
        cid2,
        PinReason::PinnedByGrant(b"grant-cid".to_vec()),
    )
    .unwrap();

    assert!(is_pinned(&store, cid1).unwrap());
    assert!(is_pinned(&store, cid2).unwrap());
}

// --- Cache tests ---

#[test]
fn test_cache_basic() {
    let mut cache = AttachmentCache::new(1000);

    assert!(!cache.get(b"a"));
    cache.put(b"a", 500, 1);
    assert!(cache.get(b"a"));
    assert_eq!(cache.current_usage(), 500);
}

#[test]
fn test_cache_eviction() {
    let mut cache = AttachmentCache::new(1000);

    cache.put(b"a", 400, 1);
    cache.put(b"b", 400, 2);
    cache.put(b"c", 400, 3);

    // 1200 > 1000, should evict.
    assert!(cache.should_evict());

    let evicted = cache.evict_lru().unwrap();
    assert_eq!(evicted, b"a"); // LRU is first inserted.
    assert_eq!(cache.current_usage(), 800);
}

#[test]
fn test_cache_lru_order_updated_on_get() {
    let mut cache = AttachmentCache::new(1000);

    cache.put(b"a", 300, 1);
    cache.put(b"b", 300, 2);
    cache.put(b"c", 300, 3);

    // Touch "a" to make it most recently used.
    cache.get(b"a");

    // Now LRU should be "b".
    let evicted = cache.evict_lru().unwrap();
    assert_eq!(evicted, b"b");
}

// --- Replication hint tests ---

#[test]
fn test_replication_eager_small() {
    assert_eq!(default_replication(1024), ReplicationHint::Eager);
    assert_eq!(default_replication(EAGER_THRESHOLD), ReplicationHint::Eager);
}

#[test]
fn test_replication_lazy_large() {
    assert_eq!(
        default_replication(EAGER_THRESHOLD + 1),
        ReplicationHint::Lazy
    );
    assert_eq!(
        default_replication(100 * 1024 * 1024),
        ReplicationHint::Lazy
    );
}

// --- ManifestUpdate tests ---

#[test]
fn test_manifest_update_field_folding() {
    let manifest = AttachmentManifest {
        content_root: vec![1, 2, 3],
        content_size: 1024,
        chunk_layout: ChunkLayout::Inline { size: 1024 },
        filename: Some("test.txt".into()),
        mime_type: "text/plain".into(),
        sha256: None,
        width_height: None,
        duration_ms: None,
        extracted_text: None,
        derived_from: None,
        pii_findings: None,
        replication: ReplicationHint::Eager,
    };

    let update1 = ManifestUpdate {
        target_manifest: vec![1, 2, 3],
        extracted_text: Some(vec![10, 20]),
        pii_findings: None,
        derived_from: None,
        updated_at_ns: 100,
    };

    let update2 = ManifestUpdate {
        target_manifest: vec![1, 2, 3],
        extracted_text: Some(vec![30, 40]), // Overrides update1.
        pii_findings: Some(vec![50, 60]),
        derived_from: None,
        updated_at_ns: 200,
    };

    // Apply updates: latest wins.
    let updates = [update1, update2];
    let mut extracted_text = manifest.extracted_text.clone();
    let mut pii_findings = manifest.pii_findings.clone();

    for u in &updates {
        if u.extracted_text.is_some() {
            extracted_text = u.extracted_text.clone();
        }
        if u.pii_findings.is_some() {
            pii_findings = u.pii_findings.clone();
        }
    }

    assert_eq!(extracted_text, Some(vec![30, 40]));
    assert_eq!(pii_findings, Some(vec![50, 60]));
}

// --- SHA-256 tests ---

#[test]
fn test_sha256_computation() {
    let data = b"hello world";
    let hash = Sha256::digest(data);
    let expected: [u8; 32] = hash.into();

    // Verify it matches known SHA-256 of "hello world".
    assert_eq!(
        hex_encode(&expected),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// --- Edge cases ---

#[test]
fn test_empty_file_returns_error() {
    let result = chunk_file(&[]);
    assert!(result.is_err());
}

#[test]
fn test_exactly_one_chunk() {
    // File exactly at chunk boundary (256 KiB + 1 byte -> 2 chunks).
    let data = vec![0u8; DEFAULT_CHUNK_SIZE + 1];
    let (root_cid, blocks) = chunk_file(&data).unwrap();
    let map = block_map(&blocks);

    // 2 leaves + 1 root.
    assert_eq!(blocks.len(), 3);

    let recovered = read_unixfs(&root_cid, &|cid| map.get(cid).cloned()).unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn test_exactly_at_chunk_boundary() {
    // Exactly 256 KiB -> still > INLINE_THRESHOLD, one leaf in UnixFS.
    let data = vec![0u8; DEFAULT_CHUNK_SIZE];
    let (root_cid, blocks) = chunk_file(&data).unwrap();
    let map = block_map(&blocks);

    // Single leaf (no intermediate nodes needed).
    assert_eq!(blocks.len(), 1);

    let recovered = read_unixfs(&root_cid, &|cid| map.get(cid).cloned()).unwrap();
    assert_eq!(recovered, data);
}
