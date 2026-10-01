//! BLOCKS holds content-addressed blocks only: every write path verifies
//! `CID == hash(bytes)`, and side state (pins, health probes) lives in its
//! own tables.

use memvault_attach::pin::{PinReason, is_pinned, list_pinned, pin, unpin};
use memvault_core::cid_from_bytes;
use memvault_store::{IngestMeta, MemvaultStore};

fn open(dir: &tempfile::TempDir) -> MemvaultStore {
    MemvaultStore::open(dir.path().join("blocks.redb")).unwrap()
}

/// `ingest_block` is the one funnel for local and synced blocks; it must
/// refuse bytes that don't hash to the claimed CID, like `put_block` does.
#[test]
fn ingest_block_rejects_cid_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let cid = cid_from_bytes(b"genuine").to_bytes();
    let err = store
        .ingest_block(&cid, b"forged", &IngestMeta::default())
        .expect_err("mismatched bytes must be rejected");
    assert!(
        matches!(err, memvault_store::StoreError::CidMismatch { .. }),
        "got {err:?}"
    );
    assert!(!store.has_block(&cid).unwrap(), "nothing stored");

    // The legacy shim goes through the same check.
    let meta = memvault_store::EnvelopeMeta {
        tags: vec![("doc".into(), "x".into())],
        wall_ns: 1,
        ..Default::default()
    };
    assert!(store.insert_envelope(&cid, b"forged", &meta).is_err());
    assert!(store.query_by_tag("doc", "x", 0, 10).unwrap().is_empty());
}

/// A key that isn't a CID at all is not a block.
#[test]
fn put_block_rejects_unparseable_cid() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    assert!(store.put_block(b"__pin:abc", b"data").is_err());
    assert!(store.put_block(b"not-a-cid", b"data").is_err());
    // A real CID with trailing junk aliases the same content address.
    let mut padded = cid_from_bytes(b"data").to_bytes();
    padded.push(0);
    assert!(store.put_block(&padded, b"data").is_err());
    assert!(store.iter_blocks().unwrap().is_empty());
}

/// Pins are local policy, not blocks: pinning must not add a row to BLOCKS
/// (which RBSR would then try to sync and `rebuild_store` would classify).
#[test]
fn pins_live_outside_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let manifest = cid_from_bytes(b"manifest").to_bytes();
    pin(&store, &manifest, PinReason::Manual).unwrap();
    assert!(is_pinned(&store, &manifest).unwrap());
    assert!(
        store.iter_blocks().unwrap().is_empty(),
        "a pin must not be stored as a block"
    );
    assert_eq!(
        list_pinned(&store).unwrap(),
        vec![(manifest.clone(), PinReason::Manual)]
    );
    unpin(&store, &manifest).unwrap();
    assert!(!is_pinned(&store, &manifest).unwrap());
}

/// Stores written by older builds kept pins in BLOCKS under `__pin:<cid>`.
/// Opening the store moves them into the pin table.
#[test]
fn legacy_pin_rows_migrate_out_of_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.redb");
    let manifest = cid_from_bytes(b"manifest").to_bytes();
    {
        // Write the legacy row the way the old pin code did.
        let db = redb::Database::create(&path).unwrap();
        let table: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("blocks");
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(table).unwrap();
            let mut key = b"__pin:".to_vec();
            key.extend_from_slice(&manifest);
            let reason = serde_json::to_vec(&PinReason::EagerByPolicy).unwrap();
            t.insert(key.as_slice(), reason.as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }
    let store = MemvaultStore::open(&path).unwrap();
    assert!(
        store.iter_blocks().unwrap().is_empty(),
        "legacy row left BLOCKS"
    );
    assert!(
        is_pinned(&store, &manifest).unwrap(),
        "pin survived migration"
    );
    assert_eq!(
        list_pinned(&store).unwrap(),
        vec![(manifest, PinReason::EagerByPolicy)]
    );
}

/// The health check must not write a fake block.
#[test]
fn health_probe_does_not_touch_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let health = memvault_api::health::check_health(&store);
    assert_eq!(health.status, memvault_api::health::HealthStatus::Healthy);
    assert!(store.iter_blocks().unwrap().is_empty());
}
