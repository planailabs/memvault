//! Integration test for memvault core data path.
//!
//! Tests document creation, cross-node sync via raw block copy, search,
//! and retraction visibility across multiple MemvaultStore instances.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use memvault_api::{EventBus, LocalClient, MemvaultClient};
use memvault_core::{DocId, Visibility};
use memvault_doc::Document;
use memvault_query::{QuotaManager, TextIndex};
use memvault_store::MemvaultStore;

fn open_temp_store(dir: &tempfile::TempDir, name: &str) -> Arc<MemvaultStore> {
    let path = dir.path().join(format!("{name}.redb"));
    Arc::new(MemvaultStore::open(&path).unwrap())
}

fn make_client(store: Arc<MemvaultStore>) -> LocalClient {
    LocalClient::new(
        store,
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
        Arc::new(EventBus::new(64)),
        vec![0u8; 32],
        vec![0u8; 32],
    )
}

/// Copy all blocks from source store to destination store (simulates sync).
fn copy_blocks(src: &MemvaultStore, dst: &MemvaultStore, cids: &[Vec<u8>]) {
    for cid in cids {
        if let Ok(Some(data)) = src.get_block(cid) {
            dst.put_block(cid, &data).unwrap();
        }
    }
}

#[tokio::test]
async fn put_sync_search_retract() {
    let dir = tempfile::tempdir().unwrap();

    // Create 3 stores simulating 3 nodes.
    let store1 = open_temp_store(&dir, "node1");
    let store2 = open_temp_store(&dir, "node2");
    let store3 = open_temp_store(&dir, "node3");

    let client1 = make_client(Arc::clone(&store1));

    // Node 1: put a document with tags.
    let doc = Document::new(
        DocId::random(),
        "Quantum entanglement enables instantaneous correlation between distant particles."
            .to_string(),
        BTreeMap::from([(
            "title".to_string(),
            serde_json::Value::String("Quantum Physics Note".to_string()),
        )]),
    );
    let doc_id = doc.id.clone();
    let tags = vec![
        ("topic".to_string(), "physics".to_string()),
        ("source".to_string(), "research".to_string()),
    ];

    let cid = client1
        .put_doc(doc, tags, Visibility::Internal, None)
        .await
        .unwrap();

    // Verify node 1 can search for it.
    let hits = client1.search("quantum", 10).await.unwrap();
    assert!(!hits.is_empty(), "node1 should find the doc via search");

    // Simulate sync: copy the raw block(s) from store1 to stores 2 and 3.
    copy_blocks(&store1, &store2, &[cid.clone()]);
    copy_blocks(&store1, &store3, &[cid.clone()]);

    // Also replicate the envelope via insert_envelope metadata so queries work.
    let block_data = store1.get_block(&cid).unwrap().unwrap();

    // Parse the envelope to extract metadata for indexing on remote
    // nodes. Use EnvelopeView so this works for both legacy raw-JSON
    // envelopes and Signed<T> envelopes (which store bytes as DAG-CBOR
    // with byte-string fields that serde_json::from_slice can't parse).
    let view = memvault_store::EnvelopeView::parse(&block_data)
        .expect("envelope must parse via EnvelopeView");
    let wall_ns = view.field("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);
    // Tags on Signed<T> envelopes serialise as Vec<Tag { scope, label }>
    // rather than [scope, label] tuples; try both shapes.
    let tags_val: Vec<(String, String)> = match view
        .field("tags")
        .and_then(|t| serde_json::from_value::<Vec<(String, String)>>(t.clone()).ok())
    {
        Some(v) => v,
        None => view
            .field("tags")
            .and_then(|t| {
                serde_json::from_value::<Vec<memvault_core::tags::Tag>>(t.clone()).ok()
            })
            .map(|tags| tags.into_iter().map(|t| (t.scope, t.label)).collect())
            .unwrap_or_default(),
    };

    let meta = memvault_store::EnvelopeMeta {
        author: vec![0u8; 32],
        tags: tags_val.clone(),
        wall_ns,
        causal: vec![],
        provenance: vec![],
        cluster_id: Some(vec![0u8; 32]),
        bucket_id: None,
            ..Default::default()
    };

    // Insert envelope on nodes 2 and 3 so their indexes are populated.
    store2.insert_envelope(&cid, &block_data, &meta).unwrap();
    store3.insert_envelope(&cid, &block_data, &meta).unwrap();

    // Create clients for nodes 2 and 3 with their own indexes.
    let index2 = Arc::new(RwLock::new(TextIndex::new()));
    let index3 = Arc::new(RwLock::new(TextIndex::new()));

    // Index the document text on nodes 2 and 3.
    {
        let mut idx = index2.write().await;
        idx.index_doc(
            doc_id.clone(),
            "Quantum entanglement enables instantaneous correlation between distant particles.",
            Some("Quantum Physics Note"),
            tags_val.clone(),
        );
    }
    {
        let mut idx = index3.write().await;
        idx.index_doc(
            doc_id.clone(),
            "Quantum entanglement enables instantaneous correlation between distant particles.",
            Some("Quantum Physics Note"),
            tags_val.clone(),
        );
    }

    let client2 = LocalClient::new(
        Arc::clone(&store2),
        index2,
        Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
        Arc::new(EventBus::new(64)),
        vec![1u8; 32],
        vec![0u8; 32],
    );
    let client3 = LocalClient::new(
        Arc::clone(&store3),
        index3,
        Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
        Arc::new(EventBus::new(64)),
        vec![2u8; 32],
        vec![0u8; 32],
    );

    // Nodes 2 and 3 can find the document via search.
    let hits2 = client2.search("quantum", 10).await.unwrap();
    assert!(!hits2.is_empty(), "node2 should find the doc after sync");

    let hits3 = client3.search("quantum", 10).await.unwrap();
    assert!(!hits3.is_empty(), "node3 should find the doc after sync");

    // Node 2: retract the document.
    let tombstone = client2.retract(&cid, "outdated information").await.unwrap();
    assert!(
        !tombstone.is_empty(),
        "retraction should produce a tombstone CID"
    );

    // Verify retraction is visible on node 2.
    assert!(
        store2.is_retracted(&cid).unwrap(),
        "document should be retracted on node2"
    );

    // Simulate retraction propagation to node 3.
    store3.record_retraction(&cid, &tombstone).unwrap();

    // Verify retraction is visible on node 3.
    assert!(
        store3.is_retracted(&cid).unwrap(),
        "document should be retracted on node3 after sync"
    );
}
