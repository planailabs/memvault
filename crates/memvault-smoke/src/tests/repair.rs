//! `rebuild_store` repairs write signed blocks dated from the data they
//! repair, so re-running a rebuild writes nothing new and every node
//! derives the same state.

use std::collections::BTreeMap;

use memvault_api::MemvaultClient;
use memvault_core::classification::Classification;
use memvault_core::{BucketRole, DocId, EntityId, NodeRef, VFS_DIR_KIND, Visibility};
use memvault_doc::{Document, Entity};

use crate::harness::TestNode;

async fn bucket(node: &TestNode, name: &str) -> memvault_core::BucketId {
    node.client
        .bucket_create(
            name,
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap()
}

fn children(edges: Vec<(String, NodeRef, memvault_core::EdgeId)>) -> Vec<String> {
    edges.into_iter().map(|(n, _, _)| n).collect()
}

/// The VFS repair linked orphans with a random EdgeId at the wall clock (a
/// new unsigned edge on every rebuild) and treated all buckets' roots as
/// duplicates of one global root, retracting every root but one.
#[tokio::test]
async fn vfs_repair_is_per_bucket_signed_and_idempotent() {
    let node = TestNode::new();
    let b1 = bucket(&node, "one").await;
    let b2 = bucket(&node, "two").await;
    memvault_api::vfs::mkdir(&node.client, &b1, "/a")
        .await
        .unwrap();
    memvault_api::vfs::mkdir(&node.client, &b2, "/b")
        .await
        .unwrap();
    let root1 = memvault_api::vfs::ensure_root(&node.client, &b1)
        .await
        .unwrap();
    let root2 = memvault_api::vfs::ensure_root(&node.client, &b2)
        .await
        .unwrap();

    // An orphan dir in bucket one: a vfs:dir no edge reaches.
    node.client
        .add_entity_internal(
            Entity {
                id: EntityId::random(),
                kind: VFS_DIR_KIND.to_string(),
                props: BTreeMap::from([("name".to_string(), serde_json::json!("orphan"))]),
                edges_out: vec![],
            },
            Visibility::Internal,
            Some(&b1),
        )
        .await
        .unwrap();

    memvault_api::rebuild::rebuild_store(&node.client).unwrap();
    let blocks_after_first = node.store.iter_blocks().unwrap().len();
    let report = memvault_api::rebuild::rebuild_store(&node.client).unwrap();
    assert_eq!(
        node.store.iter_blocks().unwrap().len(),
        blocks_after_first,
        "a second rebuild wrote new blocks"
    );
    assert_eq!(
        report.vfs_dupes_removed, 0,
        "no bucket has a duplicate root"
    );

    let mut c1 = children(
        memvault_api::vfs::list_children(&node.client, &NodeRef::Entity(root1))
            .await
            .unwrap(),
    );
    c1.sort();
    assert_eq!(c1, vec!["a".to_string(), "orphan".to_string()]);
    assert_eq!(
        children(
            memvault_api::vfs::list_children(&node.client, &NodeRef::Entity(root2.clone()))
                .await
                .unwrap()
        ),
        vec!["b".to_string()],
        "bucket two's root survives the repair"
    );
    let root2_label = hex::encode(root2.0);
    for cid in node
        .store
        .query_by_tag("entity", &root2_label, 0, usize::MAX)
        .unwrap()
    {
        assert!(!node.store.is_retracted(&cid).unwrap());
    }

    // The repair edge is a signed envelope.
    let edge_cid = node
        .store
        .query_by_tag(
            "edge_target",
            &format!(
                "entity:{}",
                hex::encode(
                    node.client
                        .list_entities(usize::MAX, Some(&b1))
                        .await
                        .unwrap()
                        .into_iter()
                        .find(|e| e.props.get("name") == Some(&serde_json::json!("orphan")))
                        .unwrap()
                        .id
                        .0
                )
            ),
            0,
            usize::MAX,
        )
        .unwrap();
    assert_eq!(edge_cid.len(), 1);
    let bytes = node.store.get_block(&edge_cid[0]).unwrap().unwrap();
    let signed: memvault_core::Signed<serde_json::Value> =
        serde_ipld_dagcbor::from_slice(&bytes).unwrap();
    assert!(signed.verify_by_author().is_some());
}

/// The retraction backfill dates each block from the retracted block, so it
/// is the same block whenever (and on whichever run) it is written.
#[tokio::test]
async fn retraction_backfill_is_dated_from_its_target() {
    let node = TestNode::new();
    let b = bucket(&node, "r").await;
    let target = node
        .client
        .put_doc(
            Document::new(DocId::random(), "x".into(), Default::default()),
            vec![],
            Visibility::Internal,
            Some(&b),
        )
        .await
        .unwrap();
    let target_wall =
        memvault_store::EnvelopeView::parse(&node.store.get_block(&target).unwrap().unwrap())
            .unwrap()
            .field("wall_ns")
            .unwrap()
            .as_u64()
            .unwrap();
    // A local-only retraction, as older builds recorded it.
    node.store.record_retraction(&target, &target).unwrap();
    node.client.backfill_retraction_blocks().unwrap();
    let r = node
        .store
        .query_by_tag("retraction", &hex::encode(&target), 0, usize::MAX)
        .unwrap();
    assert_eq!(r.len(), 1);
    let wall = memvault_store::EnvelopeView::parse(&node.store.get_block(&r[0]).unwrap().unwrap())
        .unwrap()
        .field("wall_ns")
        .unwrap()
        .as_u64()
        .unwrap();
    assert_eq!(wall, target_wall);
}
