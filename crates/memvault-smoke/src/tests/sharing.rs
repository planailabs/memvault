//! Cross-cluster sharing smoke tests.

use memvault_api::MemvaultClient;
use memvault_auth::Action;
use memvault_auth::share::*;
use memvault_core::{BucketId, ClusterId, PeerId};

use crate::harness::TestNode;

#[tokio::test]
async fn share_inbox_empty() {
    let node = TestNode::new();
    assert!(node.client.share_inbox().await.unwrap().is_empty());
}

#[tokio::test]
async fn share_outbox_empty() {
    let node = TestNode::new();
    assert!(node.client.share_outbox().await.unwrap().is_empty());
}

#[tokio::test]
async fn share_decide_approve() {
    let node = TestNode::new();
    // Store a fake proposal CID
    let proposal_cid = vec![1u8; 32];
    node.store
        .record_share_inbox(&proposal_cid, &node.cluster_id.0, 1000, 0)
        .unwrap();

    node.client
        .share_decide(&proposal_cid, true, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn share_decide_reject() {
    let node = TestNode::new();
    let proposal_cid = vec![2u8; 32];
    node.store
        .record_share_inbox(&proposal_cid, &node.cluster_id.0, 2000, 0)
        .unwrap();

    node.client
        .share_decide(&proposal_cid, false, Some("not authorized"))
        .await
        .unwrap();
}

#[test]
fn share_proposal_sign_verify() {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    let proposal = ShareProposal {
        proposal_id: [1u8; 16],
        from_cluster: ClusterId::random(),
        from_bucket: BucketId::random(),
        from_admin: PeerId(vk.as_bytes().to_vec()),
        to_cluster: ClusterId::random(),
        to_recipient: ShareRecipient::AnyAdmin,
        proposed_actions: vec![Action::Read],
        purpose: "test".into(),
        not_after_ns: u64::MAX,
        signature: [0u8; 64],
    }
    .sign(&sk)
    .unwrap();

    proposal.verify_signature(&vk).unwrap();
}

#[test]
fn share_reply_sign_verify() {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    let reply = ShareReply {
        proposal_id: [2u8; 16],
        from_cluster: ClusterId::random(),
        by_principal: PeerId(vk.as_bytes().to_vec()),
        decision: ShareDecision::Approve {
            granted_actions: vec![Action::Read],
            not_after_ns: u64::MAX,
        },
        decided_at_ns: 1000,
        signature: [0u8; 64],
    }
    .sign(&sk)
    .unwrap();

    reply.verify_signature(&vk).unwrap();
}

#[test]
fn bucket_trust_sign_verify() {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    let trust = BucketTrust {
        bucket_id: BucketId::random(),
        from_cluster: ClusterId::random(),
        to_cluster: ClusterId::random(),
        actions: vec![Action::Read, Action::Write],
        not_after_ns: u64::MAX,
        from_proposal: memvault_core::cid_from_bytes(b"proposal"),
        from_reply: memvault_core::cid_from_bytes(b"reply"),
        signature: [0u8; 64],
    }
    .sign(&sk)
    .unwrap();

    trust.verify_signature(&vk).unwrap();
    assert!(trust.is_valid_at(1000));
    assert!(trust.is_valid_at(u64::MAX));
}

/// A share decision used to live only in the deciding node's redb inbox,
/// and the BucketTrust it issued pointed at `hash(proposal cid bytes)` and
/// `hash(now)` instead of the proposal and reply. The decision is now a
/// signed block; the inbox status is derived from it on every node, and
/// the trust references the real CIDs.
#[tokio::test]
async fn share_decision_is_a_synced_block_with_real_cids() {
    let a = TestNode::new();
    let admin = a.client.admin_signing_key().unwrap();
    let proposal = ShareProposal {
        proposal_id: [7u8; 16],
        from_cluster: ClusterId::random(),
        from_bucket: BucketId::random(),
        from_admin: PeerId(vec![1u8; 32]),
        to_cluster: a.cluster_id.clone(),
        to_recipient: ShareRecipient::AnyAdmin,
        proposed_actions: vec![Action::Read],
        purpose: "test".into(),
        not_after_ns: u64::MAX,
        signature: [0u8; 64],
    }
    .sign(&ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]))
    .unwrap();
    let pbytes = serde_ipld_dagcbor::to_vec(&proposal).unwrap();
    let pcid = memvault_core::cid_from_bytes(&pbytes).to_bytes();
    a.store
        .ingest_block(&pcid, &pbytes, &memvault_store::IngestMeta::unindexed())
        .unwrap();
    a.store
        .record_share_inbox(&pcid, &a.cluster_id.0, 1000, 0)
        .unwrap();

    let decision_cid = a.client.share_decide_sync(&pcid, true, None).unwrap();
    assert_eq!(
        a.store.share_inbox_status(&pcid, &a.cluster_id.0).unwrap(),
        Some(1)
    );
    // One inbox row per proposal (deciding used to add a second one).
    assert_eq!(a.client.share_inbox().await.unwrap(), vec![pcid.clone()]);

    let trust_cid = a
        .store
        .query_by_tag("kind", "bucket-trust", 0, usize::MAX)
        .unwrap()
        .pop()
        .expect("trust issued");
    let trust: BucketTrust =
        serde_ipld_dagcbor::from_slice(&a.store.get_block(&trust_cid).unwrap().unwrap()).unwrap();
    assert_eq!(trust.from_proposal.to_bytes(), pcid);
    assert_eq!(trust.from_reply.to_bytes(), decision_cid);
    trust.verify_signature(&admin.verifying_key()).unwrap();

    // A second node of the cluster learns the decision from the block.
    let b = TestNode::with_cluster(&a.cluster_id);
    b.client.seed_admin_anchor(admin.verifying_key().to_bytes());
    let mut gate = memvault_api::admission::SyncGate::new(
        &b.store,
        a.cluster_id.0,
        Some(admin.verifying_key().to_bytes()),
    );
    for (cid, data) in a.store.iter_blocks().unwrap() {
        gate.admit(&cid, &data);
    }
    memvault_api::rebuild::rebuild_store(&b.client).unwrap();
    assert_eq!(
        b.store.share_inbox_status(&pcid, &a.cluster_id.0).unwrap(),
        Some(1)
    );
}
