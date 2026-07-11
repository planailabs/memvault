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
