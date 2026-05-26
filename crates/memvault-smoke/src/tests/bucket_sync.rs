//! Bucket sync tests: gossip propagation of bucket lifecycle events
//! between two live swarms, plus federation bucket announcements.

use std::time::Duration;
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use tokio::time::timeout;

use memvault_net::{
    standalone_swarm, AdminAnnouncement,
    FederationAnnouncement, StandaloneMemvaultBehaviourEvent,
};
use memvault_net::gossip;
use memvault_core::Visibility;

// ── Helpers ────────────────────────────────────────────────────────

async fn spawn_swarm() -> (
    libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    Multiaddr,
    libp2p::PeerId,
) {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let mut swarm = standalone_swarm(
        keypair,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
    )
    .await
    .unwrap();

    let addr = loop {
        match swarm.next().await.unwrap() {
            SwarmEvent::NewListenAddr { address, .. } => break address,
            _ => {}
        }
    };
    (swarm, addr, peer_id)
}

async fn connect_swarms(
    swarm_a: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    swarm_b: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    addr_b: &Multiaddr,
) {
    swarm_a.dial(addr_b.clone()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut a_ok = false;
    let mut b_ok = false;
    while (!a_ok || !b_ok) && tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = swarm_a.next() => {
                if let Some(SwarmEvent::ConnectionEstablished { .. }) = event { a_ok = true; }
            }
            event = swarm_b.next() => {
                if let Some(SwarmEvent::ConnectionEstablished { .. }) = event { b_ok = true; }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(a_ok && b_ok, "swarms did not connect");
}

/// Let swarms mesh for gossipsub (needs heartbeat time).
async fn mesh(
    a: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    b: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
) {
    tokio::time::sleep(Duration::from_secs(1)).await;
    for _ in 0..20 {
        tokio::select! {
            _ = a.next() => {}
            _ = b.next() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

/// Publish an AdminAnnouncement and wait for the other swarm to receive it.
/// Returns the decoded announcement if received within the timeout.
async fn publish_and_receive_admin(
    publisher: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    receiver: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    announcement: AdminAnnouncement,
) -> Option<AdminAnnouncement> {
    let data = serde_ipld_dagcbor::to_vec(&announcement).unwrap();
    publisher
        .behaviour_mut()
        .gossipsub
        .publish(gossip::admin_topic(), data)
        .unwrap();

    timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = receiver.next() => {
                    if let Some(SwarmEvent::Behaviour(StandaloneMemvaultBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    ))) = event {
                        if let Ok(ann) = serde_ipld_dagcbor::from_slice::<AdminAnnouncement>(&message.data) {
                            return ann;
                        }
                    }
                }
                _ = publisher.next() => {}
            }
        }
    })
    .await
    .ok()
}

/// Publish a FederationAnnouncement on a federation topic and wait for receipt.
async fn publish_and_receive_federation(
    publisher: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    receiver: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    cluster_a: &[u8],
    cluster_b: &[u8],
    announcement: FederationAnnouncement,
) -> Option<FederationAnnouncement> {
    let topic = gossip::federation_ident_topic(cluster_a, cluster_b);

    // Both must subscribe to this federation topic.
    publisher.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    receiver.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    // Allow subscription to propagate.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for _ in 0..10 {
        tokio::select! {
            _ = publisher.next() => {}
            _ = receiver.next() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    let data = serde_ipld_dagcbor::to_vec(&announcement).unwrap();
    publisher
        .behaviour_mut()
        .gossipsub
        .publish(topic, data)
        .unwrap();

    timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = receiver.next() => {
                    if let Some(SwarmEvent::Behaviour(StandaloneMemvaultBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    ))) = event {
                        if let Ok(ann) = serde_ipld_dagcbor::from_slice::<FederationAnnouncement>(&message.data) {
                            return ann;
                        }
                    }
                }
                _ = publisher.next() => {}
            }
        }
    })
    .await
    .ok()
}

// ── Bucket gossip tests ────────────────────────────────────────────

#[tokio::test]
#[ignore = "gossipsub meshing is timing-sensitive; run with --include-ignored"]
async fn bucket_created_gossip_propagates() {
    let (mut a, _addr_a, _) = spawn_swarm().await;
    let (mut b, addr_b, _) = spawn_swarm().await;
    connect_swarms(&mut a, &mut b, &addr_b).await;
    mesh(&mut a, &mut b).await;

    let bucket_cid = vec![0xBu8; 32];
    let ann = AdminAnnouncement::BucketCreated(bucket_cid.clone());
    let received = publish_and_receive_admin(&mut a, &mut b, ann).await;

    match received {
        Some(AdminAnnouncement::BucketCreated(cid)) => assert_eq!(cid, bucket_cid),
        other => panic!("expected BucketCreated, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "gossipsub meshing is timing-sensitive; run with --include-ignored"]
async fn bucket_attached_gossip_propagates() {
    let (mut a, _addr_a, _) = spawn_swarm().await;
    let (mut b, addr_b, _) = spawn_swarm().await;
    connect_swarms(&mut a, &mut b, &addr_b).await;
    mesh(&mut a, &mut b).await;

    let op_cid = vec![0xA1; 32];
    let ann = AdminAnnouncement::BucketAttached(op_cid.clone());
    let received = publish_and_receive_admin(&mut a, &mut b, ann).await;

    match received {
        Some(AdminAnnouncement::BucketAttached(cid)) => assert_eq!(cid, op_cid),
        other => panic!("expected BucketAttached, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "gossipsub meshing is timing-sensitive; run with --include-ignored"]
async fn bucket_archived_gossip_propagates() {
    let (mut a, _addr_a, _) = spawn_swarm().await;
    let (mut b, addr_b, _) = spawn_swarm().await;
    connect_swarms(&mut a, &mut b, &addr_b).await;
    mesh(&mut a, &mut b).await;

    let op_cid = vec![0xDE; 32];
    let ann = AdminAnnouncement::BucketArchived(op_cid.clone());
    let received = publish_and_receive_admin(&mut a, &mut b, ann).await;

    match received {
        Some(AdminAnnouncement::BucketArchived(cid)) => assert_eq!(cid, op_cid),
        other => panic!("expected BucketArchived, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "gossipsub meshing is timing-sensitive; run with --include-ignored"]
async fn bucket_trust_established_gossip_propagates() {
    let (mut a, _addr_a, _) = spawn_swarm().await;
    let (mut b, addr_b, _) = spawn_swarm().await;
    connect_swarms(&mut a, &mut b, &addr_b).await;
    mesh(&mut a, &mut b).await;

    let trust_cid = vec![0xFE; 32];
    let ann = AdminAnnouncement::BucketTrustEstablished(trust_cid.clone());
    let received = publish_and_receive_admin(&mut a, &mut b, ann).await;

    match received {
        Some(AdminAnnouncement::BucketTrustEstablished(cid)) => assert_eq!(cid, trust_cid),
        other => panic!("expected BucketTrustEstablished, got {other:?}"),
    }
}

// ── Federation bucket announcement tests ───────────────────────────

#[tokio::test]
#[ignore = "gossipsub meshing is timing-sensitive; run with --include-ignored"]
async fn federation_head_with_bucket_id_propagates() {
    let (mut a, _addr_a, _) = spawn_swarm().await;
    let (mut b, addr_b, _) = spawn_swarm().await;
    connect_swarms(&mut a, &mut b, &addr_b).await;
    mesh(&mut a, &mut b).await;

    let cluster_x = vec![1u8; 32];
    let cluster_y = vec![2u8; 32];
    let head_cid = vec![0xCA; 32];
    let bucket = vec![0xBB; 32];

    let ann = FederationAnnouncement::HeadAvailable {
        head_cid: head_cid.clone(),
        visibility: Visibility::Federated,
        scope_tags: vec![("kind".into(), "note".into())],
        bucket_id: Some(bucket.clone()),
    };

    let received = publish_and_receive_federation(
        &mut a, &mut b, &cluster_x, &cluster_y, ann,
    )
    .await;

    match received {
        Some(FederationAnnouncement::HeadAvailable {
            head_cid: hc,
            bucket_id: Some(bid),
            ..
        }) => {
            assert_eq!(hc, head_cid);
            assert_eq!(bid, bucket);
        }
        other => panic!("expected HeadAvailable with bucket_id, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "gossipsub meshing is timing-sensitive; run with --include-ignored"]
async fn federation_bucket_trust_established_propagates() {
    let (mut a, _addr_a, _) = spawn_swarm().await;
    let (mut b, addr_b, _) = spawn_swarm().await;
    connect_swarms(&mut a, &mut b, &addr_b).await;
    mesh(&mut a, &mut b).await;

    let cluster_x = vec![3u8; 32];
    let cluster_y = vec![4u8; 32];
    let trust_cid = vec![0xCC; 32];

    let ann = FederationAnnouncement::BucketTrustEstablished {
        trust_cid: trust_cid.clone(),
    };

    let received = publish_and_receive_federation(
        &mut a, &mut b, &cluster_x, &cluster_y, ann,
    )
    .await;

    match received {
        Some(FederationAnnouncement::BucketTrustEstablished { trust_cid: tc }) => {
            assert_eq!(tc, trust_cid);
        }
        other => panic!("expected BucketTrustEstablished, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "gossipsub meshing is timing-sensitive; run with --include-ignored"]
async fn federation_bucket_trust_revoked_propagates() {
    let (mut a, _addr_a, _) = spawn_swarm().await;
    let (mut b, addr_b, _) = spawn_swarm().await;
    connect_swarms(&mut a, &mut b, &addr_b).await;
    mesh(&mut a, &mut b).await;

    let cluster_x = vec![5u8; 32];
    let cluster_y = vec![6u8; 32];
    let revocation_cid = vec![0xDD; 32];

    let ann = FederationAnnouncement::BucketTrustRevoked {
        revocation_cid: revocation_cid.clone(),
    };

    let received = publish_and_receive_federation(
        &mut a, &mut b, &cluster_x, &cluster_y, ann,
    )
    .await;

    match received {
        Some(FederationAnnouncement::BucketTrustRevoked { revocation_cid: rc }) => {
            assert_eq!(rc, revocation_cid);
        }
        other => panic!("expected BucketTrustRevoked, got {other:?}"),
    }
}

// ── Bucket visibility enforcement over the wire ────────────────────

#[test]
fn private_bucket_blocks_other_local_peer() {
    use memvault_net::{VisibilityFilter, FederationState, ConnectionState, ServeDecision, ServeRefuseReason};

    // Filter for cluster-a. Bucket is private to "cluster-a" (owner = cluster_id).
    let filter = VisibilityFilter::new(b"cluster-a".to_vec());
    let fed = FederationState::new(b"cluster-a".to_vec());

    // A local peer that is NOT the owner.
    let other_local = ConnectionState {
        peer_id: b"other-local-peer".to_vec(),
        cluster_id: b"cluster-a".to_vec(),
        role: "admin".to_string(),
        is_local_cluster: true,
        authenticated_at_ns: 1000,
    };

    // Bucket private_to_peer = "cluster-a" (matches filter.local_cluster_id),
    // but requester.peer_id != "cluster-a" → BucketPrivate
    let decision = filter.may_serve(
        &Visibility::Internal,
        Some(b"cluster-a"),
        &other_local,
        &fed,
    );
    assert_eq!(decision, ServeDecision::Refused(ServeRefuseReason::BucketPrivate));
}

#[test]
fn private_bucket_allows_owner_peer() {
    use memvault_net::{VisibilityFilter, FederationState, ConnectionState, ServeDecision};

    let filter = VisibilityFilter::new(b"cluster-a".to_vec());
    let fed = FederationState::new(b"cluster-a".to_vec());

    // The actual owner peer (peer_id == owner_peer) should have access.
    let owner = ConnectionState {
        peer_id: b"cluster-a".to_vec(),
        cluster_id: b"cluster-a".to_vec(),
        role: "admin".to_string(),
        is_local_cluster: true,
        authenticated_at_ns: 1000,
    };

    let decision = filter.may_serve(
        &Visibility::Internal,
        Some(b"cluster-a"),
        &owner,
        &fed,
    );
    assert_eq!(decision, ServeDecision::Allowed);
}

#[test]
fn private_bucket_foreign_owner_always_refused() {
    use memvault_net::{VisibilityFilter, FederationState, ConnectionState, ServeDecision, ServeRefuseReason};

    let filter = VisibilityFilter::new(b"cluster-a".to_vec());
    let fed = FederationState::new(b"cluster-a".to_vec());

    let local = ConnectionState {
        peer_id: b"local-peer".to_vec(),
        cluster_id: b"cluster-a".to_vec(),
        role: "admin".to_string(),
        is_local_cluster: true,
        authenticated_at_ns: 1000,
    };

    // Bucket owned by a different cluster — always refused
    let decision = filter.may_serve(
        &Visibility::Internal,
        Some(b"cluster-b"),
        &local,
        &fed,
    );
    assert_eq!(decision, ServeDecision::Refused(ServeRefuseReason::BucketPrivate));
}

#[test]
fn attached_bucket_allows_local_cluster_access() {
    use memvault_net::{VisibilityFilter, FederationState, ConnectionState};

    let filter = VisibilityFilter::new(b"cluster-a".to_vec());
    let fed = FederationState::new(b"cluster-a".to_vec());

    let local = ConnectionState {
        peer_id: b"local-peer".to_vec(),
        cluster_id: b"cluster-a".to_vec(),
        role: "admin".to_string(),
        is_local_cluster: true,
        authenticated_at_ns: 1000,
    };

    // Internal item in an attached bucket (owner = None) → allowed for local
    let allowed = filter.can_serve(&Visibility::Internal, &local, &fed);
    assert!(allowed);
}

#[test]
fn federated_bucket_with_trust_allows_remote() {
    use memvault_net::{VisibilityFilter, FederationState, TrustedClusterInfo, ConnectionState};

    let filter = VisibilityFilter::new(b"cluster-a".to_vec());
    let mut fed = FederationState::new(b"cluster-a".to_vec());
    fed.add_trust(TrustedClusterInfo {
        cluster_id: b"cluster-b".to_vec(),
        admin_keys: vec![[7u8; 32]],
        federated_since_ns: 0,
        not_after_ns: u64::MAX,
    });

    let remote = ConnectionState {
        peer_id: b"remote-peer".to_vec(),
        cluster_id: b"cluster-b".to_vec(),
        role: "agent".to_string(),
        is_local_cluster: false,
        authenticated_at_ns: 1000,
    };

    // Federated visibility + trusted cluster → allowed
    assert!(filter.can_serve(&Visibility::Federated, &remote, &fed));
}

#[test]
fn federated_bucket_without_trust_blocks_remote() {
    use memvault_net::{VisibilityFilter, FederationState, ConnectionState};

    let filter = VisibilityFilter::new(b"cluster-a".to_vec());
    let fed = FederationState::new(b"cluster-a".to_vec()); // no trust added

    let remote = ConnectionState {
        peer_id: b"untrusted".to_vec(),
        cluster_id: b"cluster-c".to_vec(),
        role: "agent".to_string(),
        is_local_cluster: false,
        authenticated_at_ns: 1000,
    };

    assert!(!filter.can_serve(&Visibility::Federated, &remote, &fed));
}

// ── Serialization round-trip tests ─────────────────────────────────

#[test]
fn admin_announcement_bucket_variants_roundtrip() {
    let variants = vec![
        AdminAnnouncement::BucketCreated(vec![1, 2, 3]),
        AdminAnnouncement::BucketAttached(vec![4, 5, 6]),
        AdminAnnouncement::BucketArchived(vec![7, 8, 9]),
        AdminAnnouncement::BucketTrustEstablished(vec![10, 11, 12]),
    ];

    for ann in &variants {
        let bytes = serde_ipld_dagcbor::to_vec(ann).unwrap();
        let decoded: AdminAnnouncement = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert_eq!(
            serde_ipld_dagcbor::to_vec(&decoded).unwrap(),
            bytes,
            "round-trip failed for {ann:?}"
        );
    }
}

#[test]
fn federation_announcement_bucket_variants_roundtrip() {
    let variants: Vec<FederationAnnouncement> = vec![
        FederationAnnouncement::HeadAvailable {
            head_cid: vec![1; 32],
            visibility: Visibility::Federated,
            scope_tags: vec![("topic".into(), "test".into())],
            bucket_id: Some(vec![2; 32]),
        },
        FederationAnnouncement::HeadAvailable {
            head_cid: vec![3; 32],
            visibility: Visibility::Internal,
            scope_tags: vec![],
            bucket_id: None,
        },
        FederationAnnouncement::BucketTrustEstablished {
            trust_cid: vec![4; 32],
        },
        FederationAnnouncement::BucketTrustRevoked {
            revocation_cid: vec![5; 32],
        },
    ];

    for ann in &variants {
        let bytes = serde_ipld_dagcbor::to_vec(ann).unwrap();
        let decoded: FederationAnnouncement = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert_eq!(
            serde_ipld_dagcbor::to_vec(&decoded).unwrap(),
            bytes,
            "round-trip failed for {ann:?}"
        );
    }
}

#[test]
fn share_request_roundtrip() {
    use memvault_net::ShareRequest;

    let req = ShareRequest {
        version: 1,
        proposal_block: b"test-proposal".to_vec(),
    };

    let bytes = serde_json::to_vec(&req).unwrap();
    let decoded: ShareRequest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.proposal_block, req.proposal_block);
    assert_eq!(decoded.version, 1);
}
