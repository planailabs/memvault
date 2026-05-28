//! P2P networking smoke tests: two live swarms communicating.
//!
//! These tests spawn actual libp2p swarms on localhost, connect them,
//! and verify gossip, auth, and join protocols work end-to-end.

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId as Libp2pPeerId};
use std::time::Duration;
use tokio::time::timeout;

use memvault_net::gossip;
use memvault_net::{
    AdminAnnouncement, AuthRequest, AuthResponse, FederationAnnouncement, JoinRequest, JoinResult,
    standalone_swarm,
};

/// Spawn a swarm on a random port and return it with its listen address.
async fn spawn_swarm() -> (
    libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    Multiaddr,
    Libp2pPeerId,
) {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let mut swarm = standalone_swarm(
        keypair,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(), // random port
        vec![],
    )
    .await
    .unwrap();

    // Wait for listen address
    let addr = loop {
        match swarm.next().await.unwrap() {
            SwarmEvent::NewListenAddr { address, .. } => break address,
            _ => {}
        }
    };

    (swarm, addr, peer_id)
}

/// Connect swarm_a to swarm_b and wait for connection.
async fn connect_swarms(
    swarm_a: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    swarm_b: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    addr_b: &Multiaddr,
) {
    swarm_a.dial(addr_b.clone()).unwrap();

    // Wait for both sides to see the connection
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut a_connected = false;
    let mut b_connected = false;

    while (!a_connected || !b_connected) && tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = swarm_a.next() => {
                if let Some(SwarmEvent::ConnectionEstablished { .. }) = event {
                    a_connected = true;
                }
            }
            event = swarm_b.next() => {
                if let Some(SwarmEvent::ConnectionEstablished { .. }) = event {
                    b_connected = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(a_connected, "swarm_a didn't connect");
    assert!(b_connected, "swarm_b didn't connect");
}

// ── Connection tests ────────────────────────────────────────────────

#[tokio::test]
async fn two_swarms_connect() {
    let (mut swarm_a, _addr_a, _peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, _peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;
}

#[tokio::test]
async fn two_swarms_identify() {
    let (mut swarm_a, _addr_a, _peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;

    // After connection, identify should fire
    let identified = timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = swarm_a.next() => {
                    if let Some(SwarmEvent::Behaviour(memvault_net::StandaloneMemvaultBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { peer_id, .. }
                    ))) = event {
                        if peer_id == peer_b {
                            return true;
                        }
                    }
                }
                event = swarm_b.next() => { let _ = event; }
            }
        }
    }).await;

    assert!(identified.is_ok(), "identify did not complete in time");
}

// ── Gossipsub tests ─────────────────────────────────────────────────

/// Drive both swarms until each side has seen the other's `Subscribed`
/// event for `topic`. Deterministic substitute for the old "sleep 1s and
/// hope" pattern — once both ends know the peer subscribes to the topic,
/// `publish` will deliver immediately via gossipsub's fan-out path
/// (it doesn't have to wait for the heartbeat-driven mesh to form).
async fn wait_for_mesh(
    swarm_a: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    swarm_b: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
    peer_a: Libp2pPeerId,
    peer_b: Libp2pPeerId,
    topic_hash: libp2p::gossipsub::TopicHash,
) {
    let mut a_saw_b = false;
    let mut b_saw_a = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while (!a_saw_b || !b_saw_a) && tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = swarm_a.next() => {
                if let Some(SwarmEvent::Behaviour(
                    memvault_net::StandaloneMemvaultBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Subscribed { peer_id, topic }
                    )
                )) = event {
                    if peer_id == peer_b && topic == topic_hash {
                        a_saw_b = true;
                    }
                }
            }
            event = swarm_b.next() => {
                if let Some(SwarmEvent::Behaviour(
                    memvault_net::StandaloneMemvaultBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Subscribed { peer_id, topic }
                    )
                )) = event {
                    if peer_id == peer_a && topic == topic_hash {
                        b_saw_a = true;
                    }
                }
            }
        }
    }
    assert!(a_saw_b, "swarm_a never saw swarm_b subscribe to {topic_hash}");
    assert!(b_saw_a, "swarm_b never saw swarm_a subscribe to {topic_hash}");
}

#[tokio::test]
async fn gossip_admin_announcement_propagates() {
    let (mut swarm_a, _addr_a, peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;
    let topic = gossip::admin_topic();
    wait_for_mesh(&mut swarm_a, &mut swarm_b, peer_a, peer_b, topic.hash()).await;

    // Publish an admin announcement from swarm_a
    let announcement = AdminAnnouncement::TokenConsumed(vec![1, 2, 3, 4]);
    let data = serde_ipld_dagcbor::to_vec(&announcement).unwrap();
    swarm_a
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), data)
        .unwrap();

    // swarm_b should receive it
    let received = timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = swarm_b.next() => {
                    if let Some(SwarmEvent::Behaviour(memvault_net::StandaloneMemvaultBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    ))) = event {
                        let ann: AdminAnnouncement = serde_ipld_dagcbor::from_slice(&message.data).unwrap();
                        if let AdminAnnouncement::TokenConsumed(cid) = ann {
                            assert_eq!(cid, vec![1, 2, 3, 4]);
                            return true;
                        }
                    }
                }
                _ = swarm_a.next() => {}
            }
        }
    }).await;

    assert!(received.is_ok(), "gossip message not received");
}

#[tokio::test]
async fn gossip_bucket_created_propagates() {
    let (mut swarm_a, _addr_a, peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;
    let admin = gossip::admin_topic();
    wait_for_mesh(&mut swarm_a, &mut swarm_b, peer_a, peer_b, admin.hash()).await;

    let announcement = AdminAnnouncement::BucketCreated(vec![10, 20, 30]);
    let data = serde_ipld_dagcbor::to_vec(&announcement).unwrap();
    swarm_a
        .behaviour_mut()
        .gossipsub
        .publish(gossip::admin_topic(), data)
        .unwrap();

    let received = timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = swarm_b.next() => {
                    if let Some(SwarmEvent::Behaviour(memvault_net::StandaloneMemvaultBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    ))) = event {
                        let ann: AdminAnnouncement = serde_ipld_dagcbor::from_slice(&message.data).unwrap();
                        if let AdminAnnouncement::BucketCreated(cid) = ann {
                            assert_eq!(cid, vec![10, 20, 30]);
                            return true;
                        }
                    }
                }
                _ = swarm_a.next() => {}
            }
        }
    }).await;

    assert!(received.is_ok(), "BucketCreated gossip not received");
}

// ── Auth protocol tests ─────────────────────────────────────────────

#[tokio::test]
async fn auth_request_response() {
    let (mut swarm_a, _addr_a, peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;

    // Send auth request from A to B
    let request = AuthRequest {
        version: 1,
        attestation_block: b"attestation-a".to_vec(),
        cluster_id: vec![1u8; 32],
    };
    swarm_a.behaviour_mut().auth.send_request(&peer_b, request);

    // B should receive the request, A should get a response
    let completed = timeout(Duration::from_secs(5), async {
        let mut b_received = false;
        let mut a_got_response = false;

        while !b_received || !a_got_response {
            tokio::select! {
                event = swarm_a.next() => {
                    if let Some(SwarmEvent::Behaviour(memvault_net::StandaloneMemvaultBehaviourEvent::Auth(
                        libp2p::request_response::Event::Message { message, .. }
                    ))) = event {
                        if let libp2p::request_response::Message::Response { .. } = message {
                            a_got_response = true;
                        }
                    }
                }
                event = swarm_b.next() => {
                    if let Some(SwarmEvent::Behaviour(memvault_net::StandaloneMemvaultBehaviourEvent::Auth(
                        libp2p::request_response::Event::Message { message, peer, .. }
                    ))) = event {
                        if let libp2p::request_response::Message::Request { channel, request, .. } = message {
                            assert_eq!(request.cluster_id, vec![1u8; 32]);
                            // Respond
                            let response = AuthResponse {
                                version: 1,
                                attestation_block: b"attestation-b".to_vec(),
                                cluster_id: vec![1u8; 32],
                            };
                            swarm_b.behaviour_mut().auth.send_response(channel, response).unwrap();
                            b_received = true;
                        }
                    }
                }
            }
        }
        true
    }).await;

    assert!(completed.is_ok(), "auth request/response did not complete");
}

// ── Join protocol tests ─────────────────────────────────────────────

#[tokio::test]
async fn join_request_response() {
    let (mut swarm_a, _addr_a, peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;

    // A sends join request to B
    let request = JoinRequest {
        version: 1,
        token_block: b"join-token-data".to_vec(),
        peer_id: peer_a.to_bytes(),
        requested_ttl: Some(3600),
        agent_id: Some("test-agent".to_string()),
        public_key: Some(vec![0u8; 32]),
    };
    swarm_a.behaviour_mut().join.send_request(&peer_b, request);

    let completed = timeout(Duration::from_secs(5), async {
        let mut b_received = false;
        let mut a_got_response = false;

        while !b_received || !a_got_response {
            tokio::select! {
                event = swarm_a.next() => {
                    if let Some(SwarmEvent::Behaviour(memvault_net::StandaloneMemvaultBehaviourEvent::Join(
                        libp2p::request_response::Event::Message { message, .. }
                    ))) = event {
                        if let libp2p::request_response::Message::Response { response, .. } = message {
                            match response.result {
                                JoinResult::Success { attestation_block, enrollment_block, .. } => {
                                    assert_eq!(attestation_block, b"welcome");
                                    assert_eq!(enrollment_block, Some(b"enrolled".to_vec()));
                                }
                                _ => panic!("expected success"),
                            }
                            a_got_response = true;
                        }
                    }
                }
                event = swarm_b.next() => {
                    if let Some(SwarmEvent::Behaviour(memvault_net::StandaloneMemvaultBehaviourEvent::Join(
                        libp2p::request_response::Event::Message { message, .. }
                    ))) = event {
                        if let libp2p::request_response::Message::Request { channel, request, .. } = message {
                            assert_eq!(request.agent_id, Some("test-agent".to_string()));
                            let response = memvault_net::JoinResponse {
                                version: 1,
                                result: JoinResult::Success {
                                    attestation_block: b"welcome".to_vec(),
                                    enrollment_block: Some(b"enrolled".to_vec()),
                                    bootstrap_blocks: vec![],
                                },
                            };
                            swarm_b.behaviour_mut().join.send_response(channel, response).unwrap();
                            b_received = true;
                        }
                    }
                }
            }
        }
        true
    }).await;

    assert!(completed.is_ok(), "join request/response did not complete");
}

// ── Visibility and access control tests ─────────────────────────────

#[test]
fn visibility_filter_internal_blocks_remote() {
    use memvault_core::Visibility;
    use memvault_net::{
        ConnectionState, FederationState, ServeDecision, ServeRefuseReason, VisibilityFilter,
    };

    let filter = VisibilityFilter::new(b"cluster-1".to_vec());
    let fed_state = FederationState::new(b"cluster-1".to_vec());

    let local_peer = ConnectionState {
        peer_id: b"local-peer".to_vec(),
        cluster_id: b"cluster-1".to_vec(),
        role: "admin".to_string(),
        is_local_cluster: true,
        authenticated_at_ns: 1000,
    };
    let remote_peer = ConnectionState {
        peer_id: b"remote-peer".to_vec(),
        cluster_id: b"cluster-2".to_vec(),
        role: "agent".to_string(),
        is_local_cluster: false,
        authenticated_at_ns: 2000,
    };

    // Internal: only local
    assert!(filter.can_serve(&Visibility::Internal, &local_peer, &fed_state));
    assert!(!filter.can_serve(&Visibility::Internal, &remote_peer, &fed_state));

    // Public: everyone
    assert!(filter.can_serve(&Visibility::Public, &local_peer, &fed_state));
    assert!(filter.can_serve(&Visibility::Public, &remote_peer, &fed_state));
}

#[test]
fn visibility_filter_federated_with_trust() {
    use memvault_core::Visibility;
    use memvault_net::{ConnectionState, FederationState, TrustedClusterInfo, VisibilityFilter};

    let filter = VisibilityFilter::new(b"cluster-1".to_vec());
    let mut fed_state = FederationState::new(b"cluster-1".to_vec());
    fed_state.add_trust(TrustedClusterInfo {
        cluster_id: b"cluster-2".to_vec(),
        admin_keys: vec![[1u8; 32]],
        federated_since_ns: 0,
        not_after_ns: u64::MAX,
    });

    let trusted_peer = ConnectionState {
        peer_id: b"trusted".to_vec(),
        cluster_id: b"cluster-2".to_vec(),
        role: "agent".to_string(),
        is_local_cluster: false,
        authenticated_at_ns: 1000,
    };
    let untrusted_peer = ConnectionState {
        peer_id: b"untrusted".to_vec(),
        cluster_id: b"cluster-3".to_vec(),
        role: "agent".to_string(),
        is_local_cluster: false,
        authenticated_at_ns: 1000,
    };

    assert!(filter.can_serve(&Visibility::Federated, &trusted_peer, &fed_state));
    assert!(!filter.can_serve(&Visibility::Federated, &untrusted_peer, &fed_state));
}

#[test]
fn may_serve_private_bucket_refused() {
    use memvault_core::Visibility;
    use memvault_net::{
        ConnectionState, FederationState, ServeDecision, ServeRefuseReason, VisibilityFilter,
    };

    let filter = VisibilityFilter::new(b"my-cluster".to_vec());
    let fed_state = FederationState::new(b"my-cluster".to_vec());

    let other_peer = ConnectionState {
        peer_id: b"other".to_vec(),
        cluster_id: b"my-cluster".to_vec(),
        role: "agent".to_string(),
        is_local_cluster: true,
        authenticated_at_ns: 1000,
    };

    // Private bucket owned by "owner-peer" — other peers can't access
    let decision = filter.may_serve(
        &Visibility::Internal,
        Some(b"owner-peer"),
        &other_peer,
        &fed_state,
    );
    assert_eq!(
        decision,
        ServeDecision::Refused(ServeRefuseReason::BucketPrivate)
    );
}

// ── Connection registry tests ───────────────────────────────────────

#[test]
fn connection_registry_tracks_peers() {
    use memvault_net::{ConnectionRegistry, ConnectionState};

    let mut registry = ConnectionRegistry::new();

    registry.register(
        b"peer-1".to_vec(),
        ConnectionState {
            peer_id: b"peer-1".to_vec(),
            cluster_id: b"cluster-a".to_vec(),
            role: "admin".to_string(),
            is_local_cluster: true,
            authenticated_at_ns: 1000,
        },
    );
    registry.register(
        b"peer-2".to_vec(),
        ConnectionState {
            peer_id: b"peer-2".to_vec(),
            cluster_id: b"cluster-b".to_vec(),
            role: "agent".to_string(),
            is_local_cluster: false,
            authenticated_at_ns: 2000,
        },
    );

    assert!(registry.get(b"peer-1").is_some());
    assert!(registry.get(b"peer-2").is_some());
    assert!(registry.get(b"peer-3").is_none());

    assert_eq!(registry.local_peers().len(), 1);
    assert_eq!(registry.federation_peers().len(), 1);

    registry.remove(b"peer-1");
    assert!(registry.get(b"peer-1").is_none());
}

// ── Federation state tests ──────────────────────────────────────────

#[test]
fn federation_state_trust_management() {
    use memvault_net::{FederationState, TrustedClusterInfo};

    let mut state = FederationState::new(b"my-cluster".to_vec());

    assert!(!state.is_trusted(b"remote-cluster"));

    state.add_trust(TrustedClusterInfo {
        cluster_id: b"remote-cluster".to_vec(),
        admin_keys: vec![[5u8; 32]],
        federated_since_ns: 1000,
        not_after_ns: u64::MAX,
    });

    assert!(state.is_trusted(b"remote-cluster"));
    assert!(!state.is_trusted(b"unknown-cluster"));

    state.remove_trust(b"remote-cluster");
    assert!(!state.is_trusted(b"remote-cluster"));
}

// ── Block exchange protocol tests ─────────────────────────────────

#[tokio::test]
async fn block_exchange_request_response() {
    let (mut swarm_a, _addr_a, _peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;

    // A requests blocks from B
    let request = memvault_net::BlockRequest {
        cids: vec![vec![1, 2, 3], vec![4, 5, 6]],
        since_ns: None,
        limit: None,
        range_fingerprints: vec![],
        token: None,
        store_version: memvault_core::BLOCKSTORE_VERSION,
    };
    swarm_a
        .behaviour_mut()
        .block_exchange
        .send_request(&peer_b, request);

    let completed = timeout(Duration::from_secs(5), async {
        let mut b_received = false;
        let mut a_got_response = false;

        while !b_received || !a_got_response {
            tokio::select! {
                event = swarm_a.next() => {
                    if let Some(SwarmEvent::Behaviour(
                        memvault_net::StandaloneMemvaultBehaviourEvent::BlockExchange(
                            libp2p::request_response::Event::Message { message, .. }
                        )
                    )) = event {
                        if let libp2p::request_response::Message::Response { response, .. } = message {
                            assert_eq!(response.blocks.len(), 2);
                            assert!(response.blocks[0].found);
                            assert_eq!(response.blocks[0].data, b"block-data-1");
                            assert!(!response.blocks[1].found);
                            a_got_response = true;
                        }
                    }
                }
                event = swarm_b.next() => {
                    if let Some(SwarmEvent::Behaviour(
                        memvault_net::StandaloneMemvaultBehaviourEvent::BlockExchange(
                            libp2p::request_response::Event::Message { message, .. }
                        )
                    )) = event {
                        if let libp2p::request_response::Message::Request { channel, request, .. } = message {
                            assert_eq!(request.cids.len(), 2);
                            // Respond: first block found, second not
                            let response = memvault_net::BlockResponse {
                                blocks: vec![
                                    memvault_net::BlockEntry {
                                        cid: request.cids[0].clone(),
                                        data: b"block-data-1".to_vec(),
                                        found: true,
                                    },
                                    memvault_net::BlockEntry {
                                        cid: request.cids[1].clone(),
                                        data: vec![],
                                        found: false,
                                    },
                                ],
                            };
                            swarm_b.behaviour_mut().block_exchange
                                .send_response(channel, response).unwrap();
                            b_received = true;
                        }
                    }
                }
            }
        }
        true
    })
    .await;

    assert!(completed.is_ok(), "block exchange did not complete");
}

#[tokio::test]
async fn block_exchange_large_block() {
    let (mut swarm_a, _addr_a, _peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;

    // Request a single large block (1 MiB)
    let large_data = vec![0xABu8; 1024 * 1024];
    let request = memvault_net::BlockRequest {
        cids: vec![vec![42; 32]],
        since_ns: None,
        limit: None,
        range_fingerprints: vec![],
        token: None,
        store_version: memvault_core::BLOCKSTORE_VERSION,
    };
    swarm_a
        .behaviour_mut()
        .block_exchange
        .send_request(&peer_b, request);

    let large_data_clone = large_data.clone();
    let completed = timeout(Duration::from_secs(10), async {
        let mut b_received = false;
        let mut a_got_response = false;

        while !b_received || !a_got_response {
            tokio::select! {
                event = swarm_a.next() => {
                    if let Some(SwarmEvent::Behaviour(
                        memvault_net::StandaloneMemvaultBehaviourEvent::BlockExchange(
                            libp2p::request_response::Event::Message { message, .. }
                        )
                    )) = event {
                        if let libp2p::request_response::Message::Response { response, .. } = message {
                            assert_eq!(response.blocks.len(), 1);
                            assert!(response.blocks[0].found);
                            assert_eq!(response.blocks[0].data.len(), 1024 * 1024);
                            a_got_response = true;
                        }
                    }
                }
                event = swarm_b.next() => {
                    if let Some(SwarmEvent::Behaviour(
                        memvault_net::StandaloneMemvaultBehaviourEvent::BlockExchange(
                            libp2p::request_response::Event::Message { message, .. }
                        )
                    )) = event {
                        if let libp2p::request_response::Message::Request { channel, .. } = message {
                            let response = memvault_net::BlockResponse {
                                blocks: vec![memvault_net::BlockEntry {
                                    cid: vec![42; 32],
                                    data: large_data_clone.clone(),
                                    found: true,
                                }],
                            };
                            swarm_b.behaviour_mut().block_exchange
                                .send_response(channel, response).unwrap();
                            b_received = true;
                        }
                    }
                }
            }
        }
        true
    })
    .await;

    assert!(completed.is_ok(), "large block exchange did not complete");
}

// ── Head announcement gossip tests ────────────────────────────────

#[tokio::test]
async fn head_announcement_propagates() {
    let (mut swarm_a, _addr_a, peer_a) = spawn_swarm().await;
    let (mut swarm_b, addr_b, peer_b) = spawn_swarm().await;

    connect_swarms(&mut swarm_a, &mut swarm_b, &addr_b).await;
    let heads = gossip::heads_topic();
    wait_for_mesh(&mut swarm_a, &mut swarm_b, peer_a, peer_b, heads.hash()).await;

    let ann = memvault_net::HeadAnnouncement {
        cid: vec![0xCA; 32],
        cluster_id: vec![1u8; 32],
        wall_ns: 1234567890,
        bucket_id: Some(vec![0xBB; 32]),
    };
    let data = serde_ipld_dagcbor::to_vec(&ann).unwrap();
    swarm_a
        .behaviour_mut()
        .gossipsub
        .publish(gossip::heads_topic(), data)
        .unwrap();

    let received = timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = swarm_b.next() => {
                    if let Some(SwarmEvent::Behaviour(
                        memvault_net::StandaloneMemvaultBehaviourEvent::Gossipsub(
                            libp2p::gossipsub::Event::Message { message, .. }
                        )
                    )) = event {
                        if message.topic.as_str() == memvault_net::HEADS_TOPIC {
                            let decoded: memvault_net::HeadAnnouncement =
                                serde_ipld_dagcbor::from_slice(&message.data).unwrap();
                            assert_eq!(decoded.cid, vec![0xCA; 32]);
                            assert_eq!(decoded.cluster_id, vec![1u8; 32]);
                            assert_eq!(decoded.wall_ns, 1234567890);
                            assert_eq!(decoded.bucket_id, Some(vec![0xBB; 32]));
                            return true;
                        }
                    }
                }
                _ = swarm_a.next() => {}
            }
        }
    })
    .await;

    assert!(received.is_ok(), "head announcement not received");
}

#[test]
fn head_announcement_serialization_roundtrip() {
    let ann = memvault_net::HeadAnnouncement {
        cid: vec![1, 2, 3, 4],
        cluster_id: vec![5; 32],
        wall_ns: 999,
        bucket_id: None,
    };
    let bytes = serde_ipld_dagcbor::to_vec(&ann).unwrap();
    let decoded: memvault_net::HeadAnnouncement = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
    assert_eq!(decoded.cid, ann.cid);
    assert_eq!(decoded.cluster_id, ann.cluster_id);
    assert_eq!(decoded.wall_ns, ann.wall_ns);
    assert_eq!(decoded.bucket_id, None);

    // With bucket_id
    let ann2 = memvault_net::HeadAnnouncement {
        cid: vec![10; 32],
        cluster_id: vec![20; 32],
        wall_ns: 12345,
        bucket_id: Some(vec![30; 32]),
    };
    let bytes2 = serde_ipld_dagcbor::to_vec(&ann2).unwrap();
    let decoded2: memvault_net::HeadAnnouncement = serde_ipld_dagcbor::from_slice(&bytes2).unwrap();
    assert_eq!(decoded2.bucket_id, Some(vec![30; 32]));
}

#[test]
fn block_request_response_serialization_roundtrip() {
    let req = memvault_net::BlockRequest {
        cids: vec![vec![1; 32], vec![2; 32], vec![3; 32]],
        since_ns: None,
        limit: None,
        range_fingerprints: vec![],
        token: None,
        store_version: memvault_core::BLOCKSTORE_VERSION,
    };
    let bytes = serde_ipld_dagcbor::to_vec(&req).unwrap();
    let decoded: memvault_net::BlockRequest = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
    assert_eq!(decoded.cids.len(), 3);

    let resp = memvault_net::BlockResponse {
        blocks: vec![
            memvault_net::BlockEntry {
                cid: vec![1; 32],
                data: b"hello".to_vec(),
                found: true,
            },
            memvault_net::BlockEntry {
                cid: vec![2; 32],
                data: vec![],
                found: false,
            },
        ],
    };
    let bytes = serde_ipld_dagcbor::to_vec(&resp).unwrap();
    let decoded: memvault_net::BlockResponse = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
    assert_eq!(decoded.blocks.len(), 2);
    assert!(decoded.blocks[0].found);
    assert!(!decoded.blocks[1].found);
}
