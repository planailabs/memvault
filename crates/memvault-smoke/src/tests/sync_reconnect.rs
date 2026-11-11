//! A peer connection that drops after the initial exchange must be re-dialed.
//!
//! Regression (`checks.x86_64-linux.sync` failing intermittently in a parallel
//! `nix flake check`): both nodes stopped logging right after
//! "peer disconnected" and the doc created on node_a never reached node_b, so
//! the reader polled a bucket it could read (`bucket list` showed the writer's
//! bucket, `grant list` showed the read grant) but exported zero documents for
//! the whole 180 s window. Neither node re-dialed: mDNS reports a peer only
//! when its records appear, the kademlia bootstrap list is empty in that test,
//! and the periodic RBSR round only covers peers that are still connected. The
//! two nodes stayed partitioned for the rest of the poll.
//!
//! The driver must therefore remember dialable addresses and re-dial peers it
//! is no longer connected to, on a throttled timer.

use std::sync::Arc;

use libp2p::Multiaddr;
use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;
use memvault_net::{BlockRequest, BlockResponse, JoinRequest, JoinResponse};
use memvault_swarm::{JoinConfig, MemvaultDriver, MemvaultHost, SyncConfig};

use crate::harness::TestNode;

/// Records every `dial` and `send_block_request`; all other host ops are no-ops.
#[derive(Default)]
struct RecordingHost {
    dialed: Vec<Multiaddr>,
    sent: Vec<(PeerId, BlockRequest)>,
}

impl MemvaultHost for RecordingHost {
    fn dial(&mut self, addr: Multiaddr) {
        self.dialed.push(addr);
    }
    fn kad_add_address(&mut self, _peer: &PeerId, _addr: Multiaddr) {}
    fn kad_set_server_mode(&mut self) {}
    fn kad_bootstrap(&mut self) {}
    fn send_block_request(&mut self, peer: &PeerId, req: BlockRequest) {
        self.sent.push((*peer, req));
    }
    fn send_block_response(&mut self, _c: ResponseChannel<BlockResponse>, _r: BlockResponse) {}
    fn send_join_request(&mut self, _peer: &PeerId, _req: JoinRequest) {}
    fn send_join_response(&mut self, _c: ResponseChannel<JoinResponse>, _r: JoinResponse) {}
    fn gossip_publish(&mut self, _t: libp2p::gossipsub::IdentTopic, _d: Vec<u8>) {}
}

fn join_config(node: &TestNode) -> JoinConfig {
    JoinConfig {
        pending_token: None,
        node_pubkey: [0u8; 32],
        admin_signing_key: None,
        pinned_admin_pubkey: None,
        cluster_id: node.cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    }
}

#[test]
fn dropped_peer_connection_is_redialed() {
    let node = TestNode::new();
    let config = SyncConfig {
        cluster_id: node.cluster_id.0.to_vec(),
        ..Default::default()
    };
    let mut driver = MemvaultDriver::new(Arc::clone(&node.store), config, join_config(&node));
    let mut host = RecordingHost::default();
    let peer = PeerId::random();
    let addr: Multiaddr = "/ip4/192.168.1.2/tcp/4001".parse().unwrap();

    // mDNS discovery registers the address and dials once.
    driver.on_mdns_discovered([(peer, addr.clone())], &mut host);
    assert_eq!(host.dialed, vec![addr.clone()], "discovery dials the peer");

    // Connected: the reconnect tick must not dial it again.
    driver.on_connection_established(peer, &mut host);
    driver.tick_reconnect(&mut host);
    assert_eq!(host.dialed.len(), 1, "a connected peer is not re-dialed");

    // The connection drops. mDNS will not report the peer again, so the tick
    // is the only thing that can bring the pair back together.
    driver.on_connection_closed(peer);
    driver.tick_reconnect(&mut host);
    assert_eq!(
        host.dialed,
        vec![addr.clone(), addr.clone()],
        "a dropped peer is re-dialed from the remembered address"
    );

    // Throttled: an immediate second tick must not dial again, so a peer that
    // is really gone costs one attempt per interval rather than a hot loop.
    driver.tick_reconnect(&mut host);
    assert_eq!(host.dialed.len(), 2, "reconnects are throttled per peer");
}

#[test]
fn identify_address_is_a_reconnect_fallback() {
    let node = TestNode::new();
    let config = SyncConfig {
        cluster_id: node.cluster_id.0.to_vec(),
        ..Default::default()
    };
    let mut driver = MemvaultDriver::new(Arc::clone(&node.store), config, join_config(&node));
    let mut host = RecordingHost::default();
    let peer = PeerId::random();
    let wildcard: Multiaddr = "/ip4/0.0.0.0/tcp/4001".parse().unwrap();
    let concrete: Multiaddr = "/ip4/192.168.1.9/tcp/4001".parse().unwrap();

    // A peer we dialed directly never went through mDNS: identify is the only
    // source of an address, and the wildcard listen addr must be skipped.
    driver.on_identify(
        peer,
        &[wildcard, concrete.clone()],
        "memvault/00",
        &mut host,
    );
    driver.on_connection_established(peer, &mut host);
    driver.on_connection_closed(peer);
    driver.tick_reconnect(&mut host);

    assert_eq!(
        host.dialed,
        vec![concrete],
        "identify's concrete listen address is used for the re-dial"
    );
}
