//! A block-exchange request that dies with its substream must be re-issued
//! within seconds.
//!
//! Regression (pipeline 3056 deploy, job 7526; reproduced locally by
//! `nix build .#checks.x86_64-linux.sync`): node_b fetched the synced doc
//! block, then lost the *queued* grant block when its outbound substream died
//! with the connection ("IO error on outbound stream: connection lost"). The
//! gate retried the fetch once, the retry hit the same dead substream, and the
//! request was dropped. The only remaining heal was the periodic RBSR round —
//! five minutes away — while the sync test polls for 180 s, so every
//! bucket-scoped read on node_b answered 404 for the whole window and the
//! check failed.
//!
//! The driver must therefore re-request heads from a peer whose last exchange
//! failed on a short timer, not just when it reconnects or on the next local
//! write.

use std::sync::Arc;

use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;
use memvault_net::{BlockEntry, BlockRequest, BlockResponse, JoinRequest, JoinResponse};
use memvault_swarm::{JoinConfig, MemvaultDriver, MemvaultHost, SyncConfig};

use crate::harness::TestNode;

/// Records every `send_block_request`; all other host ops are no-ops.
#[derive(Default)]
struct RecordingHost {
    sent: Vec<(PeerId, BlockRequest)>,
}

impl MemvaultHost for RecordingHost {
    fn dial(&mut self, _addr: libp2p::Multiaddr) {}
    fn kad_add_address(&mut self, _peer: &PeerId, _addr: libp2p::Multiaddr) {}
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
fn lost_block_request_is_rerequested_without_waiting_for_resync() {
    let node = TestNode::new();
    let config = SyncConfig {
        cluster_id: node.cluster_id.0.to_vec(),
        ..Default::default()
    };
    let mut driver = MemvaultDriver::new(Arc::clone(&node.store), config, join_config(&node));
    let mut host = RecordingHost::default();
    let peer = PeerId::random();
    let missing_cid = vec![0xAB_u8; 34];

    // A peer connects: the driver probes it with an RBSR (head) request.
    driver.on_connection_established(peer, &mut host);
    assert_eq!(host.sent.len(), 1, "connect must issue one head request");
    assert!(
        !host.sent[0].1.range_fingerprints.is_empty(),
        "the connect request is an RBSR probe"
    );

    // The peer's diff names one CID we do not hold: the driver fetches it.
    driver.on_block_response(
        peer,
        BlockResponse {
            blocks: vec![BlockEntry {
                cid: missing_cid.clone(),
                data: Vec::new(),
                found: true,
            }],
        },
        &mut host,
    );
    assert_eq!(host.sent.len(), 2, "a missing CID must be fetched");
    assert_eq!(host.sent[1].1.cids, vec![missing_cid.clone()]);

    // The substream dies with its connection: the gate retries once, then
    // gives up (no third immediate attempt on a dead stream).
    driver.on_block_outbound_failure(peer, &mut host);
    assert_eq!(host.sent.len(), 3, "a failed fetch is retried once");
    driver.on_block_outbound_failure(peer, &mut host);
    assert_eq!(host.sent.len(), 3, "a failed retry is not re-sent inline");

    // The peer is still connected and the CID is still missing. The
    // failed-peer tick must re-issue a head request instead of leaving the
    // peer incomplete until the next five-minute RBSR round.
    driver.tick_failed_resync(&mut host);
    assert_eq!(
        host.sent.len(),
        4,
        "a peer whose exchange failed must be re-requested promptly"
    );
    assert_eq!(host.sent[3].0, peer);
    assert!(
        !host.sent[3].1.range_fingerprints.is_empty(),
        "the retry is an RBSR probe, so the diff re-names the lost CID"
    );

    // A second tick with nothing failed since must stay quiet: the retry is
    // armed by failures, not fired unconditionally every tick.
    driver.tick_failed_resync(&mut host);
    assert_eq!(host.sent.len(), 4, "no retry without a new failure");
}
