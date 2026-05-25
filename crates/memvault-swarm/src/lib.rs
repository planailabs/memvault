//! memvault-swarm — shared P2P sync loop for memvault nodes.
//!
//! Runs the libp2p swarm event loop with:
//! - mDNS peer discovery → dial + Kademlia
//! - Identify → Kademlia address update
//! - Gossipsub head announcements → block exchange for missing data
//! - Block exchange server (serve blocks from store)
//! - Block exchange client (store received blocks)
//! - Initial sync on peer connect (announce recent heads)
//! - Outbound head announcements from a channel
//!
//! Used by `memctl daemon` and potentially the mac-mgmt daemon.

use std::collections::HashSet;
use std::sync::Arc;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use tokio::sync::mpsc;

use memvault_net::{
    BlockEntry, BlockRequest, BlockResponse, HeadAnnouncement,
    StandaloneMemvaultBehaviour, StandaloneMemvaultBehaviourEvent,
};
use memvault_store::MemvaultStore;

/// Configuration for the sync loop.
pub struct SyncConfig {
    /// Cluster ID for head announcements.
    pub cluster_id: Vec<u8>,
    /// How far back (in nanoseconds) to announce heads on new peer connect.
    /// Default: 5 minutes.
    pub initial_sync_window_ns: u64,
    /// Maximum number of recent heads to announce on connect.
    pub initial_sync_max_heads: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            cluster_id: vec![0u8; 32],
            initial_sync_window_ns: 5 * 60 * 1_000_000_000,
            initial_sync_max_heads: 500,
        }
    }
}

/// A CID to announce on the gossipsub heads topic.
/// Send these through the `head_tx` channel to trigger outbound announcements.
pub struct OutboundHead {
    pub cid: Vec<u8>,
    pub bucket_id: Option<Vec<u8>>,
}

/// Run the swarm event loop with full block sync.
///
/// This function blocks until ctrl+c is received.
///
/// # Arguments
/// * `swarm` — the libp2p swarm (from `memvault_net::standalone_swarm`)
/// * `store` — the block store for serving and storing blocks
/// * `head_rx` — channel receiving CIDs to announce (from local writes)
/// * `config` — sync configuration
pub async fn run_sync_loop(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: Arc<MemvaultStore>,
    mut head_rx: mpsc::UnboundedReceiver<OutboundHead>,
    config: SyncConfig,
) {
    let mut synced_peers: HashSet<libp2p::PeerId> = HashSet::new();

    loop {
        tokio::select! {
            event = swarm.next() => {
                match event {
                    Some(SwarmEvent::NewListenAddr { address, .. }) => {
                        println!("  Listening on: {address}");
                    }

                    // ── New peer connected: announce recent heads ──
                    Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                        tracing::info!(%peer_id, "peer connected");
                        if synced_peers.insert(peer_id) {
                            announce_recent_heads(swarm, &store, &config);
                        }
                    }

                    Some(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                        tracing::info!(%peer_id, "peer disconnected");
                        synced_peers.remove(&peer_id);
                    }

                    // ── mDNS discovery ──
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::Mdns(
                            libp2p::mdns::Event::Discovered(peers)
                        )
                    )) => {
                        for (peer_id, addr) in peers {
                            tracing::info!(%peer_id, %addr, "mDNS discovered peer");
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                            let _ = swarm.dial(addr);
                        }
                    }
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::Mdns(
                            libp2p::mdns::Event::Expired(peers)
                        )
                    )) => {
                        for (peer_id, addr) in peers {
                            tracing::debug!(%peer_id, %addr, "mDNS peer expired");
                        }
                    }

                    // ── Identify → update Kademlia ──
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::Identify(
                            libp2p::identify::Event::Received { peer_id, info, .. }
                        )
                    )) => {
                        for addr in &info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                        }
                        tracing::debug!(%peer_id, addrs = info.listen_addrs.len(), "identify received");
                    }

                    // ── Gossipsub: head announcements ──
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::Gossipsub(
                            libp2p::gossipsub::Event::Message { propagation_source, message, .. }
                        )
                    )) => {
                        handle_gossip_message(swarm, &store, propagation_source, &message);
                    }

                    // ── Block exchange: serve requests ──
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::BlockExchange(
                            libp2p::request_response::Event::Message {
                                peer,
                                message: libp2p::request_response::Message::Request {
                                    channel, request, ..
                                },
                                ..
                            }
                        )
                    )) => {
                        serve_block_request(swarm, &store, peer, channel, request);
                    }

                    // ── Block exchange: store responses ──
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::BlockExchange(
                            libp2p::request_response::Event::Message {
                                peer,
                                message: libp2p::request_response::Message::Response {
                                    response, ..
                                },
                                ..
                            }
                        )
                    )) => {
                        store_received_blocks(&store, peer, response);
                    }

                    // ── Block exchange: errors ──
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::BlockExchange(
                            libp2p::request_response::Event::OutboundFailure {
                                peer, error, ..
                            }
                        )
                    )) => {
                        tracing::warn!(%peer, %error, "block exchange outbound failure");
                    }
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::BlockExchange(
                            libp2p::request_response::Event::InboundFailure {
                                peer, error, ..
                            }
                        )
                    )) => {
                        tracing::warn!(%peer, %error, "block exchange inbound failure");
                    }

                    Some(SwarmEvent::Behaviour(_)) => {}
                    _ => {}
                }
            }

            // ── Outbound head announcements from local writes ──
            head = head_rx.recv() => {
                match head {
                    Some(outbound) => {
                        publish_head(swarm, &config.cluster_id, outbound);
                    }
                    None => {
                        tracing::debug!("head announcement channel closed");
                    }
                }
            }

            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down...");
                break;
            }
        }
    }
}

/// Create a channel pair for outbound head announcements.
/// The sender goes to the EventBus bridge; the receiver goes to `run_sync_loop`.
pub fn head_channel() -> (mpsc::UnboundedSender<OutboundHead>, mpsc::UnboundedReceiver<OutboundHead>) {
    mpsc::unbounded_channel()
}

// ── Internal helpers ────────────────────────────────────────────────

fn publish_head(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    cluster_id: &[u8],
    outbound: OutboundHead,
) {
    let ann = HeadAnnouncement {
        cid: outbound.cid,
        cluster_id: cluster_id.to_vec(),
        wall_ns: memvault_core::wall_ns(),
        bucket_id: outbound.bucket_id,
    };
    if let Ok(data) = serde_ipld_dagcbor::to_vec(&ann) {
        let _ = swarm
            .behaviour_mut()
            .gossipsub
            .publish(memvault_net::gossip::heads_topic(), data);
    }
}

fn announce_recent_heads(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    config: &SyncConfig,
) {
    let cutoff = memvault_core::wall_ns().saturating_sub(config.initial_sync_window_ns);
    let recent_cids = match store.query_by_time(cutoff, u64::MAX, config.initial_sync_max_heads) {
        Ok(cids) => cids,
        Err(e) => {
            tracing::warn!("failed to query recent heads: {e}");
            return;
        }
    };
    for cid in &recent_cids {
        let ann = HeadAnnouncement {
            cid: cid.clone(),
            cluster_id: config.cluster_id.clone(),
            wall_ns: memvault_core::wall_ns(),
            bucket_id: None,
        };
        if let Ok(data) = serde_ipld_dagcbor::to_vec(&ann) {
            let _ = swarm
                .behaviour_mut()
                .gossipsub
                .publish(memvault_net::gossip::heads_topic(), data);
        }
    }
    if !recent_cids.is_empty() {
        tracing::info!(heads = recent_cids.len(), "announced recent heads to new peer");
    }
}

fn handle_gossip_message(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    source: libp2p::PeerId,
    message: &libp2p::gossipsub::Message,
) {
    let topic = message.topic.as_str();
    if topic == memvault_net::HEADS_TOPIC {
        if let Ok(ann) = serde_ipld_dagcbor::from_slice::<HeadAnnouncement>(&message.data) {
            let have_it = store.get_block(&ann.cid).ok().flatten().is_some();
            if !have_it {
                tracing::debug!(
                    cid = %hex::encode(&ann.cid),
                    %source,
                    "missing block, requesting from peer"
                );
                swarm.behaviour_mut().block_exchange.send_request(
                    &source,
                    BlockRequest { cids: vec![ann.cid] },
                );
            }
        }
    } else if topic == memvault_net::ADMIN_TOPIC {
        tracing::debug!(%source, len = message.data.len(), "admin announcement received");
    } else {
        tracing::debug!(%source, topic, "gossip on unknown topic");
    }
}

fn serve_block_request(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    channel: libp2p::request_response::ResponseChannel<BlockResponse>,
    request: BlockRequest,
) {
    tracing::debug!(%peer, cids = request.cids.len(), "block request received");
    let mut entries = Vec::with_capacity(request.cids.len());
    for cid in &request.cids {
        match store.get_block(cid) {
            Ok(Some(data)) => entries.push(BlockEntry {
                cid: cid.clone(),
                data,
                found: true,
            }),
            _ => entries.push(BlockEntry {
                cid: cid.clone(),
                data: vec![],
                found: false,
            }),
        }
    }
    let found = entries.iter().filter(|e| e.found).count();
    tracing::debug!(%peer, found, total = entries.len(), "serving blocks");
    let _ = swarm
        .behaviour_mut()
        .block_exchange
        .send_response(channel, BlockResponse { blocks: entries });
}

fn store_received_blocks(
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    response: BlockResponse,
) {
    let mut stored = 0usize;
    for entry in &response.blocks {
        if !entry.found || entry.data.is_empty() {
            continue;
        }
        if store.get_block(&entry.cid).ok().flatten().is_some() {
            continue;
        }
        if let Err(e) = store.put_block_unchecked(&entry.cid, &entry.data) {
            tracing::warn!(cid = %hex::encode(&entry.cid), %e, "failed to store synced block");
            continue;
        }
        let _ = store.reindex_block(&entry.cid, &entry.data);
        stored += 1;
        tracing::debug!(cid = %hex::encode(&entry.cid), size = entry.data.len(), "synced block stored");
    }
    if stored > 0 {
        tracing::info!(%peer, stored, total = response.blocks.len(), "blocks synced from peer");
    }
}
