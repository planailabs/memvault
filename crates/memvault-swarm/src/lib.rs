//! memvault-swarm — shared P2P sync loop for memvault nodes.
//!
//! Runs the libp2p swarm event loop with:
//! - mDNS peer discovery → dial + Kademlia
//! - Identify → Kademlia address update
//! - Gossipsub head announcements → block exchange for missing data
//! - Block exchange server (serve blocks + list recent heads)
//! - Block exchange client (store received blocks, request missing)
//! - Initial sync on peer connect via block exchange (not gossipsub)
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
    /// How far back (in nanoseconds) to request heads on new peer connect.
    /// Default: 5 minutes.
    pub initial_sync_window_ns: u64,
    /// Maximum number of recent heads to request on connect.
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

                    // ── New peer connected: request their recent heads ──
                    Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                        tracing::info!(%peer_id, "peer connected");
                        if synced_peers.insert(peer_id) {
                            request_remote_heads(swarm, &config, peer_id);
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

                    // ── Block exchange: process responses ──
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
                        handle_block_response(swarm, &store, peer, response);
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
pub fn head_channel() -> (mpsc::UnboundedSender<OutboundHead>, mpsc::UnboundedReceiver<OutboundHead>) {
    mpsc::unbounded_channel()
}

// ── Internal helpers ────────────────────────────────────────────────

/// On new peer connect, send a "list heads" BlockRequest via request-response
/// (works immediately, unlike gossipsub which needs mesh formation).
fn request_remote_heads(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    config: &SyncConfig,
    peer_id: libp2p::PeerId,
) {
    let cutoff = memvault_core::wall_ns().saturating_sub(config.initial_sync_window_ns);
    let request = BlockRequest {
        cids: vec![],
        since_ns: Some(cutoff),
        limit: Some(config.initial_sync_max_heads),
    };
    swarm.behaviour_mut().block_exchange.send_request(&peer_id, request);
    tracing::debug!(%peer_id, "sent initial sync request");
}

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

fn handle_gossip_message(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    source: libp2p::PeerId,
    message: &libp2p::gossipsub::Message,
) {
    let topic = message.topic.as_str();
    if topic == memvault_net::HEADS_TOPIC {
        if let Ok(ann) = serde_ipld_dagcbor::from_slice::<HeadAnnouncement>(&message.data) {
            if store.get_block(&ann.cid).ok().flatten().is_none() {
                tracing::debug!(cid = %hex::encode(&ann.cid), %source, "missing block from gossip");
                swarm.behaviour_mut().block_exchange.send_request(
                    &source,
                    BlockRequest { cids: vec![ann.cid], since_ns: None, limit: None },
                );
            }
        }
    } else if topic == memvault_net::ADMIN_TOPIC {
        tracing::debug!(%source, len = message.data.len(), "admin announcement received");
    }
}

/// Serve a block exchange request. Two modes:
/// - **Fetch** (cids non-empty): return block data for each CID.
/// - **List heads** (cids empty, since_ns set): return recent CIDs (no data).
fn serve_block_request(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    channel: libp2p::request_response::ResponseChannel<BlockResponse>,
    request: BlockRequest,
) {
    let entries = if !request.cids.is_empty() {
        // Fetch mode: return block data.
        tracing::debug!(%peer, cids = request.cids.len(), "block fetch request");
        request.cids.iter().map(|cid| {
            match store.get_block(cid) {
                Ok(Some(data)) => BlockEntry { cid: cid.clone(), data, found: true },
                _ => BlockEntry { cid: cid.clone(), data: vec![], found: false },
            }
        }).collect()
    } else if let Some(since_ns) = request.since_ns {
        // List-heads mode: return recent CIDs without data.
        let limit = request.limit.unwrap_or(500);
        tracing::debug!(%peer, since_ns, limit, "list-heads request");
        match store.query_by_time(since_ns, u64::MAX, limit) {
            Ok(cids) => cids.into_iter().map(|cid| {
                BlockEntry { cid, data: vec![], found: true }
            }).collect(),
            Err(e) => {
                tracing::warn!(%peer, %e, "failed to query recent heads");
                vec![]
            }
        }
    } else {
        vec![]
    };

    let found = entries.iter().filter(|e| e.found).count();
    tracing::debug!(%peer, found, total = entries.len(), "serving block response");
    let _ = swarm
        .behaviour_mut()
        .block_exchange
        .send_response(channel, BlockResponse { blocks: entries });
}

/// Handle a block exchange response. Two cases:
/// - Blocks with data → store them locally.
/// - CID-only entries (from list-heads) → request the ones we're missing.
fn handle_block_response(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    response: BlockResponse,
) {
    let mut stored = 0usize;
    let mut missing_cids: Vec<Vec<u8>> = Vec::new();

    for entry in &response.blocks {
        if !entry.found {
            continue;
        }
        if entry.data.is_empty() {
            // CID-only entry (from list-heads): check if we need it.
            if store.get_block(&entry.cid).ok().flatten().is_none() {
                missing_cids.push(entry.cid.clone());
            }
        } else {
            // Full block: store it.
            if store.get_block(&entry.cid).ok().flatten().is_some() {
                continue; // already have it
            }
            if let Err(e) = store.put_block_unchecked(&entry.cid, &entry.data) {
                tracing::warn!(cid = %hex::encode(&entry.cid), %e, "failed to store synced block");
                continue;
            }
            let _ = store.reindex_block(&entry.cid, &entry.data);
            stored += 1;
            tracing::debug!(cid = %hex::encode(&entry.cid), size = entry.data.len(), "synced block stored");
        }
    }

    if stored > 0 {
        tracing::info!(%peer, stored, "blocks synced from peer");
    }

    // Follow up: fetch the blocks we're missing (from a list-heads response).
    if !missing_cids.is_empty() {
        tracing::info!(%peer, missing = missing_cids.len(), "requesting missing blocks from peer");
        swarm.behaviour_mut().block_exchange.send_request(
            &peer,
            BlockRequest { cids: missing_cids, since_ns: None, limit: None },
        );
    }
}
