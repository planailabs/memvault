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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use tokio::sync::mpsc;

use memvault_net::{
    BlockEntry, BlockRequest, BlockResponse, HeadAnnouncement, RangeFingerprint,
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
    // Track peer → cluster_id for visibility enforcement.
    let mut peer_clusters: HashMap<libp2p::PeerId, Vec<u8>> = HashMap::new();
    // Periodic resync timer to heal partial sync.
    let mut resync_timer = tokio::time::interval(RESYNC_INTERVAL);
    resync_timer.tick().await; // consume the immediate first tick

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
                            request_remote_heads(swarm, &store, &config, peer_id);
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
                        // Extract cluster_id from the identify agent string if it
                        // contains a hex-encoded cluster ID (convention: "memvault/<cluster_hex>").
                        if let Some(cluster_hex) = info.agent_version.strip_prefix("memvault/") {
                            if let Ok(cid_bytes) = hex::decode(cluster_hex) {
                                peer_clusters.insert(peer_id, cid_bytes);
                            }
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
                        serve_block_request(swarm, &store, peer, channel, request, &config.cluster_id, &peer_clusters);
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

            // ── Periodic re-sync to heal partial sync ──
            _ = resync_timer.tick() => {
                let peers: Vec<_> = synced_peers.iter().copied().collect();
                if !peers.is_empty() {
                    tracing::info!(peers = peers.len(), "periodic RBSR resync");
                    for peer_id in peers {
                        request_remote_heads(swarm, &store, &config, peer_id);
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
pub fn head_channel() -> (
    mpsc::UnboundedSender<OutboundHead>,
    mpsc::UnboundedReceiver<OutboundHead>,
) {
    mpsc::unbounded_channel()
}

// ── Internal helpers ────────────────────────────────────────────────

/// Number of time windows for RBSR initial sync.
const RBSR_WINDOWS: usize = 64;

/// Max CIDs per follow-up fetch request. Keeps the response (with full
/// block data) well within the 512 MiB codec limit even for large blocks.
const FETCH_CHUNK_SIZE: usize = 50;

/// How often to re-run RBSR for connected peers to heal partial sync.
const RESYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// On new peer connect, send range fingerprints covering the FULL store
/// (not just recent data). RBSR makes this efficient: matching windows
/// are skipped, so bandwidth is proportional to the diff.
fn request_remote_heads(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    _config: &SyncConfig,
    peer_id: libp2p::PeerId,
) {
    let now = memvault_core::wall_ns();
    // Cover all time: from epoch 0 to now. The first window catches
    // all data created before the other windows.
    let window_size = now / RBSR_WINDOWS as u64;
    if window_size == 0 {
        return;
    }

    let mut fingerprints = Vec::with_capacity(RBSR_WINDOWS);
    for i in 0..RBSR_WINDOWS {
        let start = (i as u64) * window_size;
        let end = if i == RBSR_WINDOWS - 1 {
            u64::MAX
        } else {
            start + window_size
        };
        let (count, xor) = store
            .range_fingerprint(start, end)
            .unwrap_or((0, [0u8; 32]));
        fingerprints.push(RangeFingerprint {
            start_ns: start,
            end_ns: end,
            count: count as u32,
            xor,
        });
    }

    let total: u32 = fingerprints.iter().map(|f| f.count).sum();
    let request = BlockRequest {
        cids: vec![],
        since_ns: None,
        limit: None,
        range_fingerprints: fingerprints,
        token: None,
    };
    swarm
        .behaviour_mut()
        .block_exchange
        .send_request(&peer_id, request);
    tracing::info!(%peer_id, windows = RBSR_WINDOWS, total_blocks = total, "sent RBSR full sync request");
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
                    BlockRequest {
                        cids: vec![ann.cid],
                        since_ns: None,
                        limit: None,
                        range_fingerprints: vec![],
                        token: None,
                    },
                );
            }
        }
    } else if topic == memvault_net::ADMIN_TOPIC {
        tracing::debug!(%source, len = message.data.len(), "admin announcement received");
    }
}

/// Serve a block exchange request. Three modes:
/// - **Fetch** (cids non-empty): return block data for each CID.
/// - **RBSR** (range_fingerprints non-empty): compare fingerprints, return
///   CIDs from mismatched windows (bandwidth ∝ diff, not total set size).
/// - **List heads** (cids empty, since_ns set): return recent CIDs (no data).
fn serve_block_request(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    channel: libp2p::request_response::ResponseChannel<BlockResponse>,
    request: BlockRequest,
    cluster_id: &[u8],
    peer_clusters: &std::collections::HashMap<libp2p::PeerId, Vec<u8>>,
) {
    let peer_cluster = peer_clusters.get(&peer);
    let is_local = peer_cluster.map(|c| c == cluster_id).unwrap_or(false);

    let entries =
        if !request.cids.is_empty() {
            // Fetch mode: return block data, with visibility check.
            tracing::debug!(%peer, cids = request.cids.len(), "block fetch request");
            request.cids.iter().map(|cid| {
            match store.get_block(cid) {
                Ok(Some(data)) => {
                    // Visibility enforcement: check bucket access.
                    if !is_local && !check_block_access(store, cid, &data, &request.token) {
                        tracing::debug!(%peer, cid = %hex::encode(cid), "block access denied");
                        BlockEntry { cid: cid.clone(), data: vec![], found: false }
                    } else {
                        BlockEntry { cid: cid.clone(), data, found: true }
                    }
                }
                _ => BlockEntry { cid: cid.clone(), data: vec![], found: false },
            }
        }).collect()
        } else if !request.range_fingerprints.is_empty() {
            // RBSR mode: compare fingerprints, return CIDs from mismatched windows.
            let mut diff_cids = Vec::new();
            let mut matched = 0usize;
            let mut mismatched = 0usize;
            for rf in &request.range_fingerprints {
                let (local_count, local_xor) = store
                    .range_fingerprint(rf.start_ns, rf.end_ns)
                    .unwrap_or((0, [0u8; 32]));
                if local_count as u32 == rf.count && local_xor == rf.xor {
                    matched += 1;
                    continue; // Same data in this window.
                }
                mismatched += 1;
                // Return ALL our CIDs from this window so the requester can diff.
                // No limit — bandwidth is already bounded by the number of
                // mismatched windows, and truncating here causes silent
                // data loss when blocks cluster temporally (burst writes).
                if let Ok(cids) = store.query_by_time(rf.start_ns, rf.end_ns, usize::MAX) {
                    for cid in cids {
                        diff_cids.push(BlockEntry {
                            cid,
                            data: vec![],
                            found: true,
                        });
                    }
                }
            }
            tracing::debug!(%peer, matched, mismatched, diff = diff_cids.len(), "RBSR response");
            diff_cids
        } else if let Some(since_ns) = request.since_ns {
            // List-heads fallback.
            let limit = request.limit.unwrap_or(500);
            tracing::debug!(%peer, since_ns, limit, "list-heads request");
            match store.query_by_time(since_ns, u64::MAX, limit) {
                Ok(cids) => cids
                    .into_iter()
                    .map(|cid| BlockEntry {
                        cid,
                        data: vec![],
                        found: true,
                    })
                    .collect(),
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

/// Check whether a block should be served to a remote peer.
/// For local cluster peers, always allow. For remote peers, check
/// bucket visibility and BAT.
fn check_block_access(
    store: &MemvaultStore,
    _cid: &[u8],
    block_data: &[u8],
    token: &Option<memvault_net::BlockAccessToken>,
) -> bool {
    // Parse the block to check if it has a bucket_id.
    let val: serde_json::Value = match serde_json::from_slice(block_data) {
        Ok(v) => v,
        Err(_) => return true, // Non-JSON blocks (raw file chunks) are allowed.
    };

    // Check if the block belongs to a private bucket.
    let bucket_id = val
        .get("bucket_id")
        .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok());

    let bucket_id = match bucket_id {
        Some(bid) => bid,
        None => return true, // No bucket association → public.
    };

    // If a BAT is provided and matches this bucket, allow.
    if let Some(bat) = token {
        if bat.bucket_id.as_slice() == bucket_id.as_slice() {
            // BAT signature verification requires the admin key, which
            // we'd need to look up. For now, check structural validity.
            // Full verification requires the store to hold the issuer's
            // public key — look up from BUCKET_TRUST or admin key.
            if !bat.signature.is_empty() && bat.not_after_ns >= memvault_core::wall_ns() {
                return true;
            }
        }
    }

    // No valid BAT → check if bucket is private.
    // A private bucket has `private_to_peer` set in its decl.
    if let Ok(Some(decl_cid)) = store.get_bucket(&bucket_id) {
        if let Ok(Some(decl_data)) = store.get_block(&decl_cid) {
            if let Ok(decl) = serde_json::from_slice::<serde_json::Value>(&decl_data) {
                // Check both envelope format and legacy raw decl.
                let ptp = decl
                    .get("payload")
                    .and_then(|p| p.get("BucketCreate"))
                    .and_then(|bc| bc.get("private_to_peer"))
                    .or_else(|| decl.get("private_to_peer"));
                if ptp.is_some() && !ptp.unwrap().is_null() {
                    return false; // Private bucket, no valid BAT.
                }
            }
        }
    }

    true // Attached bucket, allow.
}

/// Handle a block exchange response. Two cases:
/// - Blocks with data → store them locally.
/// - CID-only entries (from list-heads) → request the ones we're missing.
///
/// Also chases references: if a stored block is an attachment envelope
/// (references manifest_cid) or an AttachmentManifest (references
/// content_root / chunk CIDs), those dependent CIDs are queued for
/// fetch. Without this, file data chunks are invisible to RBSR (they
/// have no BY_TIME entry) and silently diverge between nodes.
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
            if let Err(e) = store.put_block(&entry.cid, &entry.data) {
                tracing::warn!(cid = %hex::encode(&entry.cid), %e, "failed to store synced block");
                continue;
            }
            let _ = store.reindex_block(&entry.cid, &entry.data);
            // Also try bucket-specific reindexing (BUCKETS table).
            let _ = store.reindex_bucket_decl(&entry.cid, &entry.data);
            stored += 1;
            tracing::debug!(cid = %hex::encode(&entry.cid), size = entry.data.len(), "synced block stored");

            // Chase references: envelopes → manifest, manifests → content_root.
            // This ensures file data chunks are fetched even though they have
            // no BY_TIME entry and are invisible to RBSR.
            for dep_cid in extract_dependent_cids(&entry.data) {
                if store.get_block(&dep_cid).ok().flatten().is_none() {
                    missing_cids.push(dep_cid);
                }
            }
        }
    }

    if stored > 0 {
        tracing::info!(%peer, stored, "blocks synced from peer");
    }

    // Follow up: fetch the blocks we're missing in chunks.
    // A single response with thousands of full blocks easily exceeds the
    // 16 MiB codec limit, causing a silent OutboundFailure. Chunk into
    // batches of FETCH_CHUNK_SIZE to keep responses within bounds.
    if !missing_cids.is_empty() {
        tracing::info!(%peer, missing = missing_cids.len(), "requesting missing blocks from peer");
        for chunk in missing_cids.chunks(FETCH_CHUNK_SIZE) {
            swarm.behaviour_mut().block_exchange.send_request(
                &peer,
                BlockRequest {
                    cids: chunk.to_vec(),
                    since_ns: None,
                    limit: None,
                    range_fingerprints: vec![],
                    token: None,
                },
            );
        }
    }
}

/// Extract CIDs referenced by a block so the sync loop can chase them.
///
/// Handles three cases:
/// - **Attachment envelope** (kind: "attachment"): has `manifest_cid`
/// - **AttachmentManifest**: has `content_root` (the UnixFS DAG root)
/// - **DAG-PB node** (protobuf): has `links[].hash` pointing to child blocks
///
/// Without this, file data chunks (stored via `put_block`, no BY_TIME
/// entry) are invisible to RBSR and silently diverge between nodes.
fn extract_dependent_cids(block_data: &[u8]) -> Vec<Vec<u8>> {
    // Try JSON first (envelopes, manifests).
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(block_data) {
        let mut deps = Vec::new();

        // Attachment envelope → manifest_cid
        if let Some(mcid) = val
            .get("manifest_cid")
            .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
        {
            deps.push(mcid);
        }

        // AttachmentManifest → content_root (UnixFS DAG root CID)
        if let Some(root) = val
            .get("content_root")
            .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
        {
            deps.push(root);
        }

        // Causal / provenance links (envelope references to prior blocks)
        if let Some(arr) = val.get("causal").and_then(|v| v.as_array()) {
            for v in arr {
                if let Ok(cid) = serde_json::from_value::<Vec<u8>>(v.clone()) {
                    deps.push(cid);
                }
            }
        }

        return deps;
    }

    // Try DAG-PB (protobuf UnixFS nodes): extract child CIDs from links.
    use prost::Message;
    if let Ok(node) = memvault_attach::proto::PbNode::decode(block_data) {
        return node
            .links
            .into_iter()
            .filter_map(|link| link.hash)
            .collect();
    }

    vec![]
}
