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
    BlockEntry, BlockRequest, BlockResponse, HeadAnnouncement, JoinRefuseReason, JoinRequest,
    JoinResponse, JoinResult, RangeFingerprint, StandaloneMemvaultBehaviour,
    StandaloneMemvaultBehaviourEvent,
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

/// Configuration for the `/ai-memvault/join/1.0` protocol — both the
/// client-side (we have a pending token, looking for admin to accept it)
/// and server-side (we are admin, accept tokens and mint `NodeAttestation`).
#[derive(Clone, Default)]
pub struct JoinConfig {
    /// Encoded `mvjoin1:…` token. If present, the sync loop sends a
    /// `JoinRequest` to each peer on first connect until one returns
    /// `Success`. Cleared by [`on_join_success`].
    pub pending_token: Option<String>,
    /// This node's ed25519 verifying key (sent as `peer_id` in the request).
    /// Used by admin to verify the requester controls the key it claims.
    pub node_pubkey: [u8; 32],
    /// Admin signing key, set only on the admin node. When present, this
    /// node serves incoming `JoinRequest`s by minting a `NodeAttestation`.
    pub admin_signing_key: Option<ed25519_dalek::SigningKey>,
    /// Cluster ID — bound into NodeAttestations we mint as admin.
    pub cluster_id: [u8; 32],
    /// Called once after a successful join. Callers typically use this to
    /// delete the pending-token file on disk so we don't try to redeem it
    /// again on the next restart.
    pub on_join_success: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

/// Run the swarm event loop with full block sync.
///
/// This function blocks until ctrl+c is received.
pub async fn run_sync_loop(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: Arc<MemvaultStore>,
    mut head_rx: mpsc::UnboundedReceiver<OutboundHead>,
    config: SyncConfig,
    mut join_config: JoinConfig,
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
                        // If we have a pending join token, redeem it with
                        // this peer. Only admin will reply Success — other
                        // peers respond NotAdminPeer and we keep waiting.
                        if let Some(token) = &join_config.pending_token {
                            send_join_request(swarm, peer_id, token, join_config.node_pubkey);
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

                    // ── /join/1.0 server: incoming JoinRequest ──
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::Join(
                            libp2p::request_response::Event::Message {
                                peer,
                                message: libp2p::request_response::Message::Request {
                                    channel, request, ..
                                },
                                ..
                            }
                        )
                    )) => {
                        serve_join_request(swarm, &store, peer, channel, request, &join_config);
                    }

                    // ── /join/1.0 client: response to our JoinRequest ──
                    Some(SwarmEvent::Behaviour(
                        StandaloneMemvaultBehaviourEvent::Join(
                            libp2p::request_response::Event::Message {
                                peer,
                                message: libp2p::request_response::Message::Response {
                                    response, ..
                                },
                                ..
                            }
                        )
                    )) => {
                        if handle_join_response(&store, peer, response) {
                            // Success. Clear pending token + fire callback
                            // (caller removes the pending-token file).
                            join_config.pending_token = None;
                            if let Some(cb) = join_config.on_join_success.take() {
                                cb();
                            }
                        }
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
                    for peer_id in &peers {
                        request_remote_heads(swarm, &store, &config, *peer_id);
                    }

                    // Verify completeness: walk all stored blocks, find missing
                    // dependencies (manifest → DAG chunks), and re-request them.
                    let missing = collect_incomplete_cids(&store);
                    if !missing.is_empty() {
                        let target = peers[0]; // request from first connected peer
                        tracing::info!(missing = missing.len(), %target, "requesting incomplete file chunks");
                        for chunk in missing.chunks(FETCH_CHUNK_SIZE) {
                            swarm.behaviour_mut().block_exchange.send_request(
                                &target,
                                BlockRequest {
                                    cids: chunk.to_vec(),
                                    since_ns: None,
                                    limit: None,
                                    range_fingerprints: vec![],
                                    token: None,
                                    store_version: memvault_core::BLOCKSTORE_VERSION,
                                },
                            );
                        }
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
        store_version: memvault_core::BLOCKSTORE_VERSION,
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
                        store_version: memvault_core::BLOCKSTORE_VERSION,
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
    // Reject requests from peers with a different blockstore version.
    let local_version = memvault_core::BLOCKSTORE_VERSION;
    if request.store_version != local_version {
        tracing::warn!(
            %peer,
            remote = request.store_version,
            local = local_version,
            "rejecting sync: blockstore version mismatch"
        );
        let _ = swarm
            .behaviour_mut()
            .block_exchange
            .send_response(channel, BlockResponse { blocks: vec![] });
        return;
    }

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
    let val: serde_json::Value = match memvault_store::deserialize_block(block_data) {
        Some(v) => v,
        None => return true, // Raw file chunks are allowed.
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
            if let Some(decl) = memvault_store::deserialize_block(&decl_data) {
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
                    store_version: memvault_core::BLOCKSTORE_VERSION,
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
    if let Some(val) = memvault_store::deserialize_block(block_data) {
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

/// Walk every stored block, extract its dependencies, and return CIDs that
/// are referenced but missing from the store.  This catches incomplete file
/// DAGs (envelope present but some chunks missing due to interrupted sync).
fn collect_incomplete_cids(store: &MemvaultStore) -> Vec<Vec<u8>> {
    let blocks = match store.iter_blocks() {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    let mut missing: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();

    for (_cid, data) in &blocks {
        for dep in extract_dependent_cids(data) {
            if seen.insert(dep.clone()) {
                if store.get_block(&dep).ok().flatten().is_none() {
                    missing.push(dep);
                }
            }
        }
    }

    missing
}


// ─────────────────────────────────────────────────────────────────────────
// /ai-memvault/join/1.0 — node-attestation handshake.
//
// Server: any node that holds the cluster admin signing key accepts incoming
// JoinRequests. The request carries a join-token issued by admin and the
// requester's ed25519 pubkey. We verify the token's admin-signature with
// the local admin key, verify the requester's libp2p PeerId matches the
// claimed pubkey, then mint a NodeAttestation for the requester and return
// it. The mint is persisted via insert_envelope so the store's index
// notifier fires the usual sigchain pipeline (gossip, watcher updates).
//
// Client: any node carrying a pending token sends a JoinRequest to every
// peer that connects. Only the admin will return Success; others return
// NotAdminPeer (or other refuse codes). On Success we put_block the
// returned attestation locally; reindex_block fires the notifier so our
// own trust state picks it up live and we cease to be PreGenesis.
// ─────────────────────────────────────────────────────────────────────────

fn send_join_request(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    peer_id: libp2p::PeerId,
    token: &str,
    node_pubkey: [u8; 32],
) {
    let req = JoinRequest {
        version: 1,
        token_block: token.as_bytes().to_vec(),
        peer_id: node_pubkey.to_vec(),
        requested_ttl: None,
        agent_id: None,
        public_key: None,
    };
    let _ = swarm.behaviour_mut().join.send_request(&peer_id, req);
    tracing::debug!(%peer_id, "sent /join/1.0 request");
}

fn serve_join_request(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    channel: libp2p::request_response::ResponseChannel<JoinResponse>,
    request: JoinRequest,
    join_config: &JoinConfig,
) {
    let response = build_join_response(store, peer, &request, join_config);
    let _ = swarm.behaviour_mut().join.send_response(channel, response);
}

fn build_join_response(
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    request: &JoinRequest,
    join_config: &JoinConfig,
) -> JoinResponse {
    if request.version != 1 {
        return refuse(JoinRefuseReason::TokenInvalidSignature);
    }
    let Some(admin_sk) = &join_config.admin_signing_key else {
        return refuse(JoinRefuseReason::NotAdminPeer);
    };

    // Decode the token. token_block is the raw mvjoin1: string bytes.
    let token_str = match std::str::from_utf8(&request.token_block) {
        Ok(s) => s,
        Err(_) => return refuse(JoinRefuseReason::TokenInvalidSignature),
    };
    let token = match memvault_auth::decode_token_string(token_str) {
        Ok(t) => t,
        Err(_) => return refuse(JoinRefuseReason::TokenInvalidSignature),
    };

    // Verify the token signature against our admin pubkey.
    let admin_vk = admin_sk.verifying_key();
    if token.verify_signature(&admin_vk).is_err() {
        return refuse(JoinRefuseReason::TokenInvalidSignature);
    }

    // Time bounds.
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    if let Err(e) = token.verify_time_bounds(now_ns) {
        return match e {
            memvault_auth::AuthError::GrantExpired => refuse(JoinRefuseReason::TokenExpired),
            memvault_auth::AuthError::GrantNotYetValid => {
                refuse(JoinRefuseReason::TokenNotYetValid)
            }
            _ => refuse(JoinRefuseReason::TokenInvalidSignature),
        };
    }

    // Cluster_id must match ours.
    if token.cluster_id.0 != join_config.cluster_id {
        return refuse(JoinRefuseReason::TokenInvalidSignature);
    }

    // Verify the libp2p peer's PeerId derives from the claimed pubkey.
    // This proves the requester controls the key they're asking us to attest.
    let claimed: [u8; 32] = match request.peer_id.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return refuse(JoinRefuseReason::PeerIdMismatch),
    };
    if !peer_id_matches_pubkey(peer, &claimed) {
        return refuse(JoinRefuseReason::PeerIdMismatch);
    }

    // Mint the NodeAttestation and persist it. The store's index notifier
    // will publish a `SigchainBlock` event so our own watcher updates trust
    // state, and the post-create gossip bridge announces the CID to peers.
    use ed25519_dalek::Signer;
    let mut node_att = memvault_auth::NodeAttestation {
        cluster_id: memvault_core::ClusterId(join_config.cluster_id),
        member: memvault_core::PeerId(claimed.to_vec()),
        role: token.role,
        not_after_ns: u64::MAX,
        issued_via: memvault_auth::AttestationOrigin::Direct,
        signature: [0u8; 64],
    };
    let signing_bytes = match node_att.signing_bytes() {
        Ok(b) => b,
        Err(_) => return refuse(JoinRefuseReason::TokenInvalidSignature),
    };
    node_att.signature = admin_sk.sign(&signing_bytes).to_bytes();

    let att_bytes = match serde_ipld_dagcbor::to_vec(&node_att) {
        Ok(b) => b,
        Err(_) => return refuse(JoinRefuseReason::TokenInvalidSignature),
    };
    let cid = memvault_core::cid_from_bytes(&att_bytes);
    let cid_bytes = cid.to_bytes();
    let meta = memvault_store::EnvelopeMeta {
        author: claimed.to_vec(),
        tags: vec![("sigchain".to_string(), "node_att".to_string())],
        wall_ns: now_ns,
        cluster_id: Some(join_config.cluster_id.to_vec()),
        ..Default::default()
    };
    if store.insert_envelope(&cid_bytes, &att_bytes, &meta).is_err() {
        return refuse(JoinRefuseReason::TokenInvalidSignature);
    }

    tracing::info!(%peer, "minted NodeAttestation via /join/1.0");
    JoinResponse {
        version: 1,
        result: JoinResult::Success {
            attestation_block: att_bytes,
            enrollment_block: None,
        },
    }
}

fn refuse(reason: JoinRefuseReason) -> JoinResponse {
    JoinResponse {
        version: 1,
        result: JoinResult::Refuse {
            reason,
            try_peers: vec![],
        },
    }
}

fn peer_id_matches_pubkey(peer: libp2p::PeerId, pubkey: &[u8; 32]) -> bool {
    let ed_pk = match libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let pk: libp2p::identity::PublicKey = ed_pk.into();
    pk.to_peer_id() == peer
}

/// Returns `true` if the response was a successful node attestation that
/// we persisted; `false` for refuse, decode failures, or any other case.
fn handle_join_response(
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    response: JoinResponse,
) -> bool {
    match response.result {
        JoinResult::Success {
            attestation_block, ..
        } => {
            // Store the block + reindex; the index notifier fires the
            // SigchainBlock event so the watcher promotes us from
            // PreGenesis to Attested.
            let cid = memvault_core::cid_from_bytes(&attestation_block);
            let cid_bytes = cid.to_bytes();
            if let Err(e) = store.put_block(&cid_bytes, &attestation_block) {
                tracing::warn!(%peer, %e, "failed to store join attestation");
                return false;
            }
            if let Err(e) = store.reindex_block(&cid_bytes, &attestation_block) {
                tracing::warn!(%peer, %e, "failed to reindex join attestation");
                return false;
            }
            tracing::info!(%peer, "received node attestation via /join/1.0");
            true
        }
        JoinResult::Refuse { reason, .. } => {
            tracing::debug!(%peer, ?reason, "join refused");
            false
        }
    }
}
