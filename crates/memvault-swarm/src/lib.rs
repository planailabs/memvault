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
    /// Cluster admin VERIFYING key, from the pinned `genesis` in the
    /// keystore. Used by the sync receiver to
    /// signature-verify incoming `NodeAttestation` blocks BEFORE they
    /// land in the store — sync is otherwise a wide-open block ingress
    /// path and an unsigned-or-foreign-admin attestation would corrupt
    /// trust on the receiver.
    pub pinned_admin_pubkey: Option<[u8; 32]>,
    /// Cluster ID — bound into NodeAttestations we mint as admin.
    pub cluster_id: [u8; 32],
    /// Optional admin key this node wants admitted as a co-equal cluster
    /// admin when it joins. When set (and the redeemed token allows it),
    /// the `JoinRequest` carries this key's pubkey + a fresh POP, and a
    /// successful join returns + stores the `AdminKeyAdmission`. `None`
    /// for a normal (non-admin) join.
    pub admit_admin_key: Option<ed25519_dalek::SigningKey>,
    /// Optional token keystore (shared with the daemon's LocalClient). When
    /// present, token revocation and `max_uses` consumption for incoming
    /// libp2p joins are checked/recorded here instead of redb — keeping the
    /// libp2p join path consistent with HTTP enrollment now that tokens live
    /// off redb. `None` falls back to the redb tables.
    pub keystore: Option<std::sync::Arc<memvault_keystore::KeyStore>>,
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
    // Retry timer for /join/1.0 — re-broadcast the JoinRequest while
    // we still hold a pending token. Covers transient request-response
    // failures (admin briefly offline, codec retries, etc.) without
    // requiring a peer reconnect.
    let mut join_retry_timer = tokio::time::interval(Duration::from_secs(15));
    join_retry_timer.tick().await; // skip immediate fire
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
                            send_join_request(swarm, peer_id, token, &join_config);
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
                        serve_block_request(swarm, &store, peer, channel, request, &config.cluster_id, &peer_clusters, &join_config);
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
                        handle_block_response(swarm, &store, peer, response, &join_config);
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
                        if handle_join_response(&store, peer, response, &join_config) {
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

            // ── /join/1.0 retry while a token is pending ──
            // Rebroadcasts the JoinRequest to every connected peer until
            // one returns Success and clears the pending token. Covers
            // transient drops without waiting for peer reconnect.
            _ = join_retry_timer.tick() => {
                if let Some(token) = join_config.pending_token.clone() {
                    let peers: Vec<_> = synced_peers.iter().copied().collect();
                    if !peers.is_empty() {
                        tracing::debug!(
                            peers = peers.len(),
                            "retrying /join/1.0 (still pending)"
                        );
                        for peer_id in peers {
                            send_join_request(swarm, peer_id, &token, &join_config);
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
    join_config: &JoinConfig,
) {
    // Refuse to serve blocks to peers that aren't an attested cluster
    // node. We pull the trusted-node PeerId set from sigchain blocks
    // each call — cheap relative to network IO, and avoids holding a
    // shared trust handle in the swarm. Pre-genesis daemons (no pinned
    // admin) skip the check.
    if join_config.pinned_admin_pubkey.is_some()
        && !peer_is_trusted_node(store, &peer, join_config)
    {
        tracing::warn!(
            %peer,
            "refusing to serve blocks: peer is not an attested cluster node"
        );
        let _ = swarm
            .behaviour_mut()
            .block_exchange
            .send_response(channel, BlockResponse { blocks: vec![] });
        return;
    }

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
/// Decide how a synced block should be persisted. Sigchain blocks are
/// detected by their CBOR shape and signature-verified before storage;
/// invalid attestations / revocations are dropped at sync ingress so
/// they never pollute trust state. Non-sigchain blocks pass through.
enum SyncDisposition {
    /// Drop the block — signature invalid, cluster mismatch, or unknown
    /// admin. Better to fail closed than to store a forgery.
    Drop,
    /// Store as opaque block (existing put_block + reindex_block path).
    AsIs,
    /// Store as a sigchain block with the given envelope tags. Tags are
    /// what `reindex_block` would assign if it could parse the CBOR
    /// shape — we set them explicitly here so the receiver's sigchain
    /// index + watcher see the block.
    AsSigchain(memvault_store::EnvelopeMeta),
}

/// Does this libp2p peer correspond to a node currently attested by
/// the cluster admin?
///
/// Walks the local NodeAttestation blocks (`sigchain/node_att` tag),
/// verifies each against the pinned admin pubkey, derives the libp2p
/// PeerId from the attested ed25519 pubkey, and compares. Returns true
/// on first match. Cheap when the cluster is small; cache later if it
/// matters.
fn peer_is_trusted_node(
    store: &MemvaultStore,
    peer: &libp2p::PeerId,
    join_config: &JoinConfig,
) -> bool {
    let Some(admin_pk) = join_config.pinned_admin_pubkey else {
        return false;
    };
    let Ok(admin_vk) = ed25519_dalek::VerifyingKey::from_bytes(&admin_pk) else {
        return false;
    };

    let cids = match store.query_by_tag("sigchain", "node_att", 0, 1024) {
        Ok(c) => c,
        Err(_) => return false,
    };

    for cid in cids {
        let Ok(Some(bytes)) = store.get_block(&cid) else {
            continue;
        };
        let Ok(att) =
            serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&bytes)
        else {
            continue;
        };
        if att.cluster_id.0 != join_config.cluster_id {
            continue;
        }
        if att.verify_signature(&admin_vk).is_err() {
            continue;
        }
        if att.member.0.len() != 32 {
            continue;
        }
        let mut pkbytes = [0u8; 32];
        pkbytes.copy_from_slice(&att.member.0);
        let Ok(ed_pk) = libp2p::identity::ed25519::PublicKey::try_from_bytes(&pkbytes) else {
            continue;
        };
        let candidate: libp2p::PeerId =
            libp2p::identity::PublicKey::from(ed_pk).to_peer_id();
        if &candidate == peer {
            return true;
        }
    }
    false
}

/// Outcome of validating a candidate sigchain block from a sync ingress.
/// Used internally by [`vet_sync_block`] to compress the per-type
/// validation arms into a single dispatcher.
enum SyncSigchainVerdict {
    /// Bytes don't look like any known sigchain type — caller treats
    /// the block as a regular envelope and lets the receiver's
    /// existing indexer handle it.
    NotSigchain,
    /// Bytes parsed as a known sigchain type but the signature didn't
    /// verify (or admin/cluster mismatch). Reason string is logged at
    /// the call site for debugging.
    Drop {
        reason: &'static str,
    },
    /// Sigchain block validated successfully. Caller wraps `label`
    /// + `signer_pubkey` into the canonical `AsSigchain` meta.
    Accept {
        label: &'static str,
        signer_pubkey: Vec<u8>,
    },
}

/// Single dispatcher for all sigchain block types arriving via sync.
/// Each arm: parse → verify signature → return label + signer pubkey,
/// or Drop with a reason. Centralises the per-type validation that
/// used to live as four near-duplicate arms inside `vet_sync_block`.
fn validate_sigchain_for_sync(bytes: &[u8], join_config: &JoinConfig) -> SyncSigchainVerdict {
    let cluster_id = join_config.cluster_id;

    // AdminKeyAdmission: verify the admitting self-signature + the
    // incoming POP here. The authoritative "admitting key was a valid
    // admin at admission time" check is deferred to
    // `rebuild_admin_key_state` (same deferral pattern as AgentAttestation
    // trust-of-node) — a block that passes here but fails the chain
    // validation there simply has no effect on the admin set.
    if let Ok(adm) = serde_ipld_dagcbor::from_slice::<memvault_auth::AdminKeyAdmission>(bytes) {
        if adm.cluster_id.0 == cluster_id && adm.new_pubkey.iter().any(|&b| b != 0) {
            if adm.verify().is_err() {
                return SyncSigchainVerdict::Drop {
                    reason: "admin_admission: bad admitting signature or POP",
                };
            }
            return SyncSigchainVerdict::Accept {
                label: "admin_admission",
                signer_pubkey: adm.admitting_pubkey.to_vec(),
            };
        }
    }

    // AdminKeyRetirement: verify the retiring self-signature here; the
    // "retiring key was a valid admin / no-lockout" checks are deferred
    // to `rebuild_admin_key_state`.
    if let Ok(ret) = serde_ipld_dagcbor::from_slice::<memvault_auth::AdminKeyRetirement>(bytes) {
        if ret.cluster_id.0 == cluster_id && ret.retired_pubkey.iter().any(|&b| b != 0) {
            if ret.verify_retiring_signature().is_err() {
                return SyncSigchainVerdict::Drop {
                    reason: "admin_retirement: bad retiring signature",
                };
            }
            return SyncSigchainVerdict::Accept {
                label: "admin_retirement",
                signer_pubkey: ret.retiring_pubkey.to_vec(),
            };
        }
    }

    // NodeAttestation: admin-signed. Under multi-admin the signer may be
    // an admitted admin the swarm can't see (it only pins the anchor), and
    // sync may deliver the attestation before the admission that
    // authorises its signer. So we fast-path on the anchor signature but
    // otherwise DEFER: accept the well-formed, cluster-matching block and
    // let the receiver's `scan_trusted_nodes` (which verifies against the
    // full, eventually-complete admin set) decide trust. A bogus
    // attestation that never verifies there simply never enters
    // node_trust — no auth bypass, same deferral as AgentAttestation.
    if let Ok(att) = serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(bytes) {
        if att.cluster_id.0 == cluster_id && !att.member.0.is_empty() {
            return SyncSigchainVerdict::Accept {
                label: "node_att",
                signer_pubkey: att.member.0.clone(),
            };
        }
    }

    // AgentAttestation: node-signed; chain-up-to-admin check happens
    // later in `scan_trusted_agents`.
    if let Ok(att) = serde_ipld_dagcbor::from_slice::<memvault_auth::AgentAttestation>(bytes) {
        if att.verify_signature().is_err() {
            return SyncSigchainVerdict::Drop {
                reason: "agent_att: bad node signature",
            };
        }
        return SyncSigchainVerdict::Accept {
            label: "agent_att",
            signer_pubkey: att.node_pubkey.to_vec(),
        };
    }

    // AgentRevocation: node-signed; trust-of-node check is deferred.
    if let Ok(rev) = serde_ipld_dagcbor::from_slice::<memvault_auth::AgentRevocation>(bytes) {
        if rev.verify_signature().is_err() {
            return SyncSigchainVerdict::Drop {
                reason: "agent_rev: bad node signature",
            };
        }
        return SyncSigchainVerdict::Accept {
            label: "agent_rev",
            signer_pubkey: rev.node_pubkey.to_vec(),
        };
    }

    // NodeRevocation: admin-signed. Verify the self-signature against the
    // embedded admin_pubkey (cheap garbage filter — the signer set
    // admin_pubkey and signed it). The authoritative "admin_pubkey is a
    // known cluster admin" check is deferred to the receiver's
    // `scan_revocations` (full admin set), so an admitted admin's
    // revocation is honoured even though the swarm only pins the anchor.
    if let Ok(rev) = serde_ipld_dagcbor::from_slice::<memvault_auth::NodeRevocation>(bytes) {
        if rev.node_pubkey.iter().any(|&b| b != 0) {
            if rev.verify_signature().is_err() {
                return SyncSigchainVerdict::Drop {
                    reason: "node_rev: bad self-signature",
                };
            }
            return SyncSigchainVerdict::Accept {
                label: "node_rev",
                signer_pubkey: rev.admin_pubkey.to_vec(),
            };
        }
    }

    // GrantRevocation: admin-signed. Verify the self-signature against the
    // embedded admin_pubkey; defer the "admin_pubkey is a known cluster
    // admin" check to the receiver's grant-revocation scan/watcher.
    if let Ok(rev) = serde_ipld_dagcbor::from_slice::<memvault_auth::GrantRevocation>(bytes) {
        if rev.admin_pubkey.iter().any(|&b| b != 0) {
            if rev.verify_signature().is_err() {
                return SyncSigchainVerdict::Drop {
                    reason: "grant_revocation: bad self-signature",
                };
            }
            return SyncSigchainVerdict::Accept {
                label: "grant_revocation",
                signer_pubkey: rev.admin_pubkey.to_vec(),
            };
        }
    }

    SyncSigchainVerdict::NotSigchain
}

fn vet_sync_block(
    bytes: &[u8],
    join_config: &JoinConfig,
    author_peer_pubkey: Option<[u8; 32]>,
) -> SyncDisposition {
    match validate_sigchain_for_sync(bytes, join_config) {
        SyncSigchainVerdict::NotSigchain => SyncDisposition::AsIs,
        SyncSigchainVerdict::Drop { reason } => {
            tracing::warn!(reason, "dropped sync'd sigchain block");
            SyncDisposition::Drop
        }
        SyncSigchainVerdict::Accept {
            label,
            signer_pubkey,
        } => {
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let author = author_peer_pubkey
                .map(|p| p.to_vec())
                .unwrap_or(signer_pubkey);
            SyncDisposition::AsSigchain(memvault_store::EnvelopeMeta {
                author,
                tags: vec![("sigchain".to_string(), label.to_string())],
                wall_ns: now_ns,
                cluster_id: Some(join_config.cluster_id.to_vec()),
                ..Default::default()
            })
        }
    }
}

fn handle_block_response(
    swarm: &mut libp2p::Swarm<StandaloneMemvaultBehaviour>,
    store: &MemvaultStore,
    peer: libp2p::PeerId,
    response: BlockResponse,
    join_config: &JoinConfig,
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
            // Content-addressing integrity: the bytes MUST hash to the
            // claimed CID. Without this a peer could serve content Y under a
            // CID X it isn't (substitution / id-reuse) — poisoning the store
            // so a later lookup of X returns the wrong content, or shadowing
            // a not-yet-held legitimate block. Use `verify_cid`, which hashes
            // with the CID's *own* algorithm + verifies the digest — so it
            // accepts both DAG-CBOR/Blake3 envelopes and raw/SHA2-256
            // attachment chunks (recomputing via `cid_from_bytes` assumed one
            // fixed codec+hash and dropped every attachment chunk).
            if !matches!(memvault_core::verify_cid(&entry.cid, &entry.data), Ok(true)) {
                tracing::warn!(
                    cid = %hex::encode(&entry.cid),
                    "dropping synced block: bytes do not hash to the claimed CID"
                );
                continue;
            }
            // Gate sigchain block ingress: a synced NodeAttestation must
            // verify against the pinned admin pubkey before being stored.
            // Other shapes pass through to the existing path.
            match vet_sync_block(&entry.data, join_config, None) {
                SyncDisposition::Drop => continue,
                SyncDisposition::AsSigchain(meta) => {
                    if let Err(e) = store.insert_envelope(&entry.cid, &entry.data, &meta) {
                        tracing::warn!(
                            cid = %hex::encode(&entry.cid), %e,
                            "failed to insert synced sigchain block"
                        );
                        continue;
                    }
                }
                SyncDisposition::AsIs => {
                    if let Err(e) = store.put_block(&entry.cid, &entry.data) {
                        tracing::warn!(cid = %hex::encode(&entry.cid), %e, "failed to store synced block");
                        continue;
                    }
                    let _ = store.reindex_block(&entry.cid, &entry.data);
                    let _ = store.reindex_bucket_decl(&entry.cid, &entry.data);
                }
            }
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
    // Try the canonical envelope view first — handles both legacy
    // raw-JSON envelopes and Signed<T> payload-nested attachments.
    if let Some(view) = memvault_store::EnvelopeView::parse(block_data) {
        let mut deps = Vec::new();

        // Attachment envelope → manifest_cid (top-level or in payload).
        if let Some(mcid) = view.get_as::<Vec<u8>>("manifest_cid") {
            deps.push(mcid);
        }

        // AttachmentManifest → content_root (UnixFS DAG root CID).
        if let Some(root) = view.get_as::<Vec<u8>>("content_root") {
            deps.push(root);
        }

        // Causal links — always at the envelope level, not nested.
        if let Some(arr) = view.field("causal").and_then(|v| v.as_array()) {
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
    join_config: &JoinConfig,
) {
    // If this node wants to be admitted as an admin, attach its admin
    // pubkey + a fresh POP (valid for 1h). The admin only honours it if
    // the token allows it.
    let (admin_pubkey, admin_pop, admin_pop_not_after_ns) = match &join_config.admit_admin_key {
        Some(sk) => {
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let pop_not_after = now_ns.saturating_add(3600 * 1_000_000_000);
            let cluster = memvault_core::ClusterId(join_config.cluster_id);
            let pop = memvault_auth::sign_admin_pop(sk, &cluster, pop_not_after);
            (
                Some(sk.verifying_key().to_bytes().to_vec()),
                Some(pop.to_vec()),
                Some(pop_not_after),
            )
        }
        None => (None, None, None),
    };
    let req = JoinRequest {
        version: 1,
        token_block: token.as_bytes().to_vec(),
        peer_id: join_config.node_pubkey.to_vec(),
        requested_ttl: None,
        agent_id: None,
        public_key: None,
        admin_pubkey,
        admin_pop,
        admin_pop_not_after_ns,
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

    // The token's CID — keys the CONSUMED_TOKENS / REVOCATIONS tables.
    let token_cbor = match serde_ipld_dagcbor::to_vec(&token) {
        Ok(b) => b,
        Err(_) => return refuse(JoinRefuseReason::TokenInvalidSignature),
    };
    let token_cid = memvault_core::cid_from_bytes(&token_cbor).to_bytes();

    // Token revocation: keystore first (where revocations now live), then
    // the legacy redb table.
    let revoked = join_config
        .keystore
        .as_ref()
        .map(|ks| ks.contains(format!("tokrevoked:{}", hex::encode(&token_cid)).as_bytes()))
        .unwrap_or(false)
        || store.is_revoked(&token_cid).unwrap_or(false);
    if revoked {
        return refuse(JoinRefuseReason::TokenRevoked);
    }

    // Build the would-be NodeAttestation. Ed25519 signing is
    // deterministic given the same admin key + same payload, so the
    // serialised attestation bytes (and hence the CID) are stable
    // across multiple JoinRequests from the same peer with the same
    // role / cluster. We use that determinism for idempotence: if the
    // block already exists in our store, this is a retry — return the
    // existing block without consuming another use of the token.
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

    // Hard idempotence: BLOCKS-table existence check. Reliable
    // regardless of BY_TAG state, race timing, or comparison gotchas.
    // The previous tag-scan check (`already_attested`) was correct in
    // theory but lost a race in practice when two JoinRequests from
    // the same peer arrived ~20ms apart (libp2p retransmit, double
    // ConnectionEstablished, etc.) — both saw "no attestation yet" if
    // the redb commit hadn't propagated to the read txn in time.
    let already_minted =
        matches!(store.get_block(&cid_bytes), Ok(Some(_)));

    if !already_minted {
        // Honour max_uses BEFORE minting so we don't over-issue. Keystore
        // first (where consumption now accrues), then redb.
        let used = match &join_config.keystore {
            Some(ks) => {
                let k = format!("tokused:{}", hex::encode(&token_cid));
                if ks.contains(k.as_bytes()) {
                    ks.get_u32(k.as_bytes())
                } else {
                    store.get_token_consumption_count(&token_cid).unwrap_or(0)
                }
            }
            None => store.get_token_consumption_count(&token_cid).unwrap_or(0),
        };
        if used >= token.max_uses {
            return refuse(JoinRefuseReason::TokenAlreadyConsumed);
        }
    }

    let meta = memvault_store::EnvelopeMeta {
        author: claimed.to_vec(),
        tags: vec![("sigchain".to_string(), "node_att".to_string())],
        wall_ns: now_ns,
        cluster_id: Some(join_config.cluster_id.to_vec()),
        ..Default::default()
    };
    // insert_envelope is idempotent on the BLOCKS-table key (same CID
    // overwrites with identical bytes) but adds a fresh BY_TAG entry
    // every call. Skip the insert entirely on a hit to keep tag
    // index clean.
    if !already_minted {
        if store.insert_envelope(&cid_bytes, &att_bytes, &meta).is_err() {
            return refuse(JoinRefuseReason::TokenInvalidSignature);
        }
    }

    // Record token consumption on first mint only. Keystore (atomic,
    // cross-process) when present, else redb.
    if !already_minted {
        match &join_config.keystore {
            Some(ks) => {
                let k = format!("tokused:{}", hex::encode(&token_cid));
                if let Err(e) = ks.fetch_add_u32(k.as_bytes(), 1) {
                    tracing::warn!(%peer, %e, "failed to record token consumption (keystore)");
                }
            }
            None => {
                if let Err(e) = store.record_token_consumption(&token_cid, &claimed, now_ns) {
                    tracing::warn!(%peer, %e, "failed to record token consumption");
                }
            }
        }
    }

    tracing::info!(%peer, "minted NodeAttestation via /join/1.0");

    // Bootstrap bundle: hand the joining peer the sigchain blocks it
    // needs to verify cluster trust before its first block-exchange
    // round (the trust gate in `serve_block_request` would otherwise
    // refuse — peer isn't attested yet from admin's POV until the
    // attestation we just minted reaches admin's trust state via the
    // sigchain notifier, and from peer's POV admin isn't attested
    // until admin's own NodeAttestation arrives). Bundling avoids the
    // chicken-and-egg without opening up unauthenticated block
    // exchange. Each block is shape-and-signature-verified at the
    // peer via `vet_sync_block`, so a malicious admin can't inject
    // arbitrary blocks here.
    let bootstrap_blocks = gather_bootstrap_blocks(store);

    // Optional admin admission: only if the token explicitly allows it AND
    // the request carries a valid proof-of-possession for the admin key it
    // wants admitted. The admission is signed by THIS admin key, published
    // as a sigchain block (so it propagates), and returned to the joiner.
    let admission_block = mint_join_admission(store, admin_sk, &token, request, now_ns);

    JoinResponse {
        version: 1,
        result: JoinResult::Success {
            attestation_block: att_bytes,
            enrollment_block: None,
            bootstrap_blocks,
            admission_block,
        },
    }
}

/// Mint + persist an `AdminKeyAdmission` for a join request, when the
/// token grants admit-as-admin and the request's POP verifies. Returns
/// the admission block bytes, or `None` if not requested / not valid.
fn mint_join_admission(
    store: &MemvaultStore,
    admin_sk: &ed25519_dalek::SigningKey,
    token: &memvault_auth::JoinToken,
    request: &JoinRequest,
    now_ns: u64,
) -> Option<Vec<u8>> {
    if !token.admit_as_admin {
        return None;
    }
    let new_pk: [u8; 32] = request.admin_pubkey.as_deref()?.try_into().ok()?;
    let pop: [u8; 64] = request.admin_pop.as_deref()?.try_into().ok()?;
    let pop_not_after_ns = request.admin_pop_not_after_ns?;
    let cluster = memvault_core::ClusterId(token.cluster_id.0);
    // POP must verify and not have expired.
    if memvault_auth::verify_admin_pop(&cluster, &new_pk, pop_not_after_ns, &pop).is_err()
        || now_ns > pop_not_after_ns
    {
        tracing::warn!("join admission: POP invalid or expired; minting node attestation only");
        return None;
    }
    let admission = memvault_auth::sign_admin_admission(
        admin_sk,
        new_pk,
        cluster,
        now_ns,
        now_ns,
        pop_not_after_ns,
        None,
        pop,
    )
    .ok()?;
    let bytes = serde_ipld_dagcbor::to_vec(&admission).ok()?;
    let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
    let meta = memvault_store::EnvelopeMeta {
        author: admin_sk.verifying_key().to_bytes().to_vec(),
        tags: vec![("sigchain".to_string(), "admin_admission".to_string())],
        wall_ns: now_ns,
        cluster_id: Some(token.cluster_id.0.to_vec()),
        ..Default::default()
    };
    let _ = store.insert_envelope(&cid, &bytes, &meta);
    tracing::info!(new_admin = %hex::encode(new_pk), "admitted admin via /join/1.0");
    Some(bytes)
}

/// Collect the sigchain blocks a joining peer needs to verify cluster
/// trust before its first block-exchange round: every NodeAttestation
/// we hold (so peer learns who else is attested) and every
/// AdminGenesis block (the cluster's pin material, in case the peer
/// wants to cross-check). Size is bounded by cluster size + 1.
fn gather_bootstrap_blocks(store: &MemvaultStore) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (kind, label) in &[
        ("sigchain", "node_att"),
        ("sigchain", "admin_genesis"),
    ] {
        if let Ok(cids) = store.query_by_tag(kind, label, 0, 1024) {
            // Tag entries may repeat the same CID (pre-fix duplicate
            // publishes); dedupe before reading.
            let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
            for cid in cids {
                if !seen.insert(cid.clone()) {
                    continue;
                }
                if let Ok(Some(bytes)) = store.get_block(&cid) {
                    out.push(bytes);
                }
            }
        }
    }
    out
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
    join_config: &JoinConfig,
) -> bool {
    match response.result {
        JoinResult::Success {
            attestation_block,
            bootstrap_blocks,
            admission_block,
            ..
        } => {
            // If admin admitted our admin key, persist the admission block
            // (vetted like any synced sigchain block — verifies the
            // admitting signature + our POP). It also propagates via sync.
            if let Some(adm) = &admission_block {
                let adm_cid = memvault_core::cid_from_bytes(adm).to_bytes();
                match vet_sync_block(adm, join_config, None) {
                    SyncDisposition::AsSigchain(meta) => {
                        if let Err(e) = store.insert_envelope(&adm_cid, adm, &meta) {
                            tracing::warn!(%peer, %e, "failed to insert admission block");
                        } else {
                            tracing::info!(%peer, "stored admin admission from /join/1.0");
                        }
                    }
                    _ => tracing::warn!(%peer, "join admission block failed vetting"),
                }
            }
            // Bootstrap bundle first: each block (admin's
            // NodeAttestation, AdminGenesis, etc.) goes through
            // vet_sync_block for signature verification and proper
            // tagging. After this, admin's identity is in our
            // sigchain index — the block-exchange gate on the peer
            // side won't refuse admin's serve_block_request once we
            // ask. And from admin's POV, the attestation it just
            // minted for us is already in admin's local sigchain, so
            // admin's peer_is_trusted_node(us) returns true.
            for boot in &bootstrap_blocks {
                let boot_cid = memvault_core::cid_from_bytes(boot).to_bytes();
                match vet_sync_block(boot, join_config, None) {
                    SyncDisposition::AsSigchain(meta) => {
                        if let Err(e) = store.insert_envelope(&boot_cid, boot, &meta) {
                            tracing::warn!(%peer, %e, "failed to insert bootstrap block");
                        }
                    }
                    SyncDisposition::Drop => {
                        tracing::warn!(
                            %peer,
                            "dropped bootstrap block: signature does not verify"
                        );
                    }
                    SyncDisposition::AsIs => {
                        tracing::debug!(
                            %peer,
                            "ignoring non-sigchain bootstrap block"
                        );
                    }
                }
            }

            // Now the main attestation_block (peer's own
            // NodeAttestation). Same shape: vet + tag.
            //
            // Route through vet_sync_block so the NodeAttestation is
            // signature-verified against the pinned admin pubkey AND
            // tagged `sigchain/node_att`. Going through put_block +
            // reindex_block here would store untagged bytes — the
            // receiver's sigchain index would never see the entry and
            // the watcher would never promote us out of PreGenesis.
            let cid = memvault_core::cid_from_bytes(&attestation_block);
            let cid_bytes = cid.to_bytes();
            match vet_sync_block(&attestation_block, join_config, None) {
                SyncDisposition::AsSigchain(meta) => {
                    if let Err(e) = store.insert_envelope(&cid_bytes, &attestation_block, &meta) {
                        tracing::warn!(%peer, %e, "failed to insert join attestation");
                        return false;
                    }
                    tracing::info!(%peer, "received node attestation via /join/1.0");
                    true
                }
                SyncDisposition::Drop => {
                    tracing::warn!(
                        %peer,
                        "dropped /join/1.0 response: attestation does not verify \
                         against pinned admin pubkey"
                    );
                    false
                }
                SyncDisposition::AsIs => {
                    // Shouldn't happen — admin minted a NodeAttestation,
                    // it has the right shape. Defensive fallback.
                    tracing::warn!(
                        %peer,
                        "join response was not a recognized NodeAttestation; ignoring"
                    );
                    false
                }
            }
        }
        JoinResult::Refuse { reason, .. } => {
            tracing::debug!(%peer, ?reason, "join refused");
            false
        }
    }
}
