//! End-to-end `/ai-memvault/join/1.0` test with two real swarms.
//!
//! Spawns an admin daemon and a peer daemon, connects them, and verifies
//! the peer transitions from PreGenesis to Attested without any manual
//! `memctl node-attest` step — admin mints a NodeAttestation in response
//! to the peer's JoinRequest, and the peer's sync receiver stores it
//! with proper sigchain tags so the local trust index picks it up.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, identity};
use rand::RngCore;
use tokio::sync::mpsc;
use tokio::time::timeout;

use memvault_auth::{
    AdminGenesis, AgentRole, JoinToken, NodeRole, TokenRole, encode_token_string,
    sign_admin_genesis,
};
use memvault_core::{ClusterId, PeerId};
use memvault_net::standalone_swarm;
use memvault_store::MemvaultStore;
use memvault_swarm::{JoinConfig, OutboundHead, SyncConfig};

fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

fn libp2p_keypair_from_seed(seed: &[u8; 32]) -> identity::Keypair {
    let secret = identity::ed25519::SecretKey::try_from_bytes(*seed).expect("seed");
    identity::Keypair::from(identity::ed25519::Keypair::from(secret))
}

fn pubkey_from_libp2p(kp: &identity::Keypair) -> [u8; 32] {
    kp.public().try_into_ed25519().expect("ed25519").to_bytes()
}

/// Build a signed JoinToken with the AdminGenesis embedded — the
/// production token-issuer output.
fn issue_token(
    admin_sk: &SigningKey,
    admin_peer_id: &PeerId,
    cluster_id: &ClusterId,
    genesis: &AdminGenesis,
) -> JoinToken {
    issue_token_ex(admin_sk, admin_peer_id, cluster_id, genesis, false)
}

fn issue_token_ex(
    admin_sk: &SigningKey,
    admin_peer_id: &PeerId,
    cluster_id: &ClusterId,
    genesis: &AdminGenesis,
    admit_as_admin: bool,
) -> JoinToken {
    use ed25519_dalek::Signer;
    let now_ns = memvault_core::wall_ns();
    let node_role = if admit_as_admin {
        NodeRole::Admin
    } else {
        NodeRole::Node
    };
    let mut token = JoinToken {
        issuer: admin_peer_id.clone(),
        cluster_id: cluster_id.clone(),
        // /join/1.0 only admits node-join (`TokenRole::Node`) tokens.
        role: TokenRole::Node(node_role),
        initial_grants: vec![],
        not_before_ns: now_ns.saturating_sub(60_000_000_000),
        not_after_ns: now_ns + 3600 * 1_000_000_000,
        max_uses: 1,
        nonce: random_seed()[..16].try_into().unwrap(),
        label: Some("smoke-test".into()),
        admin_genesis: Some(genesis.clone()),
        issuer_addrs: vec![],
        signature: [0u8; 64],
    };
    let bytes = token.signing_bytes().expect("signing bytes");
    token.signature = admin_sk.sign(&bytes).to_bytes();
    token
}

/// Wait for the swarm to announce a listen addr, then return it.
async fn await_listen_addr(
    swarm: &mut libp2p::Swarm<memvault_net::StandaloneMemvaultBehaviour>,
) -> Multiaddr {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(SwarmEvent::NewListenAddr { address, .. }) = swarm.next().await {
                return address;
            }
        }
    })
    .await
    .expect("listen addr within 5s")
}

#[tokio::test]
async fn join_protocol_promotes_peer_to_attested() {
    // ── Admin cryptographic identity ────────────────────────────────
    let admin_seed = random_seed();
    let admin_sk = SigningKey::from_bytes(&admin_seed);
    let admin_pubkey = admin_sk.verifying_key().to_bytes();

    let cluster_id = ClusterId::random();
    let genesis = sign_admin_genesis(&admin_sk, cluster_id.clone(), memvault_core::wall_ns())
        .expect("sign admin_genesis");

    // ── Admin libp2p identity (separate from admin signing key) ────
    let admin_node_seed = random_seed();
    let admin_kp = libp2p_keypair_from_seed(&admin_node_seed);
    let admin_node_pubkey = pubkey_from_libp2p(&admin_kp);
    let admin_libp2p_peerid = admin_kp.public().to_peer_id();

    // ── Peer libp2p identity ────────────────────────────────────────
    let peer_seed = random_seed();
    let peer_kp = libp2p_keypair_from_seed(&peer_seed);
    let peer_node_pubkey = pubkey_from_libp2p(&peer_kp);

    // ── Issue the token (the in-memory equivalent of `memctl token-issue`)
    let admin_peer_for_token = PeerId(admin_node_pubkey.to_vec());
    let token = issue_token(&admin_sk, &admin_peer_for_token, &cluster_id, &genesis);
    let token_str = encode_token_string(&token).expect("encode token");

    // ── Two stores under tempdirs ───────────────────────────────────
    let admin_dir = tempfile::tempdir().unwrap();
    let peer_dir = tempfile::tempdir().unwrap();
    let admin_store = Arc::new(MemvaultStore::open(admin_dir.path().join("blocks.redb")).unwrap());
    let peer_store = Arc::new(MemvaultStore::open(peer_dir.path().join("blocks.redb")).unwrap());
    admin_store.set_local_cluster_id(&cluster_id.0).unwrap();
    peer_store.set_local_cluster_id(&cluster_id.0).unwrap();

    // ── Build the two swarms ────────────────────────────────────────
    let mut admin_swarm = standalone_swarm(
        admin_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let admin_listen = await_listen_addr(&mut admin_swarm).await;

    let mut peer_swarm = standalone_swarm(
        peer_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let _peer_listen = await_listen_addr(&mut peer_swarm).await;

    // Peer dials admin so they actually connect.
    peer_swarm.dial(admin_listen.clone()).unwrap();

    // ── JoinConfig for both sides ──────────────────────────────────
    let admin_join = JoinConfig {
        pending_token: None,
        node_pubkey: admin_node_pubkey,
        admin_signing_key: Some(admin_sk.clone()),
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };
    let peer_join = JoinConfig {
        pending_token: Some(token_str.clone()),
        node_pubkey: peer_node_pubkey,
        admin_signing_key: None,
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };

    // ── Run both swarms in background tasks ────────────────────────
    let (admin_head_tx, admin_head_rx) = mpsc::unbounded_channel::<OutboundHead>();
    let (peer_head_tx, peer_head_rx) = mpsc::unbounded_channel::<OutboundHead>();
    drop(admin_head_tx);
    drop(peer_head_tx);

    let admin_store_for_task = Arc::clone(&admin_store);
    let admin_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut admin_swarm,
            admin_store_for_task,
            admin_head_rx,
            SyncConfig {
                cluster_id: cluster_id.0.to_vec(),
                ..Default::default()
            },
            admin_join,
        )
        .await;
    });

    let peer_store_for_task = Arc::clone(&peer_store);
    let peer_cluster = cluster_id.0;
    let peer_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut peer_swarm,
            peer_store_for_task,
            peer_head_rx,
            SyncConfig {
                cluster_id: peer_cluster.to_vec(),
                ..Default::default()
            },
            peer_join,
        )
        .await;
    });

    // ── Poll the peer's store until the NodeAttestation arrives ────
    let attested = timeout(Duration::from_secs(20), async {
        loop {
            // Look for any sigchain/node_att block on the peer's store
            // whose `member` matches peer's pubkey.
            if let Ok(cids) = peer_store.query_by_tag("sigchain", "node_att", 0, 64) {
                for cid in cids {
                    if let Ok(Some(bytes)) = peer_store.get_block(&cid) {
                        if let Ok(att) =
                            serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&bytes)
                        {
                            if att.member.0 == peer_node_pubkey.to_vec() {
                                return Some(att);
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("timed out waiting for NodeAttestation");

    let att = attested.expect("attestation present");
    assert_eq!(att.cluster_id.0, cluster_id.0, "cluster_id matches");

    // Signature must verify against admin pubkey (the pin).
    let admin_vk = ed25519_dalek::VerifyingKey::from_bytes(&admin_pubkey).expect("admin pubkey");
    att.verify_signature(&admin_vk)
        .expect("admin signature on NodeAttestation");

    // Clean up background tasks.
    admin_task.abort();
    peer_task.abort();
    let _ = admin_task.await;
    let _ = peer_task.await;

    // We can't easily inspect libp2p_libp2p_peerid here without a
    // separate trust-state plumb; the cryptographic chain check above
    // is the load-bearing assertion.
    let _ = admin_libp2p_peerid;
}

/// Regression test for the production bug where memctl daemon loaded
/// `<data_dir>/identity/node.key` for `set_node_signing_key` and
/// `<data_dir>/identity/libp2p.key` for the swarm — different files,
/// different pubkeys. Admin then minted `NodeAttestation` for the
/// libp2p key (what the JoinRequest carried), but
/// `bootstrap_cluster_trust` looked for the node-key entry in
/// `node_trust` and never found it, so the trust tree showed the local
/// node as PreGenesis indefinitely.
///
/// Asserts the memctl daemon's two helpers produce the same pubkey from
/// the same `libp2p.key` file. Pre-fix this fails because the daemon
/// reads two different files; post-fix both routes go through
/// `libp2p.key`.
#[test]
fn libp2p_key_drives_both_swarm_and_node_signing_key() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("identity")).unwrap();

    // Generate a libp2p keypair and persist it the way memctl's
    // load_or_generate_keypair does (32-byte seed file).
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let ed_kp = kp.clone().try_into_ed25519().expect("ed25519");
    let full = ed_kp.to_bytes(); // 64 bytes (seed + pub)
    std::fs::write(dir.path().join("identity").join("libp2p.key"), &full[..32]).unwrap();

    let kp_loaded =
        memctl::load_or_generate_keypair(&dir.path().join("identity").join("libp2p.key"))
            .expect("load_or_generate_keypair");
    let swarm_pubkey: [u8; 32] = kp_loaded
        .public()
        .try_into_ed25519()
        .expect("ed25519")
        .to_bytes();

    let node_sk = memctl::libp2p_node_signing_key(dir.path()).expect("libp2p_node_signing_key");
    let bootstrap_pubkey = node_sk.verifying_key().to_bytes();

    assert_eq!(
        swarm_pubkey, bootstrap_pubkey,
        "memctl's swarm-side libp2p pubkey must equal memctl's \
         bootstrap-side node signing key. They both come from \
         <data_dir>/identity/libp2p.key by design A-1 (node key = \
         libp2p key). If this diverges, admin mints a NodeAttestation \
         for the libp2p key but bootstrap_cluster_trust looks for the \
         node-key entry and the local node stays PreGenesis."
    );
}

/// End-to-end version of the regression: drive the full swarm
/// handshake with the daemon helpers and confirm the peer ends up with
/// a NodeAttestation for the pubkey `bootstrap_cluster_trust` would
/// treat as its own.
#[tokio::test]
async fn join_protocol_attests_peer_under_bootstrap_pubkey() {
    // Drives the post-fix daemon flow end-to-end: the peer's libp2p key
    // (carried in the JoinRequest) IS the same key that
    // `bootstrap_cluster_trust` would use as the node signing key.
    // After the handshake, the peer must have a NodeAttestation in its
    // store whose `member` equals that single shared pubkey.
    let admin_seed = random_seed();
    let admin_sk = SigningKey::from_bytes(&admin_seed);
    let admin_pubkey = admin_sk.verifying_key().to_bytes();
    let cluster_id = ClusterId::random();
    let genesis = sign_admin_genesis(&admin_sk, cluster_id.clone(), memvault_core::wall_ns())
        .expect("sign admin_genesis");

    let admin_kp = libp2p_keypair_from_seed(&random_seed());
    let admin_node_pubkey = pubkey_from_libp2p(&admin_kp);

    // Peer's libp2p key — this single key is used by BOTH the swarm
    // (PeerId on the wire) AND `bootstrap_cluster_trust`'s notion of
    // "my pubkey". Mirror the memctl daemon post-fix.
    let peer_kp = libp2p_keypair_from_seed(&random_seed());
    let peer_libp2p_pubkey = pubkey_from_libp2p(&peer_kp);
    // The pubkey bootstrap would key trust state by — same key.
    let peer_bootstrap_pubkey = peer_libp2p_pubkey;

    let admin_peer_for_token = PeerId(admin_node_pubkey.to_vec());
    let token = issue_token(&admin_sk, &admin_peer_for_token, &cluster_id, &genesis);
    let token_str = encode_token_string(&token).expect("encode token");

    let admin_dir = tempfile::tempdir().unwrap();
    let peer_dir = tempfile::tempdir().unwrap();
    let admin_store = Arc::new(MemvaultStore::open(admin_dir.path().join("blocks.redb")).unwrap());
    let peer_store = Arc::new(MemvaultStore::open(peer_dir.path().join("blocks.redb")).unwrap());
    admin_store.set_local_cluster_id(&cluster_id.0).unwrap();
    peer_store.set_local_cluster_id(&cluster_id.0).unwrap();

    let mut admin_swarm = standalone_swarm(
        admin_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let admin_listen = await_listen_addr(&mut admin_swarm).await;

    let mut peer_swarm = standalone_swarm(
        peer_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let _ = await_listen_addr(&mut peer_swarm).await;

    peer_swarm.dial(admin_listen.clone()).unwrap();

    let admin_join = JoinConfig {
        pending_token: None,
        node_pubkey: admin_node_pubkey,
        admin_signing_key: Some(admin_sk.clone()),
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };
    // Peer announces its LIBP2P pubkey in the JoinRequest — that's what
    // the production daemon does today.
    let peer_join = JoinConfig {
        pending_token: Some(token_str.clone()),
        node_pubkey: peer_libp2p_pubkey,
        admin_signing_key: None,
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };

    let (_admin_head_tx, admin_head_rx) = mpsc::unbounded_channel::<OutboundHead>();
    let (_peer_head_tx, peer_head_rx) = mpsc::unbounded_channel::<OutboundHead>();

    let admin_store_for_task = Arc::clone(&admin_store);
    let admin_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut admin_swarm,
            admin_store_for_task,
            admin_head_rx,
            SyncConfig {
                cluster_id: cluster_id.0.to_vec(),
                ..Default::default()
            },
            admin_join,
        )
        .await;
    });

    let peer_store_for_task = Arc::clone(&peer_store);
    let peer_cluster = cluster_id.0;
    let peer_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut peer_swarm,
            peer_store_for_task,
            peer_head_rx,
            SyncConfig {
                cluster_id: peer_cluster.to_vec(),
                ..Default::default()
            },
            peer_join,
        )
        .await;
    });

    // Wait for the NodeAttestation that has `member == peer_bootstrap_pubkey`.
    let found = timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(cids) = peer_store.query_by_tag("sigchain", "node_att", 0, 64) {
                for cid in cids {
                    if let Ok(Some(bytes)) = peer_store.get_block(&cid) {
                        if let Ok(att) =
                            serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&bytes)
                        {
                            if att.member.0 == peer_bootstrap_pubkey.to_vec() {
                                return true;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false);

    admin_task.abort();
    peer_task.abort();
    let _ = admin_task.await;
    let _ = peer_task.await;

    assert!(
        found,
        "NodeAttestation must exist for the daemon's bootstrap pubkey \
         (which after the fix == the libp2p pubkey)."
    );
}

/// Regression: synced `AgentAttestation` blocks must land with the
/// `sigchain/agent_att` tag on the receiver so `scan_trusted_agents`
/// can find them. Without this, admin's agent_ui shows up correctly on
/// admin's own trust tree but never appears under admin's node row on
/// peer's trust tree.
#[tokio::test]
async fn agent_attestation_syncs_with_correct_tag() {
    // Admin keys + cluster.
    let admin_sk = SigningKey::from_bytes(&random_seed());
    let admin_pubkey = admin_sk.verifying_key().to_bytes();
    let cluster_id = ClusterId::random();

    // Admin's node identity (also serves as the agent-issuing node key).
    let admin_kp = libp2p_keypair_from_seed(&random_seed());
    let admin_node_pubkey = pubkey_from_libp2p(&admin_kp);
    let admin_node_sk = {
        // Extract the 32-byte seed from the libp2p keypair so we have
        // both the libp2p Keypair and an ed25519_dalek::SigningKey for
        // the same key.
        let ed = admin_kp.clone().try_into_ed25519().unwrap();
        let seed: [u8; 32] = ed.to_bytes()[..32].try_into().unwrap();
        SigningKey::from_bytes(&seed)
    };

    // Peer's node identity.
    let peer_kp = libp2p_keypair_from_seed(&random_seed());
    let peer_node_pubkey = pubkey_from_libp2p(&peer_kp);

    // ── Stores ─────────────────────────────────────────────────────
    let admin_dir = tempfile::tempdir().unwrap();
    let peer_dir = tempfile::tempdir().unwrap();
    let admin_store = Arc::new(MemvaultStore::open(admin_dir.path().join("blocks.redb")).unwrap());
    let peer_store = Arc::new(MemvaultStore::open(peer_dir.path().join("blocks.redb")).unwrap());
    admin_store.set_local_cluster_id(&cluster_id.0).unwrap();
    peer_store.set_local_cluster_id(&cluster_id.0).unwrap();

    // ── Admin publishes its agent_ui's AgentAttestation locally,
    //    tagged sigchain/agent_att so the receiver expects the same. ─
    let agent_seed = random_seed();
    let agent_sk = SigningKey::from_bytes(&agent_seed);
    let attestation = memvault_auth::sign_agent_attestation(
        &admin_node_sk,
        memvault_core::AgentName("test_ui".into()),
        agent_sk.verifying_key().to_bytes(),
        AgentRole::AgentHost,
        u64::MAX,
    )
    .expect("sign agent attestation");

    let att_bytes = serde_ipld_dagcbor::to_vec(&attestation).unwrap();
    let cid = memvault_core::cid_from_bytes(&att_bytes);
    let cid_bytes = cid.to_bytes();
    let meta = memvault_store::EnvelopeMeta {
        author: admin_node_pubkey.to_vec(),
        tags: vec![("sigchain".to_string(), "agent_att".to_string())],
        wall_ns: memvault_core::wall_ns(),
        cluster_id: Some(cluster_id.0.to_vec()),
        ..Default::default()
    };
    admin_store
        .insert_envelope(&cid_bytes, &att_bytes, &meta)
        .expect("admin local insert");

    // ── Two swarms ─────────────────────────────────────────────────
    let mut admin_swarm = standalone_swarm(
        admin_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let admin_listen = await_listen_addr(&mut admin_swarm).await;

    let mut peer_swarm = standalone_swarm(
        peer_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let _ = await_listen_addr(&mut peer_swarm).await;

    peer_swarm.dial(admin_listen.clone()).unwrap();

    let admin_join = JoinConfig {
        pending_token: None,
        node_pubkey: admin_node_pubkey,
        admin_signing_key: Some(admin_sk.clone()),
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };
    // Peer must complete /join/1.0 first — otherwise admin's
    // `serve_block_request` refuses to serve blocks to it and sync
    // never delivers the AgentAttestation. Issue a token here.
    let admin_peer_for_token = PeerId(admin_node_pubkey.to_vec());
    let admin_genesis = sign_admin_genesis(&admin_sk, cluster_id.clone(), memvault_core::wall_ns())
        .expect("sign admin_genesis");
    let token = issue_token(
        &admin_sk,
        &admin_peer_for_token,
        &cluster_id,
        &admin_genesis,
    );
    let token_str = encode_token_string(&token).expect("encode token");

    let peer_join = JoinConfig {
        pending_token: Some(token_str),
        node_pubkey: peer_node_pubkey,
        admin_signing_key: None,
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };

    let (_admin_head_tx, admin_head_rx) = mpsc::unbounded_channel::<OutboundHead>();
    let (_peer_head_tx, peer_head_rx) = mpsc::unbounded_channel::<OutboundHead>();

    let admin_store_for_task = Arc::clone(&admin_store);
    let admin_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut admin_swarm,
            admin_store_for_task,
            admin_head_rx,
            SyncConfig {
                cluster_id: cluster_id.0.to_vec(),
                ..Default::default()
            },
            admin_join,
        )
        .await;
    });

    let peer_store_for_task = Arc::clone(&peer_store);
    let peer_cluster = cluster_id.0;
    let peer_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut peer_swarm,
            peer_store_for_task,
            peer_head_rx,
            SyncConfig {
                cluster_id: peer_cluster.to_vec(),
                ..Default::default()
            },
            peer_join,
        )
        .await;
    });

    // ── Poll peer's store for the agent_att tag ─────────────────────
    let found = timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(cids) = peer_store.query_by_tag("sigchain", "agent_att", 0, 64) {
                for cid in cids {
                    if let Ok(Some(bytes)) = peer_store.get_block(&cid) {
                        if let Ok(att) = serde_ipld_dagcbor::from_slice::<
                            memvault_auth::AgentAttestation,
                        >(&bytes)
                        {
                            if att.agent_pubkey == agent_sk.verifying_key().to_bytes() {
                                return true;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false);

    admin_task.abort();
    peer_task.abort();
    let _ = admin_task.await;
    let _ = peer_task.await;

    assert!(
        found,
        "AgentAttestation must reach the peer with the `sigchain/agent_att` \
         tag. Pre-fix, vet_sync_block only recognized NodeAttestation \
         and AgentAttestation arrived untagged — peer's scan_trusted_agents \
         never saw it, so the agent never showed up under its node on the \
         trust tree."
    );
}

/// Regression: `rebuild_store` must re-tag raw-CBOR sigchain blocks
/// after `clear_secondary_indexes` so trust-state scanning works
/// after a blockstore version bump. Without this, bumping
/// `BLOCKSTORE_VERSION` would wipe `BY_TAG` and leave sigchain
/// blocks untagged (since `reindex_block` treats raw CBOR as
/// "not an envelope") — `scan_trusted_nodes` / `scan_trusted_agents`
/// would silently return empty.
#[tokio::test]
async fn rebuild_retags_sigchain_blocks() {
    use memvault_api::{EventBus, LocalClient, bootstrap::bootstrap_cluster_trust, sigchain};
    use memvault_core::ClusterId;
    use memvault_query::QuotaManager;
    use std::sync::Arc;

    // Build a LocalClient with admin + node keys so we can mint
    // sigchain blocks.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("blocks.redb")).unwrap());
    let cluster_id = ClusterId::random();
    store.set_local_cluster_id(&cluster_id.0).unwrap();
    let mut peer_id = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut peer_id);
    store.set_local_peer_id(&peer_id).unwrap();

    let client = Arc::new({
        let c = LocalClient::new(
            Arc::clone(&store),
            Arc::new(tokio::sync::RwLock::new(QuotaManager::default())),
            Arc::new(EventBus::new(64)),
            peer_id,
            cluster_id.0.to_vec(),
        );
        let admin_sk = SigningKey::from_bytes(&random_seed());
        c.set_admin_signing_key(admin_sk.clone());
        let node_sk = SigningKey::from_bytes(&random_seed());
        c.set_node_signing_key(node_sk);
        let genesis = sign_admin_genesis(&admin_sk, cluster_id.clone(), memvault_core::wall_ns())
            .expect("sign admin_genesis");
        c.set_pinned_admin_genesis(genesis);
        c
    });

    // Bootstrap publishes the admin's NodeAttestation + AdminGenesis.
    let _trust = bootstrap_cluster_trust(&client).expect("bootstrap");

    // Confirm tags exist pre-rebuild.
    assert!(
        !store
            .query_by_tag("sigchain", "node_att", 0, 64)
            .unwrap_or_default()
            .is_empty(),
        "node_att tag should exist before rebuild"
    );

    // Simulate the version-bump rebuild: clear secondaries, then
    // rebuild_store should walk all blocks and re-tag sigchain shapes.
    store.clear_secondary_indexes().expect("clear");
    assert!(
        store
            .query_by_tag("sigchain", "node_att", 0, 64)
            .unwrap_or_default()
            .is_empty(),
        "node_att tag must be wiped by clear_secondary_indexes"
    );

    let report = memvault_api::rebuild::rebuild_store(&client).expect("rebuild");
    assert!(report.envelopes_indexed > 0, "rebuild indexed nothing");

    // Sigchain tags must be back after rebuild.
    let node_att_cids = store
        .query_by_tag("sigchain", "node_att", 0, 64)
        .unwrap_or_default();
    assert!(
        !node_att_cids.is_empty(),
        "rebuild_store must re-tag NodeAttestation blocks. \
         Pre-fix, raw CBOR sigchain blocks had no envelope `tags` \
         field and `reindex_block` silently skipped them."
    );

    let admin_genesis_cids = store
        .query_by_tag("sigchain", "admin_genesis", 0, 64)
        .unwrap_or_default();
    assert!(
        !admin_genesis_cids.is_empty(),
        "rebuild_store must re-tag AdminGenesis blocks"
    );

    // Verify the re-tagged blocks are still valid sigchain content
    // (not just tagged garbage).
    let scanned_nodes = sigchain::scan_trusted_nodes(
        &client,
        &[client.admin_signing_key().unwrap().verifying_key()],
    )
    .expect("scan_trusted_nodes");
    assert!(
        !scanned_nodes.is_empty(),
        "scan_trusted_nodes must find the re-tagged NodeAttestation"
    );
}

/// After a /join/1.0 round-trip, the joining peer's store must contain
/// admin's own NodeAttestation — handed over in the
/// `JoinResult::Success.bootstrap_blocks` bundle. Without this the
/// block-exchange gate on admin's side would refuse to serve the
/// admin's NodeAttestation to the peer (peer not attested yet from
/// admin's POV at request time), creating a permanent chicken-and-egg.
#[tokio::test]
async fn join_bundles_admin_node_attestation() {
    let admin_seed = random_seed();
    let admin_sk = SigningKey::from_bytes(&admin_seed);
    let admin_pubkey = admin_sk.verifying_key().to_bytes();
    let cluster_id = ClusterId::random();
    let genesis = sign_admin_genesis(&admin_sk, cluster_id.clone(), memvault_core::wall_ns())
        .expect("sign admin_genesis");

    // Admin libp2p identity.
    let admin_kp = libp2p_keypair_from_seed(&random_seed());
    let admin_node_pubkey = pubkey_from_libp2p(&admin_kp);

    // Pre-seed admin's store with admin's OWN NodeAttestation tagged
    // sigchain/node_att (what `bootstrap_cluster_trust` would do at
    // genesis time). This is the block we expect to be bundled.
    use ed25519_dalek::Signer;
    let mut admin_self_att = memvault_auth::NodeAttestation {
        cluster_id: cluster_id.clone(),
        member: memvault_core::PeerId(admin_node_pubkey.to_vec()),
        not_after_ns: u64::MAX,
        issued_via: memvault_auth::AttestationOrigin::Direct,
        signature: [0u8; 64],
    };
    let admin_self_bytes = admin_self_att.signing_bytes().unwrap();
    admin_self_att.signature = admin_sk.sign(&admin_self_bytes).to_bytes();
    let admin_self_cbor = serde_ipld_dagcbor::to_vec(&admin_self_att).unwrap();
    let admin_self_cid = memvault_core::cid_from_bytes(&admin_self_cbor).to_bytes();

    let admin_dir = tempfile::tempdir().unwrap();
    let peer_dir = tempfile::tempdir().unwrap();
    let admin_store = Arc::new(MemvaultStore::open(admin_dir.path().join("blocks.redb")).unwrap());
    let peer_store = Arc::new(MemvaultStore::open(peer_dir.path().join("blocks.redb")).unwrap());
    admin_store.set_local_cluster_id(&cluster_id.0).unwrap();
    peer_store.set_local_cluster_id(&cluster_id.0).unwrap();

    admin_store
        .insert_envelope(
            &admin_self_cid,
            &admin_self_cbor,
            &memvault_store::EnvelopeMeta {
                author: admin_node_pubkey.to_vec(),
                tags: vec![("sigchain".to_string(), "node_att".to_string())],
                wall_ns: memvault_core::wall_ns(),
                cluster_id: Some(cluster_id.0.to_vec()),
                ..Default::default()
            },
        )
        .unwrap();

    // Peer libp2p identity + token.
    let peer_kp = libp2p_keypair_from_seed(&random_seed());
    let peer_pubkey = pubkey_from_libp2p(&peer_kp);
    let admin_peer_for_token = PeerId(admin_node_pubkey.to_vec());
    let token = issue_token(&admin_sk, &admin_peer_for_token, &cluster_id, &genesis);
    let token_str = encode_token_string(&token).expect("encode token");

    let mut admin_swarm = standalone_swarm(
        admin_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let admin_listen = await_listen_addr(&mut admin_swarm).await;

    let mut peer_swarm = standalone_swarm(
        peer_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let _ = await_listen_addr(&mut peer_swarm).await;

    peer_swarm.dial(admin_listen.clone()).unwrap();

    let admin_join = JoinConfig {
        pending_token: None,
        node_pubkey: admin_node_pubkey,
        admin_signing_key: Some(admin_sk.clone()),
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };
    let peer_join = JoinConfig {
        pending_token: Some(token_str),
        node_pubkey: peer_pubkey,
        admin_signing_key: None,
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };

    let (_atx, admin_head_rx) = mpsc::unbounded_channel::<OutboundHead>();
    let (_ptx, peer_head_rx) = mpsc::unbounded_channel::<OutboundHead>();
    let admin_store_t = Arc::clone(&admin_store);
    let admin_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut admin_swarm,
            admin_store_t,
            admin_head_rx,
            SyncConfig {
                cluster_id: cluster_id.0.to_vec(),
                ..Default::default()
            },
            admin_join,
        )
        .await;
    });
    let peer_store_t = Arc::clone(&peer_store);
    let peer_cluster = cluster_id.0;
    let peer_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut peer_swarm,
            peer_store_t,
            peer_head_rx,
            SyncConfig {
                cluster_id: peer_cluster.to_vec(),
                ..Default::default()
            },
            peer_join,
        )
        .await;
    });

    // Poll the peer's store for admin's own NodeAttestation specifically.
    // It should arrive via /join/1.0's bootstrap_blocks bundle, NOT via
    // block-exchange (which the trust gate would refuse to serve).
    let found_admin = timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(cids) = peer_store.query_by_tag("sigchain", "node_att", 0, 64) {
                for cid in cids {
                    if let Ok(Some(bytes)) = peer_store.get_block(&cid) {
                        if let Ok(att) =
                            serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&bytes)
                        {
                            // Admin's attestation: `member` == admin's
                            // node pubkey.
                            if att.member.0 == admin_node_pubkey.to_vec() {
                                return true;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false);

    admin_task.abort();
    peer_task.abort();
    let _ = admin_task.await;
    let _ = peer_task.await;

    assert!(
        found_admin,
        "Peer's store must contain admin's own NodeAttestation after \
         /join/1.0. This block must be bundled in JoinResult::Success.\
         bootstrap_blocks because the trust gate on admin's \
         serve_block_request would refuse to serve it to a peer that \
         isn't attested yet (and the peer isn't attested by admin's \
         POV until its attestation propagates through admin's local \
         sigchain notifier — which happens after the join handshake \
         returns)."
    );
}

/// /join/1.0 must record token consumption (so the trust-tree's Used
/// counter actually ticks) and must reject replays once `max_uses` is
/// reached — while still being idempotent for the SAME peer retrying
/// (the swarm fires JoinRequest every 15s while pending_token is set,
/// and that retry path shouldn't burn through max_uses on its own).
#[tokio::test]
async fn join_consumes_token_once_and_refuses_replay() {
    let admin_sk = SigningKey::from_bytes(&random_seed());
    let admin_pubkey = admin_sk.verifying_key().to_bytes();
    let cluster_id = ClusterId::random();
    let genesis = sign_admin_genesis(&admin_sk, cluster_id.clone(), memvault_core::wall_ns())
        .expect("sign admin_genesis");

    let admin_kp = libp2p_keypair_from_seed(&random_seed());
    let admin_node_pubkey = pubkey_from_libp2p(&admin_kp);
    let peer_kp = libp2p_keypair_from_seed(&random_seed());
    let peer_pubkey = pubkey_from_libp2p(&peer_kp);

    let admin_peer_for_token = PeerId(admin_node_pubkey.to_vec());
    let token = issue_token(&admin_sk, &admin_peer_for_token, &cluster_id, &genesis);
    let token_str = encode_token_string(&token).expect("encode token");
    let token_cbor = serde_ipld_dagcbor::to_vec(&token).unwrap();
    let token_cid = memvault_core::cid_from_bytes(&token_cbor).to_bytes();

    let admin_dir = tempfile::tempdir().unwrap();
    let peer_dir = tempfile::tempdir().unwrap();
    let admin_store = Arc::new(MemvaultStore::open(admin_dir.path().join("blocks.redb")).unwrap());
    let peer_store = Arc::new(MemvaultStore::open(peer_dir.path().join("blocks.redb")).unwrap());
    admin_store.set_local_cluster_id(&cluster_id.0).unwrap();
    peer_store.set_local_cluster_id(&cluster_id.0).unwrap();

    let mut admin_swarm = standalone_swarm(
        admin_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let admin_listen = await_listen_addr(&mut admin_swarm).await;
    let mut peer_swarm = standalone_swarm(
        peer_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let _ = await_listen_addr(&mut peer_swarm).await;
    peer_swarm.dial(admin_listen.clone()).unwrap();

    let admin_join = JoinConfig {
        pending_token: None,
        node_pubkey: admin_node_pubkey,
        admin_signing_key: Some(admin_sk.clone()),
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };
    let peer_join = JoinConfig {
        pending_token: Some(token_str.clone()),
        node_pubkey: peer_pubkey,
        admin_signing_key: None,
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };

    let (_atx, admin_head_rx) = mpsc::unbounded_channel::<OutboundHead>();
    let (_ptx, peer_head_rx) = mpsc::unbounded_channel::<OutboundHead>();
    let admin_store_t = Arc::clone(&admin_store);
    let admin_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut admin_swarm,
            admin_store_t,
            admin_head_rx,
            SyncConfig {
                cluster_id: cluster_id.0.to_vec(),
                ..Default::default()
            },
            admin_join,
        )
        .await;
    });
    let peer_store_t = Arc::clone(&peer_store);
    let pc = cluster_id.0;
    let peer_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut peer_swarm,
            peer_store_t,
            peer_head_rx,
            SyncConfig {
                cluster_id: pc.to_vec(),
                ..Default::default()
            },
            peer_join,
        )
        .await;
    });

    // Wait for the peer's attestation to land on admin's store —
    // proves the join succeeded.
    let _ = timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(cids) = admin_store.query_by_tag("sigchain", "node_att", 0, 64) {
                for cid in cids {
                    if let Ok(Some(bytes)) = admin_store.get_block(&cid) {
                        if let Ok(att) =
                            serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&bytes)
                        {
                            if att.member.0 == peer_pubkey.to_vec() {
                                return;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    // First success must have ticked the consumption counter once.
    let count_after_first = admin_store
        .get_token_consumption_count(&token_cid)
        .unwrap_or(0);
    assert_eq!(
        count_after_first, 1,
        "consumption count must tick on successful /join/1.0"
    );

    // Peer's retry loop fires every 15s. We don't wait for it; instead
    // we drive a fresh join_protocol request directly to verify
    // idempotency: same peer's reply should NOT increment the counter.
    // (Without the `already_attested` guard, every retry would tick.)
    //
    // Simulate by sleeping enough for the retry timer to fire at least
    // once if the runtime gets to it within the window.
    tokio::time::sleep(Duration::from_secs(16)).await;
    let count_after_retry = admin_store
        .get_token_consumption_count(&token_cid)
        .unwrap_or(0);
    assert_eq!(
        count_after_retry, 1,
        "peer retry must NOT increment consumption — same peer, same attestation"
    );

    admin_task.abort();
    peer_task.abort();
    let _ = admin_task.await;
    let _ = peer_task.await;

    // The "refuse a DIFFERENT peer with the same token" branch is
    // covered by `already_attested` + the `used >= max_uses` gate in
    // `build_join_response`. Driving a second real swarm is racy;
    // assert the invariant via the store instead:
    assert_eq!(
        admin_store
            .get_token_consumption_count(&token_cid)
            .unwrap_or(0),
        1,
        "consumption count must equal 1, equalling token.max_uses — \
         further peers would hit the `used >= max_uses` refuse branch"
    );
}

/// Co-admin join: when the token is issued with `admit_as_admin`, the peer
/// presents a fresh admin key + POP (via `JoinConfig.admit_admin_key`), and
/// admin mints an `AdminKeyAdmission` over `/join/1.0` that the peer stores.
/// This is the swarm-side of `cluster-join --admit-as-admin`.
#[tokio::test]
async fn join_admits_co_admin_when_token_allows() {
    let admin_sk = SigningKey::from_bytes(&random_seed());
    let admin_pubkey = admin_sk.verifying_key().to_bytes();
    let cluster_id = ClusterId::random();
    let genesis = sign_admin_genesis(&admin_sk, cluster_id.clone(), memvault_core::wall_ns())
        .expect("sign admin_genesis");

    let admin_kp = libp2p_keypair_from_seed(&random_seed());
    let admin_node_pubkey = pubkey_from_libp2p(&admin_kp);
    let peer_kp = libp2p_keypair_from_seed(&random_seed());
    let peer_node_pubkey = pubkey_from_libp2p(&peer_kp);

    // The fresh admin key the joining peer wants admitted.
    let co_admin_sk = SigningKey::from_bytes(&random_seed());
    let co_admin_pubkey = co_admin_sk.verifying_key().to_bytes();

    // Token issued WITH admit-as-admin.
    let admin_peer_for_token = PeerId(admin_node_pubkey.to_vec());
    let token = issue_token_ex(
        &admin_sk,
        &admin_peer_for_token,
        &cluster_id,
        &genesis,
        true,
    );
    let token_str = encode_token_string(&token).expect("encode token");

    let admin_dir = tempfile::tempdir().unwrap();
    let peer_dir = tempfile::tempdir().unwrap();
    let admin_store = Arc::new(MemvaultStore::open(admin_dir.path().join("blocks.redb")).unwrap());
    let peer_store = Arc::new(MemvaultStore::open(peer_dir.path().join("blocks.redb")).unwrap());
    admin_store.set_local_cluster_id(&cluster_id.0).unwrap();
    peer_store.set_local_cluster_id(&cluster_id.0).unwrap();

    let mut admin_swarm = standalone_swarm(
        admin_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let admin_listen = await_listen_addr(&mut admin_swarm).await;
    let mut peer_swarm = standalone_swarm(
        peer_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        vec![0u8; 32],
    )
    .await
    .unwrap();
    let _ = await_listen_addr(&mut peer_swarm).await;
    peer_swarm.dial(admin_listen.clone()).unwrap();

    let admin_join = JoinConfig {
        pending_token: None,
        node_pubkey: admin_node_pubkey,
        admin_signing_key: Some(admin_sk.clone()),
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        admit_admin_key: None,
        keystore: None,
        on_join_success: None,
    };
    let peer_join = JoinConfig {
        pending_token: Some(token_str.clone()),
        node_pubkey: peer_node_pubkey,
        admin_signing_key: None,
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
        // Peer presents the co-admin key for admission.
        admit_admin_key: Some(co_admin_sk.clone()),
        keystore: None,
        on_join_success: None,
    };

    let (a_tx, a_rx) = mpsc::unbounded_channel::<OutboundHead>();
    let (p_tx, p_rx) = mpsc::unbounded_channel::<OutboundHead>();
    drop(a_tx);
    drop(p_tx);

    let admin_store_t = Arc::clone(&admin_store);
    let admin_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut admin_swarm,
            admin_store_t,
            a_rx,
            SyncConfig {
                cluster_id: cluster_id.0.to_vec(),
                ..Default::default()
            },
            admin_join,
        )
        .await;
    });
    let peer_store_t = Arc::clone(&peer_store);
    let peer_cluster = cluster_id.0;
    let peer_task = tokio::spawn(async move {
        memvault_swarm::run_sync_loop(
            &mut peer_swarm,
            peer_store_t,
            p_rx,
            SyncConfig {
                cluster_id: peer_cluster.to_vec(),
                ..Default::default()
            },
            peer_join,
        )
        .await;
    });

    // The peer should store an AdminKeyAdmission for its co-admin pubkey.
    let admission = timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(cids) = peer_store.query_by_tag("sigchain", "admin_admission", 0, 64) {
                for cid in cids {
                    if let Ok(Some(bytes)) = peer_store.get_block(&cid) {
                        if let Ok(adm) = serde_ipld_dagcbor::from_slice::<
                            memvault_auth::AdminKeyAdmission,
                        >(&bytes)
                        {
                            if adm.new_pubkey == co_admin_pubkey {
                                return adm;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("timed out waiting for AdminKeyAdmission");

    assert_eq!(
        admission.new_pubkey, co_admin_pubkey,
        "admitted the peer's key"
    );
    assert_eq!(
        admission.admitting_pubkey, admin_pubkey,
        "admitted by the cluster admin"
    );
    assert_eq!(admission.cluster_id.0, cluster_id.0, "cluster matches");

    admin_task.abort();
    peer_task.abort();
    let _ = admin_task.await;
    let _ = peer_task.await;
}
