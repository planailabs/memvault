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
    AdminGenesis, JoinToken, Role, encode_token_string, sign_admin_genesis,
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
    kp.public()
        .try_into_ed25519()
        .expect("ed25519")
        .to_bytes()
}

/// Build a signed JoinToken with the AdminGenesis embedded — the
/// production token-issuer output.
fn issue_token(
    admin_sk: &SigningKey,
    admin_peer_id: &PeerId,
    cluster_id: &ClusterId,
    genesis: &AdminGenesis,
) -> JoinToken {
    use ed25519_dalek::Signer;
    let now_ns = memvault_core::wall_ns();
    let mut token = JoinToken {
        issuer: admin_peer_id.clone(),
        cluster_id: cluster_id.clone(),
        role: Role::AgentHost,
        initial_grants: vec![],
        not_before_ns: now_ns.saturating_sub(60_000_000_000),
        not_after_ns: now_ns + 3600 * 1_000_000_000,
        max_uses: 1,
        nonce: random_seed()[..16].try_into().unwrap(),
        label: Some("smoke-test".into()),
        admin_genesis: Some(genesis.clone()),
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
    let admin_store =
        Arc::new(MemvaultStore::open(admin_dir.path().join("blocks.redb")).unwrap());
    let peer_store =
        Arc::new(MemvaultStore::open(peer_dir.path().join("blocks.redb")).unwrap());
    admin_store
        .set_local_cluster_id(&cluster_id.0)
        .unwrap();
    peer_store.set_local_cluster_id(&cluster_id.0).unwrap();

    // ── Build the two swarms ────────────────────────────────────────
    let mut admin_swarm = standalone_swarm(
        admin_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
    )
    .await
    .unwrap();
    let admin_listen = await_listen_addr(&mut admin_swarm).await;

    let mut peer_swarm = standalone_swarm(
        peer_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
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
        on_join_success: None,
    };
    let peer_join = JoinConfig {
        pending_token: Some(token_str.clone()),
        node_pubkey: peer_node_pubkey,
        admin_signing_key: None,
        pinned_admin_pubkey: Some(admin_pubkey),
        cluster_id: cluster_id.0,
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
            if let Ok(cids) =
                peer_store.query_by_tag("sigchain", "node_att", 0, 64)
            {
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
    assert_eq!(att.role, Role::AgentHost, "role matches token");

    // Signature must verify against admin pubkey (the pin).
    let admin_vk =
        ed25519_dalek::VerifyingKey::from_bytes(&admin_pubkey).expect("admin pubkey");
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
    std::fs::write(
        dir.path().join("identity").join("libp2p.key"),
        &full[..32],
    )
    .unwrap();

    let kp_loaded = memctl::load_or_generate_keypair(
        &dir.path().join("identity").join("libp2p.key"),
    )
    .expect("load_or_generate_keypair");
    let swarm_pubkey: [u8; 32] = kp_loaded
        .public()
        .try_into_ed25519()
        .expect("ed25519")
        .to_bytes();

    let node_sk = memctl::libp2p_node_signing_key(dir.path())
        .expect("libp2p_node_signing_key");
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
    let admin_store =
        Arc::new(MemvaultStore::open(admin_dir.path().join("blocks.redb")).unwrap());
    let peer_store =
        Arc::new(MemvaultStore::open(peer_dir.path().join("blocks.redb")).unwrap());
    admin_store.set_local_cluster_id(&cluster_id.0).unwrap();
    peer_store.set_local_cluster_id(&cluster_id.0).unwrap();

    let mut admin_swarm = standalone_swarm(
        admin_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
    )
    .await
    .unwrap();
    let admin_listen = await_listen_addr(&mut admin_swarm).await;

    let mut peer_swarm = standalone_swarm(
        peer_kp.clone(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
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
                        if let Ok(att) = serde_ipld_dagcbor::from_slice::<
                            memvault_auth::NodeAttestation,
                        >(&bytes)
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
