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
