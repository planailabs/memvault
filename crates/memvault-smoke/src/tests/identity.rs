//! Agent identity and enrollment smoke tests.

use memvault_api::agent_identity::AgentIdentity;
use memvault_auth::Role;
use memvault_core::{ClusterId, PeerId};

#[test]
fn generate_and_load_identity() {
    let dir = tempfile::tempdir().unwrap();
    let identity_dir = dir.path().join("agent-test");
    let cluster_id = ClusterId::random();
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let admin_sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let admin_vk = admin_sk.verifying_key();
    let admin_peer = PeerId(admin_vk.as_bytes().to_vec());

    let id = AgentIdentity::generate_local(
        &identity_dir, "smoke-agent", &cluster_id, &admin_peer, &admin_sk,
        Role::AgentHost, 86400_000_000_000,
    ).unwrap();

    assert_eq!(id.agent_id.0, "smoke-agent");
    id.attestation.verify_signature(&admin_vk).unwrap();
    id.enrollment.verify_signature(&admin_vk).unwrap();

    // Load from disk
    let loaded = AgentIdentity::load(&identity_dir).unwrap();
    assert_eq!(loaded.signing_key.to_bytes(), id.signing_key.to_bytes());
}

#[test]
fn ensure_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let identity_dir = dir.path().join("idem");
    let cluster_id = ClusterId::random();
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let admin_sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let admin_vk = admin_sk.verifying_key();
    let admin_peer = PeerId(admin_vk.as_bytes().to_vec());

    let id1 = AgentIdentity::ensure(
        &identity_dir, "agent", &cluster_id, &admin_peer, &admin_sk,
        Role::AgentHost, 86400_000_000_000,
    ).unwrap();
    let id2 = AgentIdentity::ensure(
        &identity_dir, "agent", &cluster_id, &admin_peer, &admin_sk,
        Role::AgentHost, 86400_000_000_000,
    ).unwrap();
    assert_eq!(id1.signing_key.to_bytes(), id2.signing_key.to_bytes());
}

#[test]
fn identity_exists_check() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!AgentIdentity::exists(dir.path()));
}

#[test]
fn store_peer_id_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let store = memvault_store::MemvaultStore::open(dir.path().join("test.redb")).unwrap();
    let peer_id = vec![42u8; 32];
    store.set_local_peer_id(&peer_id).unwrap();
    assert_eq!(store.get_local_peer_id().unwrap().unwrap(), peer_id);
    // Same value is idempotent
    store.set_local_peer_id(&peer_id).unwrap();
    // Different value fails
    assert!(store.set_local_peer_id(&vec![99u8; 32]).is_err());
}

#[test]
fn store_cluster_id_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let store = memvault_store::MemvaultStore::open(dir.path().join("test.redb")).unwrap();
    let cluster_id = vec![7u8; 32];
    store.set_local_cluster_id(&cluster_id).unwrap();
    assert_eq!(store.get_local_cluster_id().unwrap().unwrap(), cluster_id);
}
