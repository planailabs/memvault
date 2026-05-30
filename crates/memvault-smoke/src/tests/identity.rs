//! Agent identity and enrollment smoke tests.

use memvault_api::agent_identity::AgentIdentity;
use memvault_auth::AgentRole;
use memvault_core::ClusterId;

#[test]
fn generate_and_load_identity() {
    let dir = tempfile::tempdir().unwrap();
    let identity_dir = dir.path().join("agent-test");
    let cluster_id = ClusterId::random();
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let node_sk = ed25519_dalek::SigningKey::from_bytes(&secret);

    let (id, attestation) = AgentIdentity::generate_local(
        &identity_dir,
        "smoke-agent",
        &cluster_id,
        &node_sk,
        AgentRole::AgentHost,
        86400_000_000_000,
    )
    .unwrap();

    assert_eq!(id.agent_id.0, "smoke-agent");
    // Attestation is returned but not persisted — verify it here, then
    // confirm no other files leak onto disk.
    attestation.verify_signature().unwrap();
    assert_eq!(
        attestation.node_pubkey,
        node_sk.verifying_key().to_bytes()
    );
    assert!(!identity_dir.join("attestation.cbor").exists());
    assert!(!identity_dir.join("agent.json").exists());

    // Load from disk — private_key.pem is the only required file;
    // agent_id derives from the directory basename.
    let loaded = AgentIdentity::load(&identity_dir).unwrap();
    assert_eq!(loaded.signing_key.to_bytes(), id.signing_key.to_bytes());
    assert_eq!(loaded.agent_id.0, "agent-test");
}

#[test]
fn ensure_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let identity_dir = dir.path().join("idem");
    let cluster_id = ClusterId::random();
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let node_sk = ed25519_dalek::SigningKey::from_bytes(&secret);

    let id1 = AgentIdentity::ensure(
        &identity_dir,
        "agent",
        &cluster_id,
        &node_sk,
        AgentRole::AgentHost,
        86400_000_000_000,
    )
    .unwrap();
    let id2 = AgentIdentity::ensure(
        &identity_dir,
        "agent",
        &cluster_id,
        &node_sk,
        AgentRole::AgentHost,
        86400_000_000_000,
    )
    .unwrap();
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
