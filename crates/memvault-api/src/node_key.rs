//! Helpers for obtaining the cluster *node* signing key.
//!
//! The node key signs [`memvault_auth::NodeAttestation`]s issued by this node
//! to its agents, plus [`memvault_auth::AgentRevocation`]s. It must be
//! stable across daemon restarts, otherwise every issued attestation is
//! orphaned.
//!
//! Two sources are supported:
//!
//! - **libp2p host key** (production daemon): the daemon's russh-format
//!   ed25519 private key. Loaded via a daemon-side helper that depends on
//!   `russh`; this crate doesn't take a russh dependency.
//! - **File-backed key** (memctl dev / standalone `memvault-web`): a 32-byte
//!   seed stored at `<data_dir>/identity/node.key`. Created on first use
//!   with `0o600` permissions and a CSPRNG seed.

use std::path::Path;

/// Load (or generate + persist) a per-daemon node signing key at
/// `<data_dir>/identity/node.key`. Used by dev / non-libp2p callers
/// (memctl, memvault-web standalone main). The full daemon reuses its
/// libp2p host key instead (design A-1).
pub fn load_or_generate(data_dir: &Path) -> std::io::Result<ed25519_dalek::SigningKey> {
    let path = data_dir.join("identity").join("node.key");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() >= 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut seed = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut seed);
    std::fs::write(&path, &seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// Keystore key holding the singleton node signing seed (design A-1: the node
/// key *is* the libp2p key). The daemon persists its host-key seed here; the
/// memctl/swarm paths migrate a loose `libp2p.key` into it. Resolving the node
/// key keystore-first lets the daemon and any co-process tool (memctl) agree
/// on one key with no loose identity file.
pub const NODE_SEED_KEYSTORE_KEY: &[u8] = b"nodesk";

/// Resolve the 32-byte node signing seed, keystore-first.
///
/// Order:
///  1. keystore `nodesk` (authoritative — written by the daemon),
///  2. a loose `<identity_dir>/libp2p.key`, which is migrated into the
///     keystore and then deleted on first sight — mirroring the `admin.key`
///     migration in [`LocalClient::migrate_legacy_identity_files`].
///
/// Returns `None` when neither source exists; the caller decides whether to
/// generate a fresh seed (the swarm path does; signing-only callers error).
///
/// [`LocalClient::migrate_legacy_identity_files`]: crate::LocalClient::migrate_legacy_identity_files
pub fn node_seed_from_keystore_or_file(
    keystore: &memvault_keystore::KeyStore,
    identity_dir: &Path,
) -> Option<[u8; 32]> {
    if let Some(bytes) = keystore.get(NODE_SEED_KEYSTORE_KEY) {
        if bytes.len() >= 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            return Some(seed);
        }
    }

    // Migrate a loose libp2p.key into the keystore, then delete it. Accept both
    // 32-byte seed-only and 64-byte seed+public files (as the swarm loader does).
    let path = identity_dir.join("libp2p.key");
    let mut bytes = std::fs::read(&path).ok()?;
    if bytes.len() == 64 {
        bytes.truncate(32);
    }
    if bytes.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    // Only delete the loose file once the keystore durably holds the seed.
    if keystore.put(NODE_SEED_KEYSTORE_KEY, &seed).is_ok() {
        let _ = std::fs::remove_file(&path);
        tracing::info!("migrated libp2p.key into keystore (nodesk)");
    }
    Some(seed)
}
