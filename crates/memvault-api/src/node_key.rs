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
