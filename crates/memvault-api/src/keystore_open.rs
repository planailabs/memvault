//! Single source of truth for opening the token/key-material keystore.
//!
//! The daemon, `memctl`, and the swarm join path all open the *same*
//! keystore file and so must agree on the at-rest cipher. Routing every
//! opener through here guarantees that: plaintext by default, or
//! XChaCha20-Poly1305 with an Argon2id-derived key when
//! `MEMVAULT_KEYSTORE_PASSPHRASE` is set. The 16-byte Argon2id salt lives
//! in a `<path>.salt` sidecar, generated once and shared across processes.

use std::path::Path;
use std::sync::Arc;

use memvault_keystore::{Cipher, KeyStore};

use crate::error::{ApiError, Result};

const KEYSTORE_FILE: &str = "keystore.mvks";
const PASSPHRASE_ENV: &str = "MEMVAULT_KEYSTORE_PASSPHRASE";

/// Path of the keystore file within an identity directory.
pub fn keystore_path(identity_dir: impl AsRef<Path>) -> std::path::PathBuf {
    identity_dir.as_ref().join(KEYSTORE_FILE)
}

/// Open (creating if needed) the keystore for the given identity directory,
/// honouring `MEMVAULT_KEYSTORE_PASSPHRASE` for at-rest encryption.
pub fn open_token_keystore(identity_dir: impl AsRef<Path>) -> Result<Arc<KeyStore>> {
    let path = keystore_path(identity_dir);
    match std::env::var(PASSPHRASE_ENV) {
        Ok(p) if !p.is_empty() => open_encrypted(&path, p.as_bytes()),
        _ => KeyStore::open(&path)
            .map(Arc::new)
            .map_err(|e| ApiError::Other(format!("open keystore: {e}"))),
    }
}

/// Open the keystore with passphrase-derived AEAD at rest. The salt sidecar
/// (`<path>.salt`, 16 bytes, 0600) is created on first use and reused after.
pub fn open_encrypted(path: &Path, passphrase: &[u8]) -> Result<Arc<KeyStore>> {
    let salt = load_or_create_salt(path)?;
    let key = memvault_keystore::derive_key(passphrase, &salt)
        .map_err(|e| ApiError::Other(format!("derive keystore key: {e}")))?;
    KeyStore::open_with_cipher(path, Cipher::aead(key))
        .map(Arc::new)
        .map_err(|e| ApiError::Other(format!("open encrypted keystore: {e}")))
}

fn load_or_create_salt(path: &Path) -> Result<[u8; 16]> {
    let salt_path = {
        let mut s = path.as_os_str().to_os_string();
        s.push(".salt");
        std::path::PathBuf::from(s)
    };
    if let Ok(b) = std::fs::read(&salt_path) {
        if b.len() == 16 {
            return Ok(b.try_into().unwrap());
        }
    }
    let mut s = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut s);
    if let Some(parent) = salt_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&salt_path, s)
        .map_err(|e| ApiError::Other(format!("write keystore salt: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&salt_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(s)
}
