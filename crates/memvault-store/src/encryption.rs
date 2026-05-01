//! Block encryption layer using AES-256-GCM.
//!
//! Wraps raw block bytes before storage, unwraps on retrieval.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// Block encryption using AES-256-GCM.
pub struct BlockEncryption {
    key: [u8; 32],
}

impl BlockEncryption {
    /// Create from a 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Derive a key from a passphrase using blake3.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let hash = blake3::hash(passphrase.as_bytes());
        Self {
            key: *hash.as_bytes(),
        }
    }

    /// Encrypt a block. Returns nonce (12 bytes) + ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use aes_gcm::aead::rand_core::RngCore;

        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("valid key size");
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a block. Input is nonce (12 bytes) + ciphertext.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < NONCE_SIZE + 1 {
            return Err(EncryptionError::TooShort);
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("valid key size");

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)
    }
}

/// Errors from the encryption layer.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("ciphertext too short")]
    TooShort,
    #[error("decryption failed")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let enc = BlockEncryption::from_passphrase("test-key");
        let plaintext = b"hello, memvault!";
        let encrypted = enc.encrypt(plaintext).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let enc1 = BlockEncryption::from_passphrase("key-one");
        let enc2 = BlockEncryption::from_passphrase("key-two");
        let encrypted = enc1.encrypt(b"secret").unwrap();
        let result = enc2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn too_short_ciphertext_fails() {
        let enc = BlockEncryption::from_passphrase("key");
        let result = enc.decrypt(&[0u8; 5]);
        assert!(matches!(result, Err(EncryptionError::TooShort)));
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let enc = BlockEncryption::new([42u8; 32]);
        let encrypted = enc.encrypt(b"").unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn large_block_roundtrip() {
        let enc = BlockEncryption::from_passphrase("big-data");
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let encrypted = enc.encrypt(&plaintext).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
