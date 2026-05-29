use cid::Cid;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// Revokes a previously issued attestation, grant, or token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub target: Cid,
    pub reason: String,
    pub revoked_at_ns: u64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct RevocationSigningPayload<'a> {
    target: &'a Cid,
    reason: &'a str,
    revoked_at_ns: u64,
}

impl Revocation {
    /// Compute the bytes that are signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = RevocationSigningPayload {
            target: &self.target,
            reason: &self.reason,
            revoked_at_ns: self.revoked_at_ns,
        };
        crate::domain_sign(b"memvault/sig/revocation/v1", &payload)
    }

    /// Verify the revocation signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}
