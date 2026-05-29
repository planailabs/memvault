//! Per-grant revocation.
//!
//! [`GrantRevocation`] targets a specific bucket-`Grant` by its CID.
//! Once a verifier sees this revocation, ACL checks treat the grant as
//! if it didn't exist (it's still on the chain for audit purposes; only
//! its access-conferring effect is removed).
//!
//! Signed by the cluster **admin** key — same key that originally signed
//! the grant. Today every grant is admin-signed (see
//! `LocalClient::issue_bucket_grant`), so admin authority is the
//! simplest consistent revocation model. Per-bucket-owner revocation
//! would be a second variant verified against the owner's agent
//! pubkey; not implemented yet.

use cid::Cid;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// Revokes a previously-issued bucket [`crate::Grant`]. Verifies against
/// the admin pubkey embedded inline. Callers are responsible for
/// confirming `admin_pubkey` matches the cluster's current admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRevocation {
    /// Admin pubkey that issued the revocation.
    pub admin_pubkey: [u8; 32],
    /// CID of the grant block being revoked.
    pub grant_cid: Cid,
    /// Human-readable reason (logged + surfaced in audit UI).
    pub reason: String,
    /// Unix nanoseconds at which the revocation was issued.
    pub revoked_at_ns: u64,
    /// Ed25519 signature over [`GrantRevocation::signing_bytes`] under
    /// the admin's private key.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct GrantRevocationSigningPayload<'a> {
    admin_pubkey: &'a [u8; 32],
    grant_cid: &'a Cid,
    reason: &'a str,
    revoked_at_ns: u64,
}

impl GrantRevocation {
    /// Compute the canonical bytes that the admin signs.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = GrantRevocationSigningPayload {
            admin_pubkey: &self.admin_pubkey,
            grant_cid: &self.grant_cid,
            reason: &self.reason,
            revoked_at_ns: self.revoked_at_ns,
        };
        crate::domain_sign(b"memvault/sig/grant-revocation/v1", &payload)
    }

    /// Verify the revocation signature against the embedded admin pubkey.
    pub fn verify_signature(&self) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        let pubkey = VerifyingKey::from_bytes(&self.admin_pubkey)
            .map_err(|_| AuthError::SignatureInvalid)?;
        pubkey
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}

/// Build and sign a [`GrantRevocation`] with the admin key.
pub fn sign_grant_revocation(
    admin_key: &SigningKey,
    grant_cid: Cid,
    reason: impl Into<String>,
) -> Result<GrantRevocation> {
    let revoked_at_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut rev = GrantRevocation {
        admin_pubkey: admin_key.verifying_key().to_bytes(),
        grant_cid,
        reason: reason.into(),
        revoked_at_ns,
        signature: [0u8; 64],
    };
    let bytes = rev.signing_bytes()?;
    rev.signature = admin_key.sign(&bytes).to_bytes();
    Ok(rev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn make_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn fake_cid() -> Cid {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        memvault_core::cid_from_bytes(&bytes)
    }

    #[test]
    fn roundtrip_sign_verify() {
        let admin = make_key();
        let cid = fake_cid();
        let rev = sign_grant_revocation(&admin, cid, "key rotated").unwrap();
        assert_eq!(rev.admin_pubkey, admin.verifying_key().to_bytes());
        assert_eq!(rev.grant_cid, cid);
        rev.verify_signature().unwrap();
    }

    #[test]
    fn rejects_tampered_grant_cid() {
        let admin = make_key();
        let mut rev = sign_grant_revocation(&admin, fake_cid(), "real").unwrap();
        rev.grant_cid = fake_cid();
        assert!(rev.verify_signature().is_err());
    }

    #[test]
    fn rejects_tampered_reason() {
        let admin = make_key();
        let mut rev = sign_grant_revocation(&admin, fake_cid(), "real").unwrap();
        rev.reason = "fake".into();
        assert!(rev.verify_signature().is_err());
    }
}
