use cid::Cid;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use memvault_core::{ClusterId, PeerId};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};
use crate::role::Role;

/// How the attestation was issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationOrigin {
    /// Directly attested by an admin.
    Direct,
    /// Attested via token redemption; the CID references the TokenConsumption record.
    TokenRedemption(Cid),
}

/// Proves that a peer is a member of a cluster with a given role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAttestation {
    pub cluster_id: ClusterId,
    pub member: PeerId,
    pub role: Role,
    pub not_after_ns: u64,
    pub issued_via: AttestationOrigin,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// The fields covered by the signature (everything except the signature itself).
#[derive(Serialize)]
struct AttestationSigningPayload<'a> {
    cluster_id: &'a ClusterId,
    member: &'a PeerId,
    role: &'a Role,
    not_after_ns: u64,
    issued_via: &'a AttestationOrigin,
}

impl NodeAttestation {
    /// Compute the bytes that are signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = AttestationSigningPayload {
            cluster_id: &self.cluster_id,
            member: &self.member,
            role: &self.role,
            not_after_ns: self.not_after_ns,
            issued_via: &self.issued_via,
        };
        serde_ipld_dagcbor::to_vec(&payload).map_err(|e| AuthError::Codec(e.to_string()))
    }

    /// Verify the attestation signature against the given admin key.
    pub fn verify_signature(&self, admin_key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        admin_key
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }

    /// Check that the attestation's member matches the connecting peer.
    pub fn verify_peer_identity(&self, connecting_peer: &PeerId) -> Result<()> {
        if self.member != *connecting_peer {
            return Err(AuthError::PeerMismatch {
                attestation_member: format!("{}", self.member),
                connecting_peer: format!("{}", connecting_peer),
            });
        }
        Ok(())
    }

    /// Check that the attestation has not expired.
    pub fn verify_not_expired(&self, now_ns: u64) -> Result<()> {
        if now_ns > self.not_after_ns {
            return Err(AuthError::AttestationExpired {
                expired_at_ns: self.not_after_ns,
            });
        }
        Ok(())
    }
}
