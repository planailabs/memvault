use std::collections::HashSet;

use cid::Cid;
use ed25519_dalek::VerifyingKey;
use memvault_core::PeerId;

use crate::attestation::MembershipAttestation;
use crate::error::{AuthError, Result};
use crate::key_state::AdminKeyState;
use crate::trust::ClusterTrust;

/// Trait for checking whether a CID has been revoked.
pub trait RevocationStore {
    fn is_revoked(&self, cid: &Cid) -> bool;
}

/// A simple in-memory revocation store backed by a `HashSet`.
impl RevocationStore for HashSet<Cid> {
    fn is_revoked(&self, cid: &Cid) -> bool {
        self.contains(cid)
    }
}

/// Rotation-aware auth verifier that validates attestations against known admin keys
/// and federation trust records.
pub struct AuthVerifier {
    /// Admin key state for the local cluster.
    pub local_key_state: AdminKeyState,
    /// Trusted federation clusters and their admin keys.
    pub federation_trusts: Vec<ClusterTrust>,
}

impl AuthVerifier {
    /// Create a new verifier with initial admin key state.
    pub fn new(local_key_state: AdminKeyState) -> Self {
        Self {
            local_key_state,
            federation_trusts: Vec::new(),
        }
    }

    /// Add a federation trust record.
    pub fn add_federation_trust(&mut self, trust: ClusterTrust) {
        self.federation_trusts.push(trust);
    }

    /// Fully verify an attestation:
    /// 1. Signature is by a key valid at signing time
    /// 2. `attestation.member == connecting_peer`
    /// 3. Not expired
    /// 4. Not revoked
    /// 5. For federation: accepts attestations signed by trusted cluster admin keys
    pub fn verify_attestation(
        &self,
        attestation: &MembershipAttestation,
        connecting_peer: &PeerId,
        now_ns: u64,
        attestation_cid: &Cid,
        revocations: &dyn RevocationStore,
    ) -> Result<()> {
        // Check revocation.
        if revocations.is_revoked(attestation_cid) {
            return Err(AuthError::AttestationRevoked {
                reason: "attestation CID found in revocation set".into(),
            });
        }

        // Check peer identity (member == peer invariant).
        attestation.verify_peer_identity(connecting_peer)?;

        // Check expiry.
        attestation.verify_not_expired(now_ns)?;

        // Verify signature against a valid key.
        if self.verify_with_local_keys(attestation, now_ns).is_ok() {
            return Ok(());
        }

        // Try federation keys.
        if self.verify_with_federation_keys(attestation, now_ns).is_ok() {
            return Ok(());
        }

        Err(AuthError::NoValidKeyAtTime)
    }

    /// Try to verify the attestation signature against local admin keys valid at now_ns.
    fn verify_with_local_keys(
        &self,
        attestation: &MembershipAttestation,
        now_ns: u64,
    ) -> Result<()> {
        let valid_keys = self.local_key_state.valid_keys_at(now_ns);
        for key_bytes in valid_keys {
            if let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) {
                if attestation.verify_signature(&verifying_key).is_ok() {
                    return Ok(());
                }
            }
        }
        Err(AuthError::NoValidKeyAtTime)
    }

    /// Try to verify the attestation against federated cluster admin keys.
    fn verify_with_federation_keys(
        &self,
        attestation: &MembershipAttestation,
        now_ns: u64,
    ) -> Result<()> {
        for trust in &self.federation_trusts {
            // Skip expired trust records.
            if now_ns > trust.not_after_ns {
                continue;
            }
            // Only consider trusts for the attestation's cluster.
            if trust.cluster_id != attestation.cluster_id {
                continue;
            }
            for key_bytes in &trust.trusted_admin_keys {
                if let Ok(verifying_key) = VerifyingKey::from_bytes(key_bytes) {
                    if attestation.verify_signature(&verifying_key).is_ok() {
                        return Ok(());
                    }
                }
            }
        }
        Err(AuthError::NoValidKeyAtTime)
    }
}
