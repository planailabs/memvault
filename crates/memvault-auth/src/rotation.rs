use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use memvault_core::{AgentName, ClusterId};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// Records an admin key rotation for a cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyRotation {
    pub cluster_id: ClusterId,
    pub old_key: [u8; 32],
    pub new_key: [u8; 32],
    pub valid_from_ns: u64,
    pub overlap_until_ns: u64,
    pub rotation_id: [u8; 16],
    #[serde(with = "BigArray")]
    pub signature_old: [u8; 64],
    #[serde(with = "BigArray")]
    pub signature_new: [u8; 64],
}

#[derive(Serialize)]
struct AdminRotationSigningPayload<'a> {
    cluster_id: &'a ClusterId,
    old_key: &'a [u8; 32],
    new_key: &'a [u8; 32],
    valid_from_ns: u64,
    overlap_until_ns: u64,
    rotation_id: &'a [u8; 16],
}

impl AdminKeyRotation {
    /// Compute the bytes that both keys sign.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = AdminRotationSigningPayload {
            cluster_id: &self.cluster_id,
            old_key: &self.old_key,
            new_key: &self.new_key,
            valid_from_ns: self.valid_from_ns,
            overlap_until_ns: self.overlap_until_ns,
            rotation_id: &self.rotation_id,
        };
        crate::domain_sign(b"memvault/sig/admin-key-rotation/v1", &payload)
    }

    /// Verify both signatures (old key and new key must both sign the rotation).
    pub fn verify_signatures(
        &self,
        old_verifying_key: &VerifyingKey,
        new_verifying_key: &VerifyingKey,
    ) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig_old = Signature::from_bytes(&self.signature_old);
        let sig_new = Signature::from_bytes(&self.signature_new);
        old_verifying_key
            .verify(&bytes, &sig_old)
            .map_err(|_| AuthError::SignatureInvalid)?;
        new_verifying_key
            .verify(&bytes, &sig_new)
            .map_err(|_| AuthError::SignatureInvalid)?;
        Ok(())
    }
}

/// Records an agent key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentKeyRotation {
    pub agent_id: AgentName,
    pub cluster_id: ClusterId,
    pub old_key: [u8; 32],
    pub new_key: [u8; 32],
    pub valid_from_ns: u64,
    pub overlap_until_ns: u64,
    pub rotation_id: [u8; 16],
    #[serde(with = "BigArray")]
    pub signature_old: [u8; 64],
    #[serde(with = "BigArray")]
    pub signature_new: [u8; 64],
}

#[derive(Serialize)]
struct AgentRotationSigningPayload<'a> {
    agent_id: &'a AgentName,
    cluster_id: &'a ClusterId,
    old_key: &'a [u8; 32],
    new_key: &'a [u8; 32],
    valid_from_ns: u64,
    overlap_until_ns: u64,
    rotation_id: &'a [u8; 16],
}

impl AgentKeyRotation {
    /// Compute the bytes that both keys sign.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = AgentRotationSigningPayload {
            agent_id: &self.agent_id,
            cluster_id: &self.cluster_id,
            old_key: &self.old_key,
            new_key: &self.new_key,
            valid_from_ns: self.valid_from_ns,
            overlap_until_ns: self.overlap_until_ns,
            rotation_id: &self.rotation_id,
        };
        crate::domain_sign(b"memvault/sig/agent-key-rotation/v1", &payload)
    }

    /// Verify both signatures.
    pub fn verify_signatures(
        &self,
        old_verifying_key: &VerifyingKey,
        new_verifying_key: &VerifyingKey,
    ) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig_old = Signature::from_bytes(&self.signature_old);
        let sig_new = Signature::from_bytes(&self.signature_new);
        old_verifying_key
            .verify(&bytes, &sig_old)
            .map_err(|_| AuthError::SignatureInvalid)?;
        new_verifying_key
            .verify(&bytes, &sig_new)
            .map_err(|_| AuthError::SignatureInvalid)?;
        Ok(())
    }
}

/// Records an aborted key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationAborted {
    pub rotation_id: [u8; 16],
    pub aborted_at_ns: u64,
    pub reason: String,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct AbortedSigningPayload<'a> {
    rotation_id: &'a [u8; 16],
    aborted_at_ns: u64,
    reason: &'a str,
}

impl RotationAborted {
    /// Compute the bytes that are signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = AbortedSigningPayload {
            rotation_id: &self.rotation_id,
            aborted_at_ns: self.aborted_at_ns,
            reason: &self.reason,
        };
        crate::domain_sign(b"memvault/sig/rotation-aborted/v1", &payload)
    }

    /// Verify the abort signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}
