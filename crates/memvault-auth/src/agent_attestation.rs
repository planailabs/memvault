//! Agent attestation — issued by a *node* (peer), proves that an agent's
//! public key is trusted by that node.
//!
//! Trust chain at verification time:
//! 1. The node's [`NodeAttestation`] is admin-signed (or carried via the
//!    sig-chain). The verifier looks it up by `node_pubkey`.
//! 2. This [`AgentAttestation`] is signed by that node's private key.
//! 3. The agent then issues JWTs signed with its own private key (carried in
//!    `agent_pubkey`).
//!
//! Critically, the agent attestation does **not** contain the cluster admin's
//! public key. The agent only knows which node attested it; the trust path back
//! to the admin lives in the cluster's sig-chain, looked up at verify time.
//!
//! [`NodeAttestation`]: crate::NodeAttestation

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use memvault_core::AgentName;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};
use crate::role::AgentRole;

/// Proves an agent (`agent_pubkey`, `agent_id`) is trusted by a node
/// (`node_pubkey`). Signed by the node's ed25519 private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAttestation {
    /// The node (peer) that issued this attestation. The verifier looks up
    /// this pubkey in the cluster's sig-chain to confirm it's a trusted node.
    pub node_pubkey: [u8; 32],
    /// Human-readable agent identifier (display / audit).
    pub agent_id: AgentName,
    /// Ed25519 public key the agent will sign JWTs with.
    pub agent_pubkey: [u8; 32],
    /// What the agent is allowed to do (Admin / AgentHost / Auditor / Service).
    pub role: AgentRole,
    /// Unix nanoseconds after which this attestation is invalid.
    pub not_after_ns: u64,
    /// Ed25519 signature over [`AgentAttestation::signing_bytes`] using the
    /// node's private key.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// The fields covered by `signature` (everything except the signature itself).
#[derive(Serialize)]
struct AgentAttestationSigningPayload<'a> {
    node_pubkey: &'a [u8; 32],
    agent_id: &'a AgentName,
    agent_pubkey: &'a [u8; 32],
    role: &'a AgentRole,
    not_after_ns: u64,
}

impl AgentAttestation {
    /// Compute the canonical bytes that the node signs.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = AgentAttestationSigningPayload {
            node_pubkey: &self.node_pubkey,
            agent_id: &self.agent_id,
            agent_pubkey: &self.agent_pubkey,
            role: &self.role,
            not_after_ns: self.not_after_ns,
        };
        crate::domain_sign(b"memvault/sig/agent-attestation/v1", &payload)
    }

    /// Verify the signature against the claimed `node_pubkey`. The caller is
    /// responsible for confirming `node_pubkey` is itself a trusted node (via
    /// a [`NodeAttestation`](crate::NodeAttestation) lookup).
    pub fn verify_signature(&self) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        let pubkey =
            VerifyingKey::from_bytes(&self.node_pubkey).map_err(|_| AuthError::SignatureInvalid)?;
        pubkey
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
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

/// Build an `AgentAttestation` and sign it with the node's private key.
pub fn sign_agent_attestation(
    node_key: &SigningKey,
    agent_id: AgentName,
    agent_pubkey: [u8; 32],
    role: AgentRole,
    not_after_ns: u64,
) -> Result<AgentAttestation> {
    let mut att = AgentAttestation {
        node_pubkey: node_key.verifying_key().to_bytes(),
        agent_id,
        agent_pubkey,
        role,
        not_after_ns,
        signature: [0u8; 64],
    };
    let bytes = att.signing_bytes()?;
    att.signature = node_key.sign(&bytes).to_bytes();
    Ok(att)
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

    #[test]
    fn roundtrip_sign_verify() {
        let node = make_key();
        let agent = make_key();
        let att = sign_agent_attestation(
            &node,
            AgentName("alice".to_string()),
            agent.verifying_key().to_bytes(),
            AgentRole::AgentHost,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(att.node_pubkey, node.verifying_key().to_bytes());
        att.verify_signature().unwrap();
    }

    #[test]
    fn rejects_tampered_role() {
        let node = make_key();
        let agent = make_key();
        let mut att = sign_agent_attestation(
            &node,
            AgentName("alice".to_string()),
            agent.verifying_key().to_bytes(),
            AgentRole::AgentHost,
            u64::MAX,
        )
        .unwrap();
        // Elevate role without re-signing.
        att.role = AgentRole::Admin;
        assert!(att.verify_signature().is_err());
    }

    #[test]
    fn rejects_tampered_agent_pubkey() {
        let node = make_key();
        let agent = make_key();
        let other_agent = make_key();
        let mut att = sign_agent_attestation(
            &node,
            AgentName("alice".to_string()),
            agent.verifying_key().to_bytes(),
            AgentRole::AgentHost,
            u64::MAX,
        )
        .unwrap();
        att.agent_pubkey = other_agent.verifying_key().to_bytes();
        assert!(att.verify_signature().is_err());
    }
}
