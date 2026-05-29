//! Agent + node revocation.
//!
//! - [`AgentRevocation`] — issued by a *node* against one of its own agents.
//!   Verifies against the node's pubkey.
//! - [`NodeRevocation`] — issued by the cluster *admin* against a node.
//!   Verifies against the admin's pubkey. Implicitly revokes every agent
//!   attested by that node, because the JWT verifier's lookup table filters
//!   revoked nodes out.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// Revokes an agent. Issued by the node that originally attested the agent.
/// Once a verifier sees this revocation, any JWT signed by `agent_pubkey` is
/// rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRevocation {
    /// The node that revoked the agent — must match the `node_pubkey` of the
    /// agent's original `AgentAttestation`.
    pub node_pubkey: [u8; 32],
    /// The agent's signing pubkey being revoked.
    pub agent_pubkey: [u8; 32],
    /// Human-readable reason (logged, displayed in audit UI).
    pub reason: String,
    /// Unix nanoseconds at which the revocation was issued.
    pub revoked_at_ns: u64,
    /// Ed25519 signature over [`AgentRevocation::signing_bytes`] using the
    /// node's private key.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct AgentRevocationSigningPayload<'a> {
    node_pubkey: &'a [u8; 32],
    agent_pubkey: &'a [u8; 32],
    reason: &'a str,
    revoked_at_ns: u64,
}

impl AgentRevocation {
    /// Compute the canonical bytes that the node signs.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = AgentRevocationSigningPayload {
            node_pubkey: &self.node_pubkey,
            agent_pubkey: &self.agent_pubkey,
            reason: &self.reason,
            revoked_at_ns: self.revoked_at_ns,
        };
        crate::domain_sign(b"memvault/sig/agent-revocation/v1", &payload)
    }

    /// Verify the revocation signature against the issuing node's pubkey.
    pub fn verify_signature(&self) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        let pubkey = VerifyingKey::from_bytes(&self.node_pubkey)
            .map_err(|_| AuthError::SignatureInvalid)?;
        pubkey
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}

/// Build and sign an [`AgentRevocation`] with the issuing node's key.
pub fn sign_agent_revocation(
    node_key: &SigningKey,
    agent_pubkey: [u8; 32],
    reason: impl Into<String>,
) -> Result<AgentRevocation> {
    let revoked_at_ns = now_ns();
    let mut rev = AgentRevocation {
        node_pubkey: node_key.verifying_key().to_bytes(),
        agent_pubkey,
        reason: reason.into(),
        revoked_at_ns,
        signature: [0u8; 64],
    };
    let bytes = rev.signing_bytes()?;
    rev.signature = node_key.sign(&bytes).to_bytes();
    Ok(rev)
}

/// Revokes a node. Issued by the cluster admin. Once observed, the JWT
/// verifier removes the node from its trust table, transitively invalidating
/// every agent that node ever attested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRevocation {
    /// The admin pubkey that issued the revocation.
    pub admin_pubkey: [u8; 32],
    /// The node pubkey being revoked.
    pub node_pubkey: [u8; 32],
    /// Human-readable reason.
    pub reason: String,
    /// Unix nanoseconds at which the revocation was issued.
    pub revoked_at_ns: u64,
    /// Ed25519 signature over [`NodeRevocation::signing_bytes`] using the
    /// admin's private key.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct NodeRevocationSigningPayload<'a> {
    admin_pubkey: &'a [u8; 32],
    node_pubkey: &'a [u8; 32],
    reason: &'a str,
    revoked_at_ns: u64,
}

impl NodeRevocation {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = NodeRevocationSigningPayload {
            admin_pubkey: &self.admin_pubkey,
            node_pubkey: &self.node_pubkey,
            reason: &self.reason,
            revoked_at_ns: self.revoked_at_ns,
        };
        crate::domain_sign(b"memvault/sig/node-revocation/v1", &payload)
    }

    /// Verify the revocation signature against the embedded admin pubkey.
    /// Caller is responsible for confirming `admin_pubkey` is the current
    /// cluster admin.
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

/// Build and sign a [`NodeRevocation`] with the admin key.
pub fn sign_node_revocation(
    admin_key: &SigningKey,
    node_pubkey: [u8; 32],
    reason: impl Into<String>,
) -> Result<NodeRevocation> {
    let mut rev = NodeRevocation {
        admin_pubkey: admin_key.verifying_key().to_bytes(),
        node_pubkey,
        reason: reason.into(),
        revoked_at_ns: now_ns(),
        signature: [0u8; 64],
    };
    let bytes = rev.signing_bytes()?;
    rev.signature = admin_key.sign(&bytes).to_bytes();
    Ok(rev)
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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
        let agent_pk = make_key().verifying_key().to_bytes();
        let rev = sign_agent_revocation(&node, agent_pk, "key compromise").unwrap();
        assert_eq!(rev.node_pubkey, node.verifying_key().to_bytes());
        assert_eq!(rev.agent_pubkey, agent_pk);
        rev.verify_signature().unwrap();
    }

    #[test]
    fn rejects_tampered_agent_pubkey() {
        let node = make_key();
        let agent_pk = make_key().verifying_key().to_bytes();
        let mut rev = sign_agent_revocation(&node, agent_pk, "reason").unwrap();
        rev.agent_pubkey = make_key().verifying_key().to_bytes();
        assert!(rev.verify_signature().is_err());
    }

    #[test]
    fn rejects_tampered_reason() {
        let node = make_key();
        let agent_pk = make_key().verifying_key().to_bytes();
        let mut rev = sign_agent_revocation(&node, agent_pk, "real reason").unwrap();
        rev.reason = "fake reason".into();
        assert!(rev.verify_signature().is_err());
    }

    #[test]
    fn node_revocation_roundtrip() {
        let admin = make_key();
        let node_pk = make_key().verifying_key().to_bytes();
        let rev = sign_node_revocation(&admin, node_pk, "compromised").unwrap();
        assert_eq!(rev.admin_pubkey, admin.verifying_key().to_bytes());
        assert_eq!(rev.node_pubkey, node_pk);
        rev.verify_signature().unwrap();
    }

    #[test]
    fn node_revocation_rejects_tampering() {
        let admin = make_key();
        let node_pk = make_key().verifying_key().to_bytes();
        let mut rev = sign_node_revocation(&admin, node_pk, "ok").unwrap();
        rev.node_pubkey = make_key().verifying_key().to_bytes();
        assert!(rev.verify_signature().is_err());
    }
}
