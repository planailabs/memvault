//! Sidecar block: who signed off on a given envelope.
//!
//! An envelope's `author` field (peer ID) only tells you which *node* wrote
//! the block — not which *agent* the operation was attributed to. The
//! authorship block fixes that:
//!
//! ```text
//! EnvelopeAuthorship {
//!   envelope_cid: <CID of the envelope being co-signed>
//!   agent_pubkey: <agent's ed25519 pubkey>
//!   signature:    Ed25519(agent_sk, envelope_cid)
//! }
//! ```
//!
//! Published as a separate block (tagged `sigchain/envelope_auth`) so the
//! envelope's CID is unaffected and existing readers continue to work. The
//! authorship block rides on RBSR sync alongside the envelope; the verifier
//! looks it up by envelope CID at read time.
//!
//! Trust chain on read: `agent_pubkey` must appear in a known
//! [`crate::AgentAttestation`] (issued by a trusted node, per the JWT lookup
//! table), and must not be in the revoked-agents set.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// Authorship attestation co-signed by the operating agent for a particular
/// envelope CID. Stored as a sidecar block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeAuthorship {
    /// The CID of the envelope this authorship attestation refers to.
    pub envelope_cid: Vec<u8>,
    /// The agent's signing pubkey. Must chain back to a trusted node via
    /// [`crate::AgentAttestation`].
    pub agent_pubkey: [u8; 32],
    /// Ed25519 signature over [`EnvelopeAuthorship::signing_bytes`] using the
    /// agent's private key.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct EnvelopeAuthorshipSigningPayload<'a> {
    envelope_cid: &'a [u8],
    agent_pubkey: &'a [u8; 32],
}

impl EnvelopeAuthorship {
    /// Canonical bytes the agent signs. Just the CID + pubkey — the signature
    /// itself is excluded.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = EnvelopeAuthorshipSigningPayload {
            envelope_cid: &self.envelope_cid,
            agent_pubkey: &self.agent_pubkey,
        };
        serde_ipld_dagcbor::to_vec(&payload).map_err(|e| AuthError::Codec(e.to_string()))
    }

    /// Verify the agent's signature over (envelope_cid, agent_pubkey).
    ///
    /// **Does not** check that the agent is currently trusted — the caller
    /// must additionally verify `agent_pubkey` is attested and not revoked.
    pub fn verify_signature(&self) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        let pubkey = VerifyingKey::from_bytes(&self.agent_pubkey)
            .map_err(|_| AuthError::SignatureInvalid)?;
        pubkey
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}

/// Build and sign an [`EnvelopeAuthorship`] with the agent's key.
pub fn sign_envelope_authorship(
    agent_key: &SigningKey,
    envelope_cid: Vec<u8>,
) -> Result<EnvelopeAuthorship> {
    let mut auth = EnvelopeAuthorship {
        envelope_cid,
        agent_pubkey: agent_key.verifying_key().to_bytes(),
        signature: [0u8; 64],
    };
    let bytes = auth.signing_bytes()?;
    auth.signature = agent_key.sign(&bytes).to_bytes();
    Ok(auth)
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
        let agent = make_key();
        let cid = b"cid-bytes-here".to_vec();
        let auth = sign_envelope_authorship(&agent, cid.clone()).unwrap();
        assert_eq!(auth.envelope_cid, cid);
        assert_eq!(auth.agent_pubkey, agent.verifying_key().to_bytes());
        auth.verify_signature().unwrap();
    }

    #[test]
    fn rejects_tampered_cid() {
        let agent = make_key();
        let mut auth = sign_envelope_authorship(&agent, b"original".to_vec()).unwrap();
        auth.envelope_cid = b"tampered".to_vec();
        assert!(auth.verify_signature().is_err());
    }

    #[test]
    fn rejects_tampered_pubkey() {
        let agent = make_key();
        let imposter = make_key();
        let mut auth = sign_envelope_authorship(&agent, b"cid".to_vec()).unwrap();
        auth.agent_pubkey = imposter.verifying_key().to_bytes();
        assert!(auth.verify_signature().is_err());
    }
}
