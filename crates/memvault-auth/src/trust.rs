use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use memvault_core::ClusterId;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// Records trust in another cluster for federation purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterTrust {
    pub cluster_id: ClusterId,
    pub trusted_admin_keys: Vec<[u8; 32]>,
    pub federated_since_ns: u64,
    pub not_after_ns: u64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct TrustSigningPayload<'a> {
    cluster_id: &'a ClusterId,
    trusted_admin_keys: &'a [[u8; 32]],
    federated_since_ns: u64,
    not_after_ns: u64,
}

impl ClusterTrust {
    /// Compute the bytes that are signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = TrustSigningPayload {
            cluster_id: &self.cluster_id,
            trusted_admin_keys: &self.trusted_admin_keys,
            federated_since_ns: self.federated_since_ns,
            not_after_ns: self.not_after_ns,
        };
        serde_ipld_dagcbor::to_vec(&payload).map_err(|e| AuthError::Codec(e.to_string()))
    }

    /// Verify the trust record signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}
