use cid::Cid;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use memvault_core::{AgentName, BucketId, ClusterId, PeerId};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// Records the enrollment of an agent into a cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollment {
    pub agent_id: AgentName,
    pub public_key: [u8; 32],
    pub cluster_id: ClusterId,
    pub enrolled_by: PeerId,
    pub initial_grants: Vec<Cid>,
    /// The bucket the agent writes to when no bucket is specified.
    /// Defaults to the cluster's default bucket if not set.
    /// Added in B2. Old enrollments deserialize with None via #[serde(default)].
    #[serde(default)]
    pub default_bucket: Option<BucketId>,
    pub not_after_ns: u64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct EnrollmentSigningPayload<'a> {
    agent_id: &'a AgentName,
    public_key: &'a [u8; 32],
    cluster_id: &'a ClusterId,
    enrolled_by: &'a PeerId,
    initial_grants: &'a [Cid],
    default_bucket: &'a Option<BucketId>,
    not_after_ns: u64,
}

impl AgentEnrollment {
    /// Compute the bytes that are signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = EnrollmentSigningPayload {
            agent_id: &self.agent_id,
            public_key: &self.public_key,
            cluster_id: &self.cluster_id,
            enrolled_by: &self.enrolled_by,
            initial_grants: &self.initial_grants,
            default_bucket: &self.default_bucket,
            not_after_ns: self.not_after_ns,
        };
        crate::domain_sign(b"memvault/sig/agent-enrollment/v1", &payload)
    }

    /// Verify the enrollment signature against the enrolling peer's key.
    pub fn verify_signature(&self, enrolling_key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        enrolling_key
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}
