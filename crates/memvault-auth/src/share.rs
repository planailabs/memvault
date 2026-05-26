//! Cross-cluster bucket sharing types: proposals, replies, and trust records.

use cid::Cid;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use memvault_core::{AgentId, BucketId, ClusterId, PeerId};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};
use crate::grant::Action;

/// A proposal to share a bucket with another cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProposal {
    pub proposal_id: [u8; 16],
    pub from_cluster: ClusterId,
    pub from_bucket: BucketId,
    pub from_admin: PeerId,
    pub to_cluster: ClusterId,
    pub to_recipient: ShareRecipient,
    pub proposed_actions: Vec<Action>,
    pub purpose: String,
    pub not_after_ns: u64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Who can approve a share proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShareRecipient {
    /// Any peer in the target cluster holding Action::Admin.
    AnyAdmin,
    /// A specific agent must approve.
    Agent(AgentId),
}

/// A decision on a share proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShareDecision {
    Approve {
        granted_actions: Vec<Action>,
        not_after_ns: u64,
    },
    Reject {
        reason: String,
    },
}

/// A reply to a share proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareReply {
    pub proposal_id: [u8; 16],
    pub from_cluster: ClusterId,
    pub by_principal: PeerId,
    pub decision: ShareDecision,
    pub decided_at_ns: u64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// A trust record issued after approval — opens federation reads on a bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketTrust {
    pub bucket_id: BucketId,
    pub from_cluster: ClusterId,
    pub to_cluster: ClusterId,
    pub actions: Vec<Action>,
    pub not_after_ns: u64,
    pub from_proposal: Cid,
    pub from_reply: Cid,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

// ── Signing/verification ─────────────────────────────────────────

#[derive(Serialize)]
struct ProposalSigningPayload<'a> {
    proposal_id: &'a [u8; 16],
    from_cluster: &'a ClusterId,
    from_bucket: &'a BucketId,
    from_admin: &'a PeerId,
    to_cluster: &'a ClusterId,
    to_recipient: &'a ShareRecipient,
    proposed_actions: &'a [Action],
    purpose: &'a str,
    not_after_ns: u64,
}

impl ShareProposal {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = ProposalSigningPayload {
            proposal_id: &self.proposal_id,
            from_cluster: &self.from_cluster,
            from_bucket: &self.from_bucket,
            from_admin: &self.from_admin,
            to_cluster: &self.to_cluster,
            to_recipient: &self.to_recipient,
            proposed_actions: &self.proposed_actions,
            purpose: &self.purpose,
            not_after_ns: self.not_after_ns,
        };
        serde_ipld_dagcbor::to_vec(&payload).map_err(|e| AuthError::Codec(e.to_string()))
    }

    pub fn verify_signature(&self, admin_key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        admin_key
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self> {
        let bytes = self.signing_bytes()?;
        let sig = key.sign(&bytes);
        self.signature = sig.to_bytes();
        Ok(self)
    }
}

#[derive(Serialize)]
struct ReplySigningPayload<'a> {
    proposal_id: &'a [u8; 16],
    from_cluster: &'a ClusterId,
    by_principal: &'a PeerId,
    decision: &'a ShareDecision,
    decided_at_ns: u64,
}

impl ShareReply {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = ReplySigningPayload {
            proposal_id: &self.proposal_id,
            from_cluster: &self.from_cluster,
            by_principal: &self.by_principal,
            decision: &self.decision,
            decided_at_ns: self.decided_at_ns,
        };
        serde_ipld_dagcbor::to_vec(&payload).map_err(|e| AuthError::Codec(e.to_string()))
    }

    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self> {
        let bytes = self.signing_bytes()?;
        let sig = key.sign(&bytes);
        self.signature = sig.to_bytes();
        Ok(self)
    }
}

#[derive(Serialize)]
struct TrustSigningPayload<'a> {
    bucket_id: &'a BucketId,
    from_cluster: &'a ClusterId,
    to_cluster: &'a ClusterId,
    actions: &'a [Action],
    not_after_ns: u64,
    from_proposal: &'a Cid,
    from_reply: &'a Cid,
}

impl BucketTrust {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = TrustSigningPayload {
            bucket_id: &self.bucket_id,
            from_cluster: &self.from_cluster,
            to_cluster: &self.to_cluster,
            actions: &self.actions,
            not_after_ns: self.not_after_ns,
            from_proposal: &self.from_proposal,
            from_reply: &self.from_reply,
        };
        serde_ipld_dagcbor::to_vec(&payload).map_err(|e| AuthError::Codec(e.to_string()))
    }

    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self> {
        let bytes = self.signing_bytes()?;
        let sig = key.sign(&bytes);
        self.signature = sig.to_bytes();
        Ok(self)
    }

    /// Check whether this trust is still valid at the given time.
    pub fn is_valid_at(&self, now_ns: u64) -> bool {
        now_ns <= self.not_after_ns
    }
}

/// Status of a share proposal in the outbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShareStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> (SigningKey, VerifyingKey) {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn proposal_sign_verify() {
        let (sk, vk) = make_key();
        let proposal = ShareProposal {
            proposal_id: [1u8; 16],
            from_cluster: ClusterId::random(),
            from_bucket: BucketId::random(),
            from_admin: PeerId(vk.as_bytes().to_vec()),
            to_cluster: ClusterId::random(),
            to_recipient: ShareRecipient::AnyAdmin,
            proposed_actions: vec![Action::Read],
            purpose: "test share".into(),
            not_after_ns: u64::MAX,
            signature: [0u8; 64],
        }
        .sign(&sk)
        .unwrap();

        proposal.verify_signature(&vk).unwrap();
    }

    #[test]
    fn reply_sign_verify() {
        let (sk, vk) = make_key();
        let reply = ShareReply {
            proposal_id: [2u8; 16],
            from_cluster: ClusterId::random(),
            by_principal: PeerId(vk.as_bytes().to_vec()),
            decision: ShareDecision::Approve {
                granted_actions: vec![Action::Read],
                not_after_ns: u64::MAX,
            },
            decided_at_ns: 1000,
            signature: [0u8; 64],
        }
        .sign(&sk)
        .unwrap();

        reply.verify_signature(&vk).unwrap();
    }

    #[test]
    fn trust_sign_verify() {
        let (sk, vk) = make_key();
        let trust = BucketTrust {
            bucket_id: BucketId::random(),
            from_cluster: ClusterId::random(),
            to_cluster: ClusterId::random(),
            actions: vec![Action::Read],
            not_after_ns: u64::MAX,
            from_proposal: memvault_core::cid_from_bytes(b"proposal"),
            from_reply: memvault_core::cid_from_bytes(b"reply"),
            signature: [0u8; 64],
        }
        .sign(&sk)
        .unwrap();

        trust.verify_signature(&vk).unwrap();
        assert!(trust.is_valid_at(1000));
    }
}
