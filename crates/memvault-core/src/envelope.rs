use cid::Cid;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::codec;
use crate::error::{Error, Result};
use crate::ids::{BucketId, PeerId};
use crate::tags::Tag;
use crate::visibility::Visibility;

/// The signed envelope wrapping all memvault data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub version: u8,
    pub payload: T,
    pub author: PeerId,
    pub causal: Vec<Cid>,
    pub provenance: Vec<Cid>,
    pub tags: Vec<Tag>,
    pub visibility: Visibility,
    pub lamport: u64,
    pub wall_ns: u64,
    pub capability: Option<Cid>,
    /// Bucket this envelope belongs to. `None` = unbucketed (legacy).
    /// Present in version 2+ envelopes; absent (deserialized as None) in v1.
    #[serde(default)]
    pub bucket_id: Option<BucketId>,
    /// CID of the `NodeAttestation` covering `author`. Audit pointer to
    /// the attestation that admitted the signing node into the cluster.
    /// Not required for signature verification — `author` is the pubkey
    /// ed25519 uses directly. v3+; absent (None) in v1/v2.
    #[serde(default)]
    pub node_attestation: Option<Vec<u8>>,
    /// CID of the `AgentAttestation` when this envelope was authored on
    /// behalf of an agent. The verifier resolves it via
    /// `trusted_attestations` to get the agent's pubkey, then validates
    /// `agent_signature` against that pubkey. `None` for pure node
    /// writes. v3+.
    #[serde(default)]
    pub agent_attestation: Option<Vec<u8>>,
    /// Ed25519 signature by the **node** over the version-appropriate
    /// signing payload. `#[serde(default)]` so legacy raw-JSON envelopes
    /// (no signature field) deserialize cleanly — readers detect
    /// "no signature" via `signature.is_empty()` and skip verification.
    #[serde(default, with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Optional ed25519 co-signature by the **agent** over the same
    /// signing payload. Populated iff the agent's SK was available at
    /// write time. Verified against the pubkey resolved from
    /// `agent_attestation`. Empty when only the node signed.
    #[serde(default, with = "serde_bytes")]
    pub agent_signature: Vec<u8>,
}

/// V1 signing payload (no bucket_id) — for backwards-compatible signature verification.
#[derive(Serialize)]
struct SigningPayloadV1<'a, T: Serialize> {
    version: u8,
    payload: &'a T,
    author: &'a PeerId,
    causal: &'a [Cid],
    provenance: &'a [Cid],
    tags: &'a [Tag],
    visibility: &'a Visibility,
    lamport: u64,
    wall_ns: u64,
    capability: &'a Option<Cid>,
}

/// V2 signing payload (includes bucket_id) — used when bucket_id is Some.
#[derive(Serialize)]
struct SigningPayloadV2<'a, T: Serialize> {
    version: u8,
    payload: &'a T,
    author: &'a PeerId,
    causal: &'a [Cid],
    provenance: &'a [Cid],
    tags: &'a [Tag],
    visibility: &'a Visibility,
    lamport: u64,
    wall_ns: u64,
    capability: &'a Option<Cid>,
    bucket_id: &'a Option<BucketId>,
}

/// V3 signing payload — used when node_attestation or agent_attestation
/// is set. Both attestation CIDs are committed by the node's signature so
/// they can't be swapped after the fact. The agent's co-signature (when
/// present) signs over the same bytes, binding the agent to the exact
/// node-attributed view of the envelope.
#[derive(Serialize)]
struct SigningPayloadV3<'a, T: Serialize> {
    version: u8,
    payload: &'a T,
    author: &'a PeerId,
    causal: &'a [Cid],
    provenance: &'a [Cid],
    tags: &'a [Tag],
    visibility: &'a Visibility,
    lamport: u64,
    wall_ns: u64,
    capability: &'a Option<Cid>,
    bucket_id: &'a Option<BucketId>,
    node_attestation: &'a Option<Vec<u8>>,
    agent_attestation: &'a Option<Vec<u8>>,
}

impl<T: Serialize + for<'de> Deserialize<'de>> Signed<T> {
    /// Create and sign a new envelope.
    ///
    /// `node_signing_key` always signs. When `agent_signing_key` is
    /// `Some`, the agent additionally co-signs the same payload bytes,
    /// producing `agent_signature`.
    ///
    /// Version selection (highest applicable):
    /// - v3: any of `node_attestation` or `agent_attestation` is `Some`
    ///       (attestation-aware write — new format).
    /// - v2: `bucket_id` is `Some` (bucket-aware, no attestations).
    /// - v1: legacy byte-identical to pre-bucket envelopes.
    ///
    /// `author` must match `node_signing_key.verifying_key()` so
    /// `verify()` accepts. Likewise the pubkey resolved from
    /// `agent_attestation` must match `agent_signing_key` for
    /// `verify_agent()` to accept.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        payload: T,
        node_signing_key: &SigningKey,
        author: PeerId,
        causal: Vec<Cid>,
        provenance: Vec<Cid>,
        tags: Vec<Tag>,
        visibility: Visibility,
        lamport: u64,
        wall_ns: u64,
        capability: Option<Cid>,
        bucket_id: Option<BucketId>,
        node_attestation: Option<Vec<u8>>,
        agent_attestation: Option<Vec<u8>>,
        agent_signing_key: Option<&SigningKey>,
    ) -> Result<Self> {
        let version: u8 = if node_attestation.is_some() || agent_attestation.is_some() {
            3
        } else if bucket_id.is_some() {
            2
        } else {
            1
        };

        let bytes = match version {
            1 => codec::encode(&SigningPayloadV1 {
                version: 1,
                payload: &payload,
                author: &author,
                causal: &causal,
                provenance: &provenance,
                tags: &tags,
                visibility: &visibility,
                lamport,
                wall_ns,
                capability: &capability,
            })?,
            2 => codec::encode(&SigningPayloadV2 {
                version: 2,
                payload: &payload,
                author: &author,
                causal: &causal,
                provenance: &provenance,
                tags: &tags,
                visibility: &visibility,
                lamport,
                wall_ns,
                capability: &capability,
                bucket_id: &bucket_id,
            })?,
            _ => codec::encode(&SigningPayloadV3 {
                version: 3,
                payload: &payload,
                author: &author,
                causal: &causal,
                provenance: &provenance,
                tags: &tags,
                visibility: &visibility,
                lamport,
                wall_ns,
                capability: &capability,
                bucket_id: &bucket_id,
                node_attestation: &node_attestation,
                agent_attestation: &agent_attestation,
            })?,
        };

        let sig = node_signing_key.sign(&bytes);
        let agent_signature = match agent_signing_key {
            Some(sk) => sk.sign(&bytes).to_bytes().to_vec(),
            None => Vec::new(),
        };

        Ok(Self {
            version,
            payload,
            author,
            causal,
            provenance,
            tags,
            visibility,
            lamport,
            wall_ns,
            capability,
            bucket_id,
            node_attestation,
            agent_attestation,
            signature: sig.to_bytes().to_vec(),
            agent_signature,
        })
    }

    /// Verify the agent's co-signature against the given pubkey. Returns
    /// `Ok(())` only if `agent_signature` is present and validates.
    /// `Err(SignatureInvalid)` when the agent_signature is empty (no
    /// co-signature was attached) or the bytes don't verify.
    ///
    /// Callers resolve the pubkey via `agent_attestation` →
    /// `trusted_attestations[cid]` → `agent_pubkey`.
    pub fn verify_agent(&self, agent_verifying_key: &VerifyingKey) -> Result<()> {
        if self.agent_signature.is_empty() {
            return Err(Error::SignatureInvalid);
        }
        let bytes = self.signing_payload_bytes()?;
        let sig_bytes: [u8; 64] = self
            .agent_signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::SignatureInvalid)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        agent_verifying_key
            .verify(&bytes, &sig)
            .map_err(|_| Error::SignatureInvalid)
    }

    /// Encode the version-appropriate signing payload bytes — the same
    /// bytes both the node's `signature` and the agent's `agent_signature`
    /// cover. Returns the v1/v2/v3 payload matching `self.version`.
    fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        match self.version {
            1 => codec::encode(&SigningPayloadV1 {
                version: self.version,
                payload: &self.payload,
                author: &self.author,
                causal: &self.causal,
                provenance: &self.provenance,
                tags: &self.tags,
                visibility: &self.visibility,
                lamport: self.lamport,
                wall_ns: self.wall_ns,
                capability: &self.capability,
            }),
            2 => codec::encode(&SigningPayloadV2 {
                version: self.version,
                payload: &self.payload,
                author: &self.author,
                causal: &self.causal,
                provenance: &self.provenance,
                tags: &self.tags,
                visibility: &self.visibility,
                lamport: self.lamport,
                wall_ns: self.wall_ns,
                capability: &self.capability,
                bucket_id: &self.bucket_id,
            }),
            _ => codec::encode(&SigningPayloadV3 {
                version: self.version,
                payload: &self.payload,
                author: &self.author,
                causal: &self.causal,
                provenance: &self.provenance,
                tags: &self.tags,
                visibility: &self.visibility,
                lamport: self.lamport,
                wall_ns: self.wall_ns,
                capability: &self.capability,
                bucket_id: &self.bucket_id,
                node_attestation: &self.node_attestation,
                agent_attestation: &self.agent_attestation,
            }),
        }
    }

    /// Verify the **node**'s signature against the provided verifying key.
    /// Use [`Self::verify_agent`] separately for the agent co-signature.
    ///
    /// V1 — v1 signing payload (no bucket_id).
    /// V2 — v2 signing payload (includes bucket_id).
    /// V3 — v3 signing payload (also includes node_attestation +
    ///      agent_attestation).
    ///
    /// Unknown versions are skipped (logged) — preserves forward
    /// compatibility for unknown future shapes.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        if self.version > 3 {
            tracing::warn!(
                version = self.version,
                "unknown envelope version, skipping signature verification"
            );
            return Ok(());
        }
        let bytes = self.signing_payload_bytes()?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::SignatureInvalid)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&bytes, &sig)
            .map_err(|_| Error::SignatureInvalid)
    }

    /// Compute the CID of this envelope (the full signed structure).
    pub fn cid(&self) -> Result<Cid> {
        let bytes = codec::encode(self)?;
        Ok(crate::cid::cid_from_bytes(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::Tag;

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let envelope = Signed::sign(
            "hello world".to_string(),
            &signing_key,
            PeerId(verifying_key.as_bytes().to_vec()),
            vec![],
            vec![],
            vec![Tag::new("classification", "internal")],
            Visibility::Internal,
            1,
            crate::time::wall_ns(),
            None,
            None, // no bucket (v1)
            None, // no node_attestation
            None, // no agent_attestation
            None, // no agent co-signer
        )
        .unwrap();

        assert!(envelope.verify(&verifying_key).is_ok());
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let mut envelope = Signed::sign(
            "original".to_string(),
            &signing_key,
            PeerId(verifying_key.as_bytes().to_vec()),
            vec![],
            vec![],
            vec![Tag::new("classification", "public")],
            Visibility::Internal,
            1,
            0,
            None,
            None, // no bucket (v1)
            None, // no node_attestation
            None, // no agent_attestation
            None, // no agent co-signer
        )
        .unwrap();

        envelope.payload = "tampered".to_string();
        assert!(envelope.verify(&verifying_key).is_err());
    }

    #[test]
    fn cid_is_deterministic() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let envelope = Signed::sign(
            42u64,
            &signing_key,
            PeerId(verifying_key.as_bytes().to_vec()),
            vec![],
            vec![],
            vec![Tag::new("classification", "confidential")],
            Visibility::Federated,
            5,
            1000,
            None,
            None, // no bucket (v1)
            None, // no node_attestation
            None, // no agent_attestation
            None, // no agent co-signer
        )
        .unwrap();

        let c1 = envelope.cid().unwrap();
        let c2 = envelope.cid().unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn v2_envelope_with_bucket() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let bucket = BucketId::random();
        let envelope = Signed::sign(
            "bucket content".to_string(),
            &signing_key,
            PeerId(verifying_key.as_bytes().to_vec()),
            vec![],
            vec![],
            vec![Tag::new("classification", "internal")],
            Visibility::Internal,
            1,
            crate::time::wall_ns(),
            None,
            Some(bucket.clone()),
            None, // no node_attestation
            None, // no agent_attestation
            None, // no agent co-signer
        )
        .unwrap();

        assert_eq!(envelope.version, 2);
        assert_eq!(envelope.bucket_id, Some(bucket));
        assert!(envelope.verify(&verifying_key).is_ok());
    }

    #[test]
    fn v1_and_v2_have_different_cids() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let author = PeerId(verifying_key.as_bytes().to_vec());
        let tags = vec![Tag::new("classification", "internal")];

        let v1 = Signed::sign(
            "same payload".to_string(),
            &signing_key,
            author.clone(),
            vec![],
            vec![],
            tags.clone(),
            Visibility::Internal,
            1,
            1000,
            None,
            None,
            None, // no node_attestation
            None, // no agent_attestation
            None, // no agent co-signer
        )
        .unwrap();

        let v2 = Signed::sign(
            "same payload".to_string(),
            &signing_key,
            author,
            vec![],
            vec![],
            tags,
            Visibility::Internal,
            1,
            1000,
            None,
            Some(BucketId::random()),
            None, // no node_attestation
            None, // no agent_attestation
            None, // no agent co-signer
        )
        .unwrap();

        assert_eq!(v1.version, 1);
        assert_eq!(v2.version, 2);
        assert_ne!(v1.cid().unwrap(), v2.cid().unwrap());
    }
}
