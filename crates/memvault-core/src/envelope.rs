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
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
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

impl<T: Serialize + for<'de> Deserialize<'de>> Signed<T> {
    /// Create and sign a new envelope.
    ///
    /// When `bucket_id` is `Some`, the envelope uses version 2 (bucket-aware signing payload).
    /// When `None`, version 1 is used (byte-identical to pre-bucket envelopes).
    pub fn sign(
        payload: T,
        signing_key: &SigningKey,
        author: PeerId,
        causal: Vec<Cid>,
        provenance: Vec<Cid>,
        tags: Vec<Tag>,
        visibility: Visibility,
        lamport: u64,
        wall_ns: u64,
        capability: Option<Cid>,
        bucket_id: Option<BucketId>,
    ) -> Result<Self> {
        let version = if bucket_id.is_some() { 2 } else { 1 };

        let bytes = if version == 1 {
            codec::encode(&SigningPayloadV1 {
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
            })?
        } else {
            codec::encode(&SigningPayloadV2 {
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
            })?
        };

        let sig = signing_key.sign(&bytes);

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
            signature: sig.to_bytes().to_vec(),
        })
    }

    /// Verify the signature against the provided verifying key.
    ///
    /// V1 envelopes use the v1 signing payload (no bucket_id).
    /// V2 envelopes use the v2 signing payload (includes bucket_id).
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let bytes = match self.version {
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
            })?,
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
            })?,
            _ => {
                tracing::warn!(
                    version = self.version,
                    "unknown envelope version, skipping signature verification"
                );
                return Ok(());
            }
        };

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
        )
        .unwrap();

        assert_eq!(v1.version, 1);
        assert_eq!(v2.version, 2);
        assert_ne!(v1.cid().unwrap(), v2.cid().unwrap());
    }
}
