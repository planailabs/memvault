//! Wire encoding helpers — the single place that turns memvault's byte-newtype
//! IDs into the hex strings used on the wire.
//!
//! See `standards/` (api-wire-conventions.md, wire-dtos.md). The rule: a domain
//! type has one wire shape, transmitted with `serde`; IDs are hex strings,
//! never raw `[u8; 32]` JSON arrays. Core ID types and graph block types keep
//! their byte `serde` (load-bearing for dag-cbor CIDs), so API return types
//! carry these `#[serde(with = "…")]` helpers on their ID fields instead.
//!
//! Usage:
//! ```ignore
//! #[serde(with = "crate::wire::hex_id")]            id: BucketId,
//! #[serde(with = "crate::wire::hex_id_opt", default)] cluster_id: Option<ClusterId>,
//! #[serde(with = "crate::wire::hex_array32_opt", default)] pubkey: Option<[u8; 32]>,
//! #[serde(with = "crate::wire::hex_bytes")]         cid: Vec<u8>,
//! ```

use memvault_core::{BucketId, ClusterId, DocId, EdgeId, EntityId};
use serde::{Deserialize, Deserializer, Serializer};

/// A 32-byte ID newtype that round-trips through a lowercase hex string.
pub trait HexId: Sized {
    fn id_bytes(&self) -> [u8; 32];
    fn from_id_bytes(bytes: [u8; 32]) -> Self;
}

macro_rules! impl_hex_id {
    ($($t:ty),* $(,)?) => {$(
        impl HexId for $t {
            fn id_bytes(&self) -> [u8; 32] { self.0 }
            fn from_id_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
        }
    )*};
}
impl_hex_id!(BucketId, ClusterId, DocId, EdgeId, EntityId);

fn decode_32<E: serde::de::Error>(s: &str) -> Result<[u8; 32], E> {
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("expected 32-byte hex id"))
}

/// `#[serde(with = "hex_id")]` for a 32-byte ID newtype.
pub mod hex_id {
    use super::*;

    pub fn serialize<S: Serializer, T: HexId>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.id_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, T: HexId>(d: D) -> Result<T, D::Error> {
        let s = String::deserialize(d)?;
        Ok(T::from_id_bytes(decode_32(&s)?))
    }
}

/// `#[serde(with = "hex_id_opt")]` for `Option<IdNewtype>`.
pub mod hex_id_opt {
    use super::*;

    pub fn serialize<S: Serializer, T: HexId>(v: &Option<T>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(id) => s.serialize_some(&hex::encode(id.id_bytes())),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>, T: HexId>(d: D) -> Result<Option<T>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => Ok(Some(T::from_id_bytes(decode_32(&s)?))),
            None => Ok(None),
        }
    }
}

/// `#[serde(with = "hex_array32_opt")]` for `Option<[u8; 32]>` (e.g. pubkeys).
pub mod hex_array32_opt {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => Ok(Some(decode_32(&s)?)),
            None => Ok(None),
        }
    }
}

/// `#[serde(with = "hex_bytes")]` for `Vec<u8>` (variable-length CIDs/pubkeys).
pub mod hex_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}
