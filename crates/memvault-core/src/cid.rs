use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::error::{Error, Result};

/// Multicodec identifiers for CID content types.
pub mod codec {
    pub const RAW: u64 = 0x55;
    pub const DAG_PB: u64 = 0x70;
    pub const DAG_CBOR: u64 = 0x71;
    pub const DAG_JSON: u64 = 0x0129;
}

/// Compute a CID from raw bytes using BLAKE3 hash and DAG-CBOR codec.
/// Use [`cid_with_codec`] when the content is not DAG-CBOR.
pub fn cid_from_bytes(data: &[u8]) -> Cid {
    cid_with_codec(data, codec::DAG_CBOR)
}

/// Compute a CID from raw bytes with an explicit multicodec.
pub fn cid_with_codec(data: &[u8], multicodec: u64) -> Cid {
    let hash = Code::Blake3_256.digest(data);
    Cid::new_v1(multicodec, hash)
}

/// Compute a CID from a serializable value (encodes to DAG-CBOR first).
pub fn cid_from_value<T: serde::Serialize>(value: &T) -> Result<Cid> {
    let bytes = crate::codec::encode(value)?;
    Ok(cid_from_bytes(&bytes))
}

/// Encode a CID to its base58btc string representation.
pub fn cid_to_string(cid: &Cid) -> String {
    cid.to_string()
}

/// Parse a CID from a string.
pub fn cid_from_string(s: &str) -> Result<Cid> {
    s.parse::<Cid>().map_err(|e| Error::Cid(e.to_string()))
}

/// Verify that a CID's hash matches the given data.
///
/// Parses the CID from bytes, extracts the hash algorithm from the
/// embedded multihash, recomputes the digest over `data`, and compares.
/// Supports all hash algorithms in `multihash-codetable` (Blake3, SHA2-256, etc.).
///
/// Returns `Ok(true)` if valid, `Ok(false)` if the digest doesn't match,
/// `Err` if the CID can't be parsed or the hash algorithm is unsupported.
pub fn verify_cid(cid_bytes: &[u8], data: &[u8]) -> Result<bool> {
    let cid = Cid::read_bytes(std::io::Cursor::new(cid_bytes))
        .map_err(|e| Error::Cid(format!("cannot parse CID: {e}")))?;
    let hash_code = cid.hash().code();
    let code = Code::try_from(hash_code)
        .map_err(|_| Error::Cid(format!("unsupported hash algorithm: 0x{hash_code:x}")))?;
    let expected = code.digest(data);
    Ok(cid.hash() == &expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_cid() {
        let data = b"hello memvault";
        let c1 = cid_from_bytes(data);
        let c2 = cid_from_bytes(data);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_data_different_cid() {
        let c1 = cid_from_bytes(b"aaa");
        let c2 = cid_from_bytes(b"bbb");
        assert_ne!(c1, c2);
    }

    #[test]
    fn string_roundtrip() {
        let c = cid_from_bytes(b"test");
        let s = cid_to_string(&c);
        let parsed = cid_from_string(&s).unwrap();
        assert_eq!(c, parsed);
    }

    #[test]
    fn verify_cid_handles_any_codec_and_hash() {
        // Attachment/file chunks are raw codec (0x55) + SHA2-256 (0x12), NOT
        // the Blake3/DAG-CBOR scheme of `cid_from_bytes`. Sync-ingress
        // integrity must verify against the CID's *own* algorithm, else every
        // such chunk is wrongly dropped (regression: the swarm check used
        // cid_from_bytes and dropped all raw/sha256 blocks).
        let data = b"file chunk bytes";
        let sha_raw = Cid::new_v1(codec::RAW, Code::Sha2_256.digest(data));
        let sha_raw_bytes = sha_raw.to_bytes();
        assert!(sha_raw_bytes.starts_with(&[0x01, 0x55, 0x12, 0x20]), "raw+sha256 prefix");
        assert!(verify_cid(&sha_raw_bytes, data).unwrap(), "raw/sha256 chunk verifies");
        assert!(!verify_cid(&sha_raw_bytes, b"tampered").unwrap(), "tampered rejected");

        // The default Blake3/DAG-CBOR envelope path still verifies.
        let blake = cid_from_bytes(data);
        assert!(verify_cid(&blake.to_bytes(), data).unwrap());
        assert!(!verify_cid(&blake.to_bytes(), b"other").unwrap());
    }
}
