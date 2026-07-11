//! Canonical view over an envelope block.
//!
//! Memvault envelopes come in two structural shapes today:
//!
//! - **Legacy raw-JSON**: kind-specific fields (`kind`, `target`,
//!   `manifest_cid`, `data`, …) live at the top level alongside
//!   `author`, `tags`, `wall_ns`, etc.
//! - **Signed<T> v3**: the kind-specific content lives inside a
//!   `payload` sub-object; envelope-level fields (author, tags, etc.)
//!   stay at the top level.
//!
//! Readers used to walk these shapes by hand and forget the second
//! one — leading to "file attached" envelopes that wrote successfully
//! but never showed up in the UI. [`EnvelopeView`] normalises lookup
//! so every field-access call resolves the canonical value regardless
//! of which shape produced the block.

use serde_json::Value;

/// Parsed envelope block. Owns the deserialised [`Value`] and offers
/// look-ups that fall back from the top level into `payload`.
#[derive(Debug, Clone)]
pub struct EnvelopeView {
    raw: Value,
}

impl EnvelopeView {
    /// Parse a raw block (JSON or DAG-CBOR; detected by first byte).
    /// Returns `None` for non-object bodies — those are token / sigchain
    /// blocks the envelope view doesn't try to interpret.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let raw = crate::insert::deserialize_block(bytes)?;
        if !raw.is_object() {
            return None;
        }
        Some(Self { raw })
    }

    /// Wrap an already-deserialised [`Value`] — same fall-back rules,
    /// no extra decoding. Useful when the caller already has the
    /// parsed body in hand.
    pub fn from_value(raw: Value) -> Option<Self> {
        if !raw.is_object() {
            return None;
        }
        Some(Self { raw })
    }

    /// Field lookup with fall-back into `payload`. Top-level wins; for
    /// Signed<T> envelopes the kind-specific fields are nested one
    /// level deeper, so the `payload` arm reaches them transparently.
    pub fn field(&self, name: &str) -> Option<&Value> {
        if let Some(v) = self.raw.get(name) {
            // Skip nulls so callers that defaulted a field to `null`
            // still get the payload fallback.
            if !v.is_null() {
                return Some(v);
            }
        }
        self.raw
            .get("payload")
            .and_then(|p| p.get(name))
            .filter(|v| !v.is_null())
    }

    /// Borrow the inner [`Value`] when a caller genuinely needs to
    /// walk the whole block (e.g. parse_audit_record for op_kind
    /// detection inside `payload`).
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// Borrow the `payload` sub-object, if present. Returns `None`
    /// for legacy raw-JSON envelopes that have no payload nesting.
    pub fn payload(&self) -> Option<&Value> {
        self.raw.get("payload")
    }

    /// Decode a field into an owned `T`. Returns `None` when the
    /// field is absent or doesn't deserialise to `T`.
    pub fn get_as<T: serde::de::DeserializeOwned>(&self, name: &str) -> Option<T> {
        self.field(name)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// String accessor for `kind`-style discriminator fields.
    pub fn str_field(&self, name: &str) -> Option<&str> {
        self.field(name).and_then(|v| v.as_str())
    }

    /// Top-level `author` bytes as the envelope was written. With
    /// Signed<T> this is the node pubkey; with legacy envelopes it
    /// matches `effective_author()` at write time.
    pub fn author(&self) -> Vec<u8> {
        self.get_as("author").unwrap_or_default()
    }

    /// CID of the AgentAttestation covering the agent that authored
    /// this envelope, when present (Signed<T> v3 envelopes).
    pub fn agent_attestation_cid(&self) -> Option<Vec<u8>> {
        self.get_as("agent_attestation")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_kind_at_top_level() {
        let v = json!({
            "kind": "annotation",
            "target": "doc:abc",
            "wall_ns": 42_u64,
        });
        let view = EnvelopeView::from_value(v).unwrap();
        assert_eq!(view.str_field("kind"), Some("annotation"));
        assert_eq!(view.str_field("target"), Some("doc:abc"));
    }

    #[test]
    fn signed_payload_nested_kind() {
        let v = json!({
            "version": 3,
            "payload": {
                "kind": "attachment",
                "manifest_cid": [1, 2, 3, 4],
                "filename": "x.txt",
            },
            "author": [9, 9, 9],
            "wall_ns": 100_u64,
        });
        let view = EnvelopeView::from_value(v).unwrap();
        assert_eq!(view.str_field("kind"), Some("attachment"));
        assert_eq!(view.str_field("filename"), Some("x.txt"));
        assert_eq!(
            view.get_as::<Vec<u8>>("manifest_cid"),
            Some(vec![1, 2, 3, 4])
        );
        assert_eq!(view.author(), vec![9, 9, 9]);
    }

    #[test]
    fn top_level_wins_when_both_present() {
        let v = json!({
            "kind": "top",
            "payload": { "kind": "nested" },
        });
        let view = EnvelopeView::from_value(v).unwrap();
        assert_eq!(view.str_field("kind"), Some("top"));
    }

    #[test]
    fn null_top_level_falls_through_to_payload() {
        let v = json!({
            "kind": serde_json::Value::Null,
            "payload": { "kind": "nested" },
        });
        let view = EnvelopeView::from_value(v).unwrap();
        assert_eq!(view.str_field("kind"), Some("nested"));
    }

    #[test]
    fn non_object_bodies_rejected() {
        let v = json!([1, 2, 3]);
        assert!(EnvelopeView::from_value(v).is_none());
    }
}
