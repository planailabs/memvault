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

use memvault_core::{BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef};
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

/// `#[serde(with = "hex_bytes")]` for opaque `Vec<u8>` keys (NOT CIDs — use
/// `cid_str` for content identifiers).
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

/// `#[serde(with = "hex_array16")]` for a `[u8; 16]` (e.g. a 16-byte proposal id).
pub mod hex_array16 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 16-byte hex"))
    }
}

/// `#[serde(with = "peer_b58")]` for a `memvault_core::PeerId` — base58btc, the
/// canonical multihash/peer-id string form (matches `PeerId::Display`).
pub mod peer_b58 {
    use super::*;
    use memvault_core::PeerId;

    pub fn serialize<S: Serializer>(v: &PeerId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&memvault_core::b58_encode(&v.0))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PeerId, D::Error> {
        let s = String::deserialize(d)?;
        Ok(PeerId(
            memvault_core::b58_decode(&s).map_err(serde::de::Error::custom)?,
        ))
    }
}

/// `#[serde(with = "b58_bytes")]` for a `Vec<u8>` that holds a peer id /
/// multihash (base58btc canonical string).
pub mod b58_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&memvault_core::b58_encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        memvault_core::b58_decode(&s).map_err(serde::de::Error::custom)
    }
}

/// The canonical CID string for CID bytes (`bafy…`), per
/// `standards/api-wire-conventions.md` §1b. Bytes that are not exactly one
/// CID (a legacy key, a 32-byte doc id) fall back to bare hex, which every
/// CID input accepts too (`memvault_core::cid_bytes_lenient`) — so the value
/// always round-trips to the same bytes.
pub fn cid_string(bytes: &[u8]) -> String {
    memvault_core::parse_cid(bytes)
        .map(|c| c.to_string())
        .unwrap_or_else(|_| hex::encode(bytes))
}

/// `#[serde(with = "cid_str")]` for a `Vec<u8>` that holds **CID bytes**.
///
/// Encodes as the canonical multibase CID string (`bafy…`) via
/// [`cid_string`], per `standards/api-wire-conventions.md` §1b — CIDs are
/// IPLD multihashes, not bare hex. Decodes the CID string or legacy hex.
pub mod cid_str {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&cid_string(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        memvault_core::cid_bytes_lenient(&s).map_err(serde::de::Error::custom)
    }
}

/// `#[serde(with = "cid_str_opt")]` for `Option<Vec<u8>>` CID bytes.
pub mod cid_str_opt {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_some(&cid_string(bytes)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(s) => Ok(Some(
                memvault_core::cid_bytes_lenient(&s).map_err(serde::de::Error::custom)?,
            )),
            None => Ok(None),
        }
    }
}
/// `#[serde(with = "hex_id_lenient_opt")]` for an `Option<IdNewtype>` that is
/// also stored inside blocks: serializes as hex (like [`hex_id_opt`]) and
/// deserializes hex **or** the legacy byte-newtype form (a sequence of 32
/// numbers), so blocks written before the field went hex still load.
pub mod hex_id_lenient_opt {
    use super::*;

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Hex(String),
        Bytes(Vec<u8>),
    }

    pub fn serialize<S: Serializer, T: HexId>(v: &Option<T>, s: S) -> Result<S::Ok, S::Error> {
        super::hex_id_opt::serialize(v, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>, T: HexId>(d: D) -> Result<Option<T>, D::Error> {
        let bytes = match Option::<Raw>::deserialize(d)? {
            None => return Ok(None),
            Some(Raw::Hex(s)) => decode_32(&s)?,
            Some(Raw::Bytes(b)) => b
                .try_into()
                .map_err(|_| serde::de::Error::custom("expected a 32-byte id"))?,
        };
        Ok(Some(T::from_id_bytes(bytes)))
    }
}

/// `#[serde(with = "hex_id_vec")]` for a `Vec<IdNewtype>` (a list of hex ids).
pub mod hex_id_vec {
    use super::*;

    pub fn serialize<S: Serializer, T: HexId>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for id in v {
            seq.serialize_element(&hex::encode(id.id_bytes()))?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>, T: HexId>(d: D) -> Result<Vec<T>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| decode_32(s).map(T::from_id_bytes))
            .collect()
    }
}

/// `#[serde(with = "hex_array32")]` for a `[u8; 32]` (e.g. a pubkey).
pub mod hex_array32 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        decode_32(&String::deserialize(d)?)
    }
}

/// `#[serde(with = "hex_bytes_opt")]` for an opaque `Option<Vec<u8>>` key.
pub mod hex_bytes_opt {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| hex::decode(s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// `#[serde(with = "node_label")]` for a [`NodeRef`]: its `"type:hex"` label
/// (`NodeRef::tag_label` / `NodeRef::from_tag_label`).
pub mod node_label {
    use super::*;

    pub fn serialize<S: Serializer>(v: &NodeRef, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.tag_label())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<NodeRef, D::Error> {
        let s = String::deserialize(d)?;
        NodeRef::from_tag_label(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("not a node label: {s:?}")))
    }
}

/// One step of a traversal path on the wire: `{edge_id, relation}`.
#[derive(serde::Serialize, serde::Deserialize)]
struct PathStepWire {
    #[serde(with = "hex_id")]
    edge_id: EdgeId,
    relation: String,
}

/// `#[serde(with = "edge_path")]` for a traversal path `Vec<(EdgeId, String)>`:
/// `[{edge_id: hex, relation}, …]`.
pub mod edge_path {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[(EdgeId, String)], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for (edge_id, relation) in v {
            seq.serialize_element(&PathStepWire {
                edge_id: edge_id.clone(),
                relation: relation.clone(),
            })?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(EdgeId, String)>, D::Error> {
        Ok(Vec::<PathStepWire>::deserialize(d)?
            .into_iter()
            .map(|s| (s.edge_id, s.relation))
            .collect())
    }
}

/// A CID on its own (e.g. an element of a list of CIDs): the canonical CID
/// string, transparently.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct CidWire(#[serde(with = "cid_str")] pub Vec<u8>);

/// Wire form of [`memvault_auth::GrantAudience`]: tagged by `kind`, with
/// string ids (cluster id hex, peer id base58btc, agent pubkey hex). The
/// grant's own serde is frozen (grants are signed dag-cbor blocks), so the
/// API transmits this shape — in `GrantInfo.audience` and in the
/// `POST /buckets/{id}/issue-grant` request alike.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum GrantAudienceWire {
    Cluster {
        #[serde(with = "hex_id")]
        cluster_id: ClusterId,
    },
    Peer {
        #[serde(with = "peer_b58")]
        peer_id: memvault_core::PeerId,
    },
    /// Legacy name-addressed agent grant (decoded, no longer issued).
    Agent {
        agent_id: String,
    },
    AgentKey {
        #[serde(with = "hex_array32")]
        agent_pubkey: [u8; 32],
    },
    Role {
        role: memvault_auth::AgentRole,
    },
}

impl From<&memvault_auth::GrantAudience> for GrantAudienceWire {
    fn from(a: &memvault_auth::GrantAudience) -> Self {
        use memvault_auth::GrantAudience as G;
        match a {
            G::Cluster(c) => Self::Cluster {
                cluster_id: c.clone(),
            },
            G::Peer(p) => Self::Peer { peer_id: p.clone() },
            G::Agent(n) => Self::Agent {
                agent_id: n.0.clone(),
            },
            G::AgentKey(k) => Self::AgentKey { agent_pubkey: *k },
            G::Role(r) => Self::Role { role: *r },
        }
    }
}

impl From<GrantAudienceWire> for memvault_auth::GrantAudience {
    fn from(a: GrantAudienceWire) -> Self {
        use memvault_auth::GrantAudience as G;
        match a {
            GrantAudienceWire::Cluster { cluster_id } => G::Cluster(cluster_id),
            GrantAudienceWire::Peer { peer_id } => G::Peer(peer_id),
            GrantAudienceWire::Agent { agent_id } => G::Agent(memvault_core::AgentName(agent_id)),
            GrantAudienceWire::AgentKey { agent_pubkey } => G::AgentKey(agent_pubkey),
            GrantAudienceWire::Role { role } => G::Role(role),
        }
    }
}

/// `#[serde(with = "grant_audience")]` for a `GrantAudience` field of an API
/// type: transmitted as [`GrantAudienceWire`].
pub mod grant_audience {
    use super::*;

    pub fn serialize<S: Serializer>(
        v: &memvault_auth::GrantAudience,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&GrantAudienceWire::from(v), s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<memvault_auth::GrantAudience, D::Error> {
        Ok(GrantAudienceWire::deserialize(d)?.into())
    }
}

/// Wire form of a [`memvault_query::AuditRecord`] — `GET /audit`,
/// `GET /docs/{id}/history`, `GET /entities/{id}/history` and the MCP audit
/// tools all transmit this one shape. CIDs are CID strings, the author key
/// and entity id hex, `op_kind` its snake_case serde form.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRecordWire {
    #[serde(with = "cid_str")]
    pub cid: Vec<u8>,
    pub op_kind: memvault_query::OpKind,
    #[serde(with = "hex_bytes")]
    pub author: Vec<u8>,
    #[serde(default, with = "cid_str_opt", skip_serializing_if = "Option::is_none")]
    pub agent_attestation: Option<Vec<u8>>,
    pub wall_ns: u64,
    #[serde(default, with = "hex_id_opt")]
    pub doc_id: Option<DocId>,
    #[serde(
        default,
        with = "hex_bytes_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub entity_id: Option<Vec<u8>>,
    #[serde(default, with = "cid_str_opt", skip_serializing_if = "Option::is_none")]
    pub attachment_cid: Option<Vec<u8>>,
    #[serde(default)]
    pub tags: Vec<(String, String)>,
}

impl From<&memvault_query::AuditRecord> for AuditRecordWire {
    fn from(r: &memvault_query::AuditRecord) -> Self {
        Self {
            cid: r.cid.clone(),
            op_kind: r.op_kind.clone(),
            author: r.author.clone(),
            agent_attestation: r.agent_attestation.clone(),
            wall_ns: r.wall_ns,
            doc_id: r.doc_id.clone(),
            entity_id: r.entity_id.clone(),
            attachment_cid: r.attachment_cid.clone(),
            tags: r.tags.clone(),
        }
    }
}

impl From<AuditRecordWire> for memvault_query::AuditRecord {
    fn from(w: AuditRecordWire) -> Self {
        Self {
            cid: w.cid,
            op_kind: w.op_kind,
            author: w.author,
            agent_attestation: w.agent_attestation,
            wall_ns: w.wall_ns,
            doc_id: w.doc_id,
            entity_id: w.entity_id,
            attachment_cid: w.attachment_cid,
            tags: w.tags,
        }
    }
}
// ── Shared DTOs for graph block types ──────────────────────────────────
// Entity/Edge serde is frozen (dag-cbor / CIDs), so the wire shape is a thin
// DTO with string ids/labels that both server responses and the client decode
// via serde — no `serde_json::Value` field-picking. See wire-dtos.md.

/// Wire form of an out-edge within an [`EntityWire`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityEdgeWire {
    /// Bare-hex edge id.
    #[serde(alias = "id")]
    pub edge_id: String,
    pub relation: String,
    /// "type:hex" node label.
    pub target: String,
    #[serde(default)]
    pub weight: Option<f32>,
    #[serde(default)]
    pub props: std::collections::BTreeMap<String, serde_json::Value>,
}

impl From<&memvault_doc::Edge> for EntityEdgeWire {
    fn from(e: &memvault_doc::Edge) -> Self {
        Self {
            edge_id: hex::encode(e.id.0),
            relation: e.relation.clone(),
            target: e.target.tag_label(),
            weight: e.weight,
            props: e.props.clone(),
        }
    }
}

impl EntityEdgeWire {
    fn into_edge(self) -> Option<memvault_doc::Edge> {
        let target = NodeRef::from_tag_label(&self.target)?;
        let eid: [u8; 32] = hex::decode(&self.edge_id).ok()?.try_into().ok()?;
        Some(memvault_doc::Edge {
            id: EdgeId(eid),
            relation: self.relation,
            target,
            weight: self.weight,
            props: self.props,
            provenance: None,
        })
    }
}

/// Wire form of an [`Entity`](memvault_doc::Entity): `GET /entities`,
/// `GET /entities/{id}`, the entity branch of `GET /nodes/{id}` and the MCP
/// `memvault_get_entity` / `memvault_list_entities` tools.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityWire {
    /// "entity:<hex>" node label.
    #[serde(alias = "id")]
    pub node_id: String,
    pub kind: String,
    #[serde(default)]
    pub props: std::collections::BTreeMap<String, serde_json::Value>,
    /// Out-edges (empty in listings).
    #[serde(default)]
    pub edges: Vec<EntityEdgeWire>,
}

impl EntityWire {
    /// The entity with its out-edges (a get).
    pub fn with_edges(e: &memvault_doc::Entity) -> Self {
        Self {
            edges: e.edges_out.iter().map(EntityEdgeWire::from).collect(),
            ..Self::summary(e)
        }
    }

    /// The entity without its edges (a listing row).
    pub fn summary(e: &memvault_doc::Entity) -> Self {
        Self {
            node_id: NodeRef::Entity(e.id.clone()).tag_label(),
            kind: e.kind.clone(),
            props: e.props.clone(),
            edges: vec![],
        }
    }

    /// Convert to a domain [`Entity`](memvault_doc::Entity). Listings carry
    /// no edges (empty); a get populates them.
    pub fn into_entity(self) -> Option<memvault_doc::Entity> {
        let id = match NodeRef::from_tag_label(&self.node_id)? {
            NodeRef::Entity(e) => e,
            _ => return None,
        };
        Some(memvault_doc::Entity {
            id,
            kind: self.kind,
            props: self.props,
            edges_out: self
                .edges
                .into_iter()
                .filter_map(|e| e.into_edge())
                .collect(),
        })
    }
}

/// Wire form of an edge with its source (`GET /links`, MCP `memvault_edges`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LinkWire {
    /// Bare-hex edge id.
    pub edge_id: String,
    /// "type:hex" node labels.
    pub source: String,
    pub target: String,
    pub relation: String,
    #[serde(default)]
    pub weight: Option<f32>,
    #[serde(default)]
    pub props: std::collections::BTreeMap<String, serde_json::Value>,
}

impl LinkWire {
    /// The wire form of `edge`, leaving `source`.
    pub fn new(source: &NodeRef, edge: &memvault_doc::Edge) -> Self {
        Self {
            edge_id: hex::encode(edge.id.0),
            source: source.tag_label(),
            target: edge.target.tag_label(),
            relation: edge.relation.clone(),
            weight: edge.weight,
            props: edge.props.clone(),
        }
    }

    /// Convert to a `(source, Edge)` pair (the shape `edges_of` returns).
    pub fn into_source_edge(self) -> Option<(NodeRef, memvault_doc::Edge)> {
        let source = NodeRef::from_tag_label(&self.source)?;
        let target = NodeRef::from_tag_label(&self.target)?;
        let bytes = hex::decode(&self.edge_id).ok()?;
        let eid: [u8; 32] = bytes.try_into().ok()?;
        Some((
            source,
            memvault_doc::Edge {
                id: EdgeId(eid),
                relation: self.relation,
                target,
                weight: self.weight,
                props: self.props,
                provenance: None,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memvault_core::BucketId;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Sample {
        #[serde(with = "hex_id")]
        id: BucketId,
        #[serde(with = "cid_str")]
        cid: Vec<u8>,
        #[serde(with = "hex_id_opt", default)]
        cluster: Option<memvault_core::ClusterId>,
    }

    #[test]
    fn hex_id_is_lowercase_hex_not_array() {
        let s = Sample {
            id: BucketId([0xAB; 32]),
            cid: memvault_core::cid_from_bytes(b"hello").to_bytes(),
            cluster: None,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["id"], "ab".repeat(32));
        assert!(
            json["id"].is_string(),
            "ids must be hex strings, not arrays"
        );
    }

    #[test]
    fn cid_field_is_canonical_cid_string_not_hex() {
        let cid_bytes = memvault_core::cid_from_bytes(b"hello").to_bytes();
        let s = Sample {
            id: BucketId([0; 32]),
            cid: cid_bytes.clone(),
            cluster: None,
        };
        let json = serde_json::to_value(&s).unwrap();
        let cid_field = json["cid"].as_str().unwrap();
        // Canonical CIDv1 multibase strings begin with 'b'; never raw hex.
        assert!(
            cid_field.starts_with('b'),
            "cid must be a CID string: {cid_field}"
        );
        assert_ne!(
            cid_field,
            hex::encode(&cid_bytes),
            "cid must not be bare hex"
        );
    }

    #[test]
    fn round_trips_through_json() {
        let s = Sample {
            id: BucketId([7; 32]),
            cid: memvault_core::cid_from_bytes(b"x").to_bytes(),
            cluster: Some(memvault_core::ClusterId([9; 32])),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Sample = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
