use serde::{Deserialize, Serialize};

/// Cluster identifier — random 32 bytes, not derived from any key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClusterId(pub [u8; 32]);

/// Document identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocId(pub [u8; 32]);

/// Entity identifier (knowledge-graph node).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntityId(pub [u8; 32]);

/// Edge identifier (knowledge-graph edge).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EdgeId(pub [u8; 32]);

/// Agent identifier (human-readable string).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// Peer identity — raw bytes to avoid libp2p dependency in core.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Vec<u8>);

impl ClusterId {
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        Self(buf)
    }
}

impl DocId {
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        Self(buf)
    }
}

impl EntityId {
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        Self(buf)
    }
}

impl EdgeId {
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        Self(buf)
    }
}

impl std::fmt::Display for ClusterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl std::fmt::Display for DocId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

/// A reference to any node in the knowledge graph — entity, document, or attachment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum NodeRef {
    Entity(EntityId),
    Doc(DocId),
    Attachment(Vec<u8>), // manifest CID bytes
}

impl NodeRef {
    /// Return a `"type:hex"` label suitable for tag indexing.
    pub fn tag_label(&self) -> String {
        match self {
            NodeRef::Entity(id) => format!("entity:{}", hex::encode(id.0)),
            NodeRef::Doc(id) => format!("doc:{}", hex::encode(id.0)),
            NodeRef::Attachment(cid) => format!("attachment:{}", hex::encode(cid)),
        }
    }

    /// Parse a `"type:hex"` label back into a NodeRef.
    pub fn from_tag_label(s: &str) -> Option<Self> {
        let (kind, hex_str) = s.split_once(':')?;
        let bytes = hex::decode(hex_str).ok()?;
        match kind {
            "entity" => {
                if bytes.len() != 32 { return None; }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(NodeRef::Entity(EntityId(arr)))
            }
            "doc" => {
                if bytes.len() != 32 { return None; }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(NodeRef::Doc(DocId(arr)))
            }
            "attachment" => Some(NodeRef::Attachment(bytes)),
            _ => None,
        }
    }
}

impl std::fmt::Display for NodeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.tag_label())
    }
}

impl From<EntityId> for NodeRef {
    fn from(id: EntityId) -> Self {
        NodeRef::Entity(id)
    }
}

impl From<DocId> for NodeRef {
    fn from(id: DocId) -> Self {
        NodeRef::Doc(id)
    }
}

/// Custom deserializer: accepts the tagged enum form `{"Entity": ...}` OR
/// a bare `[u8; 32]` array which is interpreted as `NodeRef::Entity(EntityId(...))`.
/// This provides backward compatibility with old blocks that stored EntityId directly.
impl<'de> Deserialize<'de> for NodeRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        // Tagged form: {"Entity": [...]} / {"Doc": [...]} / {"Attachment": [...]}
        if let Some(obj) = value.as_object() {
            if let Some(inner) = obj.get("Entity") {
                let id: EntityId = serde_json::from_value(inner.clone()).map_err(serde::de::Error::custom)?;
                return Ok(NodeRef::Entity(id));
            }
            if let Some(inner) = obj.get("Doc") {
                let id: DocId = serde_json::from_value(inner.clone()).map_err(serde::de::Error::custom)?;
                return Ok(NodeRef::Doc(id));
            }
            if let Some(inner) = obj.get("Attachment") {
                let cid: Vec<u8> = serde_json::from_value(inner.clone()).map_err(serde::de::Error::custom)?;
                return Ok(NodeRef::Attachment(cid));
            }
        }

        // Legacy fallback: bare [u8; 32] array → Entity
        if let Ok(arr) = serde_json::from_value::<[u8; 32]>(value.clone()) {
            return Ok(NodeRef::Entity(EntityId(arr)));
        }

        Err(serde::de::Error::custom("expected NodeRef: {\"Entity\": ...}, {\"Doc\": ...}, {\"Attachment\": ...}, or [u8; 32]"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noderef_roundtrip_entity() {
        let nr = NodeRef::Entity(EntityId([42u8; 32]));
        let json = serde_json::to_string(&nr).unwrap();
        let back: NodeRef = serde_json::from_str(&json).unwrap();
        assert_eq!(nr, back);
    }

    #[test]
    fn noderef_roundtrip_doc() {
        let nr = NodeRef::Doc(DocId([7u8; 32]));
        let json = serde_json::to_string(&nr).unwrap();
        let back: NodeRef = serde_json::from_str(&json).unwrap();
        assert_eq!(nr, back);
    }

    #[test]
    fn noderef_roundtrip_attachment() {
        let nr = NodeRef::Attachment(vec![1, 2, 3, 4]);
        let json = serde_json::to_string(&nr).unwrap();
        let back: NodeRef = serde_json::from_str(&json).unwrap();
        assert_eq!(nr, back);
    }

    #[test]
    fn noderef_legacy_entity_fallback() {
        // Old format: bare [u8; 32] should deserialize as Entity
        let id = EntityId([99u8; 32]);
        let legacy_json = serde_json::to_string(&id).unwrap();
        let nr: NodeRef = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(nr, NodeRef::Entity(id));
    }

    #[test]
    fn noderef_tag_label_roundtrip() {
        let nr = NodeRef::Entity(EntityId([1u8; 32]));
        let label = nr.tag_label();
        let back = NodeRef::from_tag_label(&label).unwrap();
        assert_eq!(nr, back);

        let nr2 = NodeRef::Doc(DocId([2u8; 32]));
        let label2 = nr2.tag_label();
        let back2 = NodeRef::from_tag_label(&label2).unwrap();
        assert_eq!(nr2, back2);

        let nr3 = NodeRef::Attachment(vec![3, 4, 5]);
        let label3 = nr3.tag_label();
        let back3 = NodeRef::from_tag_label(&label3).unwrap();
        assert_eq!(nr3, back3);
    }
}
