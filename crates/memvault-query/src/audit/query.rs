//! Audit log query support.

use memvault_core::DocId;
use memvault_store::MemvaultStore;
use serde::{Deserialize, Serialize};

use crate::error::QueryError;

/// What kind of operation was performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    DocCreate,
    DocEdit,
    AttachFile,
    DetachFile,
    EntityCreate,
    EdgeAdd,
    EdgeRemove,
    TagUpdate,
    Extraction,
    Retract,
    Other(String),
}

/// A single audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub cid: Vec<u8>,
    pub op_kind: OpKind,
    pub author: Vec<u8>,
    pub wall_ns: u64,
    pub doc_id: Option<DocId>,
    pub entity_id: Option<Vec<u8>>,
    pub attachment_cid: Option<Vec<u8>>,
    pub tags: Vec<(String, String)>,
}

/// Query parameters for audit log retrieval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    pub doc_id: Option<DocId>,
    pub author: Option<Vec<u8>>,
    pub op_kind: Option<OpKind>,
    pub after_ns: Option<u64>,
    pub before_ns: Option<u64>,
    pub limit: Option<usize>,
}

/// Query the audit log.
pub fn query_audit(
    store: &MemvaultStore,
    query: &AuditQuery,
) -> Result<Vec<AuditRecord>, QueryError> {
    let after = query.after_ns.unwrap_or(0);
    let before = query.before_ns.unwrap_or(u64::MAX);
    let limit = query.limit.unwrap_or(100);

    let cids = if let Some(author) = &query.author {
        store.query_by_author(author, after, limit)?
    } else {
        // Newest first so recent operations show up even when there are
        // many older annotations/edges that would fill the limit.
        store.query_by_time_desc(after, before, limit)?
    };

    let mut records = Vec::new();
    for cid in cids {
        if let Some(data) = store.get_block(&cid)? {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                let record = parse_audit_record(&cid, &val);
                if let Some(ref filter_doc) = query.doc_id {
                    if record.doc_id.as_ref() != Some(filter_doc) {
                        continue;
                    }
                }
                if let Some(ref filter_kind) = query.op_kind {
                    if &record.op_kind != filter_kind {
                        continue;
                    }
                }
                records.push(record);
            }
        }
    }

    Ok(records)
}

pub fn parse_audit_record(cid: &[u8], val: &serde_json::Value) -> AuditRecord {
    let author = val
        .get("author")
        .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
        .unwrap_or_default();

    let wall_ns = val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);

    let tags: Vec<(String, String)> = val
        .get("tags")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let op_kind = if let Some(p) = val.get("payload") {
        if p.get("DocCreate").is_some() {
            OpKind::DocCreate
        } else if p.get("DocEdit").is_some() {
            OpKind::DocEdit
        } else if p.get("AttachFile").is_some() {
            OpKind::AttachFile
        } else if p.get("DetachFile").is_some() {
            OpKind::DetachFile
        } else if p.get("EntityCreate").is_some() {
            OpKind::EntityCreate
        } else if p.get("EdgeAdd").is_some() {
            OpKind::EdgeAdd
        } else if p.get("EdgeRemove").is_some() {
            OpKind::EdgeRemove
        } else {
            OpKind::Other("unknown".into())
        }
    } else {
        let kind = val.get("kind").and_then(|v| v.as_str());
        let ann_type = val.get("type").and_then(|v| v.as_str());
        match (kind, ann_type) {
            (Some("annotation"), Some("retraction")) => OpKind::Retract,
            (Some("annotation"), Some("tag_update")) => OpKind::TagUpdate,
            (Some("annotation"), Some("extraction")) => OpKind::Extraction,
            (Some("annotation"), Some(t)) => OpKind::Other(t.into()),
            (Some("attachment"), _) => OpKind::AttachFile,
            (Some("node_retraction"), _) => OpKind::Retract, // legacy
            (Some("tag_update"), _) => OpKind::TagUpdate, // legacy
            (Some(other), _) => OpKind::Other(other.into()),
            (None, _) => OpKind::Other("unknown".into()),
        }
    };

    let doc_id = val.get("payload").and_then(|p| {
        for key in ["DocCreate", "DocEdit", "AttachFile", "DetachFile"] {
            if let Some(inner) = p.get(key) {
                if let Some(did) = inner.get("doc_id") {
                    return serde_json::from_value::<DocId>(did.clone()).ok();
                }
            }
        }
        None
    });

    let entity_id = val.get("payload").and_then(|p| {
        for key in ["EntityCreate", "EntityUpdate", "EntityDelete", "EdgeAdd", "EdgeRemove"] {
            if let Some(inner) = p.get(key) {
                // EntityCreate has entity.id, others have entity_id directly.
                let id_val = inner
                    .get("entity")
                    .and_then(|e| e.get("id"))
                    .or_else(|| inner.get("entity_id"));
                if let Some(id) = id_val {
                    return serde_json::from_value::<Vec<u8>>(id.clone()).ok();
                }
            }
        }
        None
    });

    // For attachment envelopes, extract the manifest_cid.
    let attachment_cid = val
        .get("manifest_cid")
        .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok());

    AuditRecord {
        cid: cid.to_vec(),
        op_kind,
        author,
        wall_ns,
        doc_id,
        entity_id,
        attachment_cid,
        tags,
    }
}
