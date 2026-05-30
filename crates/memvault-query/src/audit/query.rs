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
    BucketCreate,
    BucketRename,
    BucketAttach,
    BucketArchive,
    BucketBind,
    ViewCreate,
    TokenIssue,
    TokenRedeem,
    SharePropose,
    ShareDecide,
    Other(String),
}

/// A single audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub cid: Vec<u8>,
    pub op_kind: OpKind,
    /// Envelope-level author. For Signed<T> envelopes this is the node
    /// pubkey that signed; for legacy raw-JSON envelopes it's whoever the
    /// `effective_author()` was at write time (agent pubkey when an
    /// agent identity was bound, otherwise the node peer_id).
    pub author: Vec<u8>,
    /// CID of the `AgentAttestation` covering the agent that authored
    /// this write, when present. Set on Signed<T> envelopes whenever an
    /// agent identity was bound. UIs should prefer this for "who did
    /// this" attribution.
    #[serde(default)]
    pub agent_attestation: Option<Vec<u8>>,
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

    // "Token redeemed" audit records are signed TokenConsumption sigchain
    // blocks (tag `sigchain/token_redeem`). They don't carry the generic
    // envelope shape the parser below expects, so decode them by type here
    // and key them by CID. The time/author scan then SKIPS these CIDs (they
    // would otherwise come back as Other("unknown")), and we merge the typed
    // records in afterwards.
    let redeem_records = token_redeem_records(store, after, limit)?;
    let redeem_cids: std::collections::HashSet<Vec<u8>> =
        redeem_records.keys().cloned().collect();

    let cids = if let Some(author) = &query.author {
        store.query_by_author(author, after, limit)?
    } else {
        // Newest first so recent operations show up even when there are
        // many older annotations/edges that would fill the limit.
        store.query_by_time_desc(after, before, limit)?
    };

    let mut records = Vec::new();
    for cid in cids {
        if redeem_cids.contains(&cid) {
            continue;
        }
        if let Some(data) = store.get_block(&cid)? {
            // Use deserialize_block — handles both raw-JSON envelopes
            // (legacy) and DAG-CBOR Signed<T> envelopes (post-Phase 1).
            // The previous direct `serde_json::from_slice` only matched
            // JSON-stored bytes, silently dropping every CBOR envelope.
            if let Some(val) = memvault_store::deserialize_block(&data) {
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

    // Merge in the typed token-redeem records, honouring the op_kind filter
    // (doc_id never matches these). Then sort newest-first and cap to limit
    // so the merged set stays consistent with the per-scan ordering.
    let want_redeem = query
        .op_kind
        .as_ref()
        .map(|k| k == &OpKind::TokenRedeem)
        .unwrap_or(true);
    if query.doc_id.is_none() && want_redeem {
        for (_cid, rec) in redeem_records {
            if rec.wall_ns < after || rec.wall_ns > before {
                continue;
            }
            if let Some(filter_author) = &query.author {
                if &rec.author != filter_author {
                    continue;
                }
            }
            records.push(rec);
        }
    }
    records.sort_by(|a, b| b.wall_ns.cmp(&a.wall_ns));
    records.truncate(limit);

    Ok(records)
}

/// Decode the `sigchain/token_redeem` blocks (signed `TokenConsumption`
/// records) into audit rows keyed by block CID. Each row links the redeemed
/// token to the attestation block minted for it, and best-effort resolves
/// whether that attestation is a node or agent attestation.
fn token_redeem_records(
    store: &MemvaultStore,
    after: u64,
    limit: usize,
) -> Result<std::collections::HashMap<Vec<u8>, AuditRecord>, QueryError> {
    let mut out = std::collections::HashMap::new();
    let cids = store
        .query_by_tag("sigchain", "token_redeem", after, limit)
        .unwrap_or_default();
    for cid in cids {
        let Some(data) = store.get_block(&cid)? else {
            continue;
        };
        let Ok(tc) = serde_ipld_dagcbor::from_slice::<memvault_auth::TokenConsumption>(&data) else {
            continue;
        };
        let att_cid = tc.issued_attestation.to_bytes();
        // Best-effort: classify the minted attestation for nicer display.
        let att_type = match store.get_block(&att_cid) {
            Ok(Some(b)) => {
                if serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&b).is_ok() {
                    "node"
                } else if serde_ipld_dagcbor::from_slice::<memvault_auth::AgentAttestation>(&b)
                    .is_ok()
                {
                    "agent"
                } else {
                    "unknown"
                }
            }
            _ => "unknown",
        };
        let tags = vec![
            ("token".to_string(), hex::encode(tc.token_cid.to_bytes())),
            ("attestation".to_string(), hex::encode(&att_cid)),
            ("att_type".to_string(), att_type.to_string()),
        ];
        out.insert(
            cid.clone(),
            AuditRecord {
                cid,
                op_kind: OpKind::TokenRedeem,
                author: tc.consumer.0.clone(),
                agent_attestation: None,
                wall_ns: tc.consumed_at_ns,
                doc_id: None,
                entity_id: None,
                attachment_cid: None,
                tags,
            },
        );
    }
    Ok(out)
}

pub fn parse_audit_record(cid: &[u8], val: &serde_json::Value) -> AuditRecord {
    let view = memvault_store::EnvelopeView::from_value(val.clone());

    let author: Vec<u8> = view
        .as_ref()
        .map(|v| v.author())
        .unwrap_or_default();

    let wall_ns = view
        .as_ref()
        .and_then(|v| v.field("wall_ns").and_then(|x| x.as_u64()))
        .unwrap_or(0);

    // Signed<T> envelopes serialize `tags` as a list of `Tag` structs
    // (`[{"scope":"x","label":"y"}, …]`); the unsigned fallback path
    // uses nested arrays (`[["x","y"], …]`). Try the struct shape first,
    // fall back to the tuple shape so both round-trip into the
    // canonical `Vec<(String, String)>` representation.
    let tags: Vec<(String, String)> = view
        .as_ref()
        .and_then(|v| v.field("tags"))
        .and_then(|raw| {
            if let Ok(structured) =
                serde_json::from_value::<Vec<memvault_core::Tag>>(raw.clone())
            {
                Some(
                    structured
                        .into_iter()
                        .map(|t| (t.scope, t.label))
                        .collect(),
                )
            } else {
                serde_json::from_value::<Vec<(String, String)>>(raw.clone()).ok()
            }
        })
        .unwrap_or_default();

    // First try the Op-variant tags inside `payload` (the Signed<T>
    // shape that put_doc / add_entity / add_link etc. produce). If none
    // matches, FALL THROUGH to the kind/type/tag check below — the
    // previous version hard-returned Other("unknown") here, which made
    // every attachment envelope and every annotation (extraction,
    // tag_update, retraction) come back as Other("unknown") because
    // their payload object lacks any Op variant key.
    let payload_op_kind = val.get("payload").and_then(|p| {
        if p.get("DocCreate").is_some() {
            Some(OpKind::DocCreate)
        } else if p.get("DocEdit").is_some() {
            Some(OpKind::DocEdit)
        } else if p.get("AttachFile").is_some() {
            Some(OpKind::AttachFile)
        } else if p.get("DetachFile").is_some() {
            Some(OpKind::DetachFile)
        } else if p.get("EntityCreate").is_some() {
            Some(OpKind::EntityCreate)
        } else if p.get("EdgeAdd").is_some() {
            Some(OpKind::EdgeAdd)
        } else if p.get("EdgeRemove").is_some() {
            Some(OpKind::EdgeRemove)
        } else if p.get("BucketCreate").is_some() {
            Some(OpKind::BucketCreate)
        } else if p.get("BucketRename").is_some() {
            Some(OpKind::BucketRename)
        } else if p.get("BucketAttach").is_some() {
            Some(OpKind::BucketAttach)
        } else if p.get("BucketArchive").is_some() {
            Some(OpKind::BucketArchive)
        } else if p.get("BucketBind").is_some() {
            Some(OpKind::BucketBind)
        } else {
            None
        }
    });

    let op_kind = if let Some(k) = payload_op_kind {
        k
    } else {
        // EnvelopeView handles the legacy-vs-Signed<T> shape unification,
        // so the same match works whether `kind`/`type` live at the top
        // level (legacy raw JSON) or inside `payload` (Signed<T>).
        let kind = view.as_ref().and_then(|v| v.str_field("kind"));
        let ann_type = view.as_ref().and_then(|v| v.str_field("type"));
        let kind_tag = tags
            .iter()
            .find(|(s, _)| s == "kind")
            .map(|(_, l)| l.as_str());
        match (kind, ann_type, kind_tag) {
            (Some("annotation"), Some("retraction"), _) => OpKind::Retract,
            (Some("annotation"), Some("tag_update"), _) => OpKind::TagUpdate,
            (Some("annotation"), Some("extraction"), _) => OpKind::Extraction,
            (Some("annotation"), Some(t), _) => OpKind::Other(t.into()),
            (Some("attachment"), _, _) => OpKind::AttachFile,
            (Some("node_retraction"), _, _) => OpKind::Retract,
            (Some("tag_update"), _, _) => OpKind::TagUpdate,
            // Bucket ops stored without payload wrapper (legacy).
            (_, _, Some("bucket-decl")) => OpKind::BucketCreate,
            (_, _, Some("bucket-rename")) => OpKind::BucketRename,
            (_, _, Some("bucket-archive")) => OpKind::BucketArchive,
            // View and token blocks.
            (_, _, Some("view")) => OpKind::ViewCreate,
            (_, _, Some("join-token")) => OpKind::TokenIssue,
            (_, _, Some("share-proposal")) => OpKind::SharePropose,
            (_, _, Some("share-decision")) => OpKind::ShareDecide,
            (Some(other), _, _) => OpKind::Other(other.into()),
            (None, _, Some(other)) => OpKind::Other(other.into()),
            _ => OpKind::Other("unknown".into()),
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
        for key in [
            "EntityCreate",
            "EntityUpdate",
            "EntityDelete",
            "EdgeAdd",
            "EdgeRemove",
        ] {
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

    let attachment_cid: Option<Vec<u8>> =
        view.as_ref().and_then(|v| v.get_as("manifest_cid"));

    // Agent attribution lives in `agent_attestation` on Signed<T> v3+
    // envelopes. Absent on legacy raw-JSON envelopes (None).
    let agent_attestation: Option<Vec<u8>> =
        view.as_ref().and_then(|v| v.agent_attestation_cid());

    AuditRecord {
        cid: cid.to_vec(),
        op_kind,
        author,
        agent_attestation,
        wall_ns,
        doc_id,
        entity_id,
        attachment_cid,
        tags,
    }
}
