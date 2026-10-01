//! Audit log endpoint.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::RequireAuth;
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct AuditQueryParams {
    pub doc_id: Option<String>,
    pub author: Option<String>,
    pub op_kind: Option<String>,
    pub after_ns: Option<u64>,
    pub before_ns: Option<u64>,
    pub limit: Option<usize>,
    /// Only records in this bucket (hex), which the caller must be able to
    /// read. Without one, the log across the buckets it may read.
    pub bucket: Option<String>,
}

#[derive(Serialize)]
pub struct AuditRecordResponse {
    pub cid: String,
    pub op_kind: String,
    pub author: String,
    /// Hex-encoded `agent_attestation` CID when the envelope was
    /// written through the Signed<T> path with an agent identity
    /// bound. `None` for legacy / pure-node writes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_attestation: Option<String>,
    pub wall_ns: u64,
    pub doc_id: Option<String>,
    /// Hex entity id, for entity operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    /// The file manifest's CID, for file attachments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_cid: Option<String>,
    pub tags: Vec<(String, String)>,
}

/// The node a record is about, for the bucket check.
fn node_of(r: &AuditRecordResponse) -> String {
    if let Some(d) = &r.doc_id {
        format!("doc:{d}")
    } else if let Some(e) = &r.entity_id {
        format!("entity:{e}")
    } else if let Some(a) = &r.attachment_cid {
        memvault_core::cid_bytes_lenient(a)
            .map(|b| format!("file:{}", hex::encode(b)))
            .unwrap_or_default()
    } else {
        String::new()
    }
}

/// GET /api/v1/audit
pub async fn query_audit(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<Vec<AuditRecordResponse>>, ApiError> {
    use memvault_core::DocId;
    use memvault_query::AuditQuery;

    let doc_id = if let Some(ref id_hex) = params.doc_id {
        let bytes = hex::decode(id_hex).map_err(|_| ApiError::bad_request("Invalid doc_id hex"))?;
        if bytes.len() != 32 {
            return Err(ApiError::bad_request("doc_id must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(DocId(arr))
    } else {
        None
    };

    let author = if let Some(ref a) = params.author {
        Some(hex::decode(a).map_err(|_| ApiError::bad_request("Invalid author hex"))?)
    } else {
        None
    };

    // Parse op_kind from its canonical serde form (snake_case), e.g.
    // "doc_create". Invalid values are ignored (no filter) rather than erroring.
    let op_kind = params
        .op_kind
        .as_deref()
        .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok());

    let bucket = crate::api::auth::parse_bucket_param(params.bucket.as_deref())?;
    if let Some(b) = &bucket {
        crate::api::auth::enforce_bucket_action(&auth.claims, b, memvault_auth::Action::Read)?;
    }

    let query = AuditQuery {
        doc_id,
        author,
        op_kind,
        after_ns: params.after_ns,
        before_ns: params.before_ns,
        limit: params.limit,
        bucket,
    };

    let records = state.client.audit(query).await?;

    let results: Vec<AuditRecordResponse> = records
        .into_iter()
        .map(|r| AuditRecordResponse {
            // cid + agent_attestation are CIDs → canonical CID string (standards/).
            cid: memvault_core::cid_string_from_bytes(&r.cid)
                .unwrap_or_else(|_| hex::encode(&r.cid)),
            // Canonical serde form (snake_case, e.g. "doc_create") so the HTTP
            // client can round-trip it back into an OpKind — the old Debug
            // form ("DocCreate") was not deserializable.
            op_kind: serde_json::to_value(&r.op_kind)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            author: hex::encode(&r.author),
            agent_attestation: r.agent_attestation.as_ref().map(|c| {
                memvault_core::cid_string_from_bytes(c).unwrap_or_else(|_| hex::encode(c))
            }),
            wall_ns: r.wall_ns,
            doc_id: r.doc_id.map(|d| hex::encode(d.0)),
            entity_id: r.entity_id.as_ref().map(hex::encode),
            attachment_cid: r.attachment_cid.as_ref().map(|c| {
                memvault_core::cid_string_from_bytes(c).unwrap_or_else(|_| hex::encode(c))
            }),
            tags: r.tags,
        })
        .collect();

    // Only records about what the caller may read (records about no node pass).
    // ponytail: `limit` applies before this filter, so a caller may get fewer.
    let results = crate::api::auth::filter_readable(&auth.claims, results, node_of)?;
    Ok(Json(results))
}
