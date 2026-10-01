//! Audit log endpoint.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use memvault_api::wire::AuditRecordWire;
use serde::Deserialize;

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

/// The node a record is about, for the bucket check.
fn node_of(r: &memvault_query::AuditRecord) -> String {
    if let Some(d) = &r.doc_id {
        format!("doc:{}", hex::encode(d.0))
    } else if let Some(e) = &r.entity_id {
        format!("entity:{}", hex::encode(e))
    } else if let Some(a) = &r.attachment_cid {
        format!("file:{}", hex::encode(a))
    } else {
        String::new()
    }
}

/// GET /api/v1/audit
pub async fn query_audit(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<Vec<AuditRecordWire>>, ApiError> {
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

    // Only records about what the caller may read (records about no node pass).
    // ponytail: `limit` applies before this filter, so a caller may get fewer.
    let records = crate::api::auth::filter_readable(&auth.claims, records, node_of)?;
    Ok(Json(records.iter().map(AuditRecordWire::from).collect()))
}
