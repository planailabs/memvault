//! Audit log endpoint.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::auth::RequireAuth;
use crate::error::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct AuditQueryParams {
    pub doc_id: Option<String>,
    pub author: Option<String>,
    pub op_kind: Option<String>,
    pub after_ns: Option<u64>,
    pub before_ns: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct AuditRecordResponse {
    pub cid: String,
    pub op_kind: String,
    pub author: String,
    pub wall_ns: u64,
    pub doc_id: Option<String>,
    pub tags: Vec<(String, String)>,
}

/// GET /api/v1/audit
pub async fn query_audit(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<Vec<AuditRecordResponse>>, ApiError> {
    use memvault_core::DocId;
    use memvault_query::AuditQuery;

    let doc_id = if let Some(ref id_hex) = params.doc_id {
        let bytes =
            hex::decode(id_hex).map_err(|_| ApiError::bad_request("Invalid doc_id hex"))?;
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

    let query = AuditQuery {
        doc_id,
        author,
        op_kind: None, // simplified: could parse from string
        after_ns: params.after_ns,
        before_ns: params.before_ns,
        limit: params.limit,
    };

    let records = state.client.audit(query).await?;

    let results: Vec<AuditRecordResponse> = records
        .into_iter()
        .map(|r| AuditRecordResponse {
            cid: hex::encode(&r.cid),
            op_kind: format!("{:?}", r.op_kind),
            author: hex::encode(&r.author),
            wall_ns: r.wall_ns,
            doc_id: r.doc_id.map(|d| hex::encode(d.0)),
            tags: r.tags,
        })
        .collect();

    Ok(Json(results))
}
