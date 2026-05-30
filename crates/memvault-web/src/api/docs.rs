//! Document CRUD endpoints.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use memvault_core::DocId;
use memvault_doc::TextPatch;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct ListDocsQuery {
    pub tag_ns: Option<String>,
    pub tag_val: Option<String>,
    pub limit: Option<usize>,
    pub bucket: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateDocRequest {
    pub body: String,
    pub frontmatter: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    pub tags: Vec<(String, String)>,
    pub visibility: Option<String>,
    /// Optional VFS path to place the new document at.
    #[serde(default)]
    pub vfs_path: Option<String>,
    /// Optional bucket ID (hex) to scope this document to.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Serialize)]
pub struct DocResponse {
    pub id: String,
    pub cid: String,
    pub body: String,
    pub frontmatter: BTreeMap<String, serde_json::Value>,
    pub tags: Vec<(String, String)>,
    pub updated_ns: u64,
}

#[derive(Serialize)]
pub struct DocSummaryResponse {
    pub id: String,
    pub cid: String,
    pub title: Option<String>,
    pub tags: Vec<(String, String)>,
    pub updated_ns: u64,
    pub attachment_count: usize,
}

#[derive(Deserialize)]
pub struct UpdateDocRequest {
    pub ops: Vec<TextOpRequest>,
}

#[derive(Deserialize)]
pub struct TextOpRequest {
    pub retain: Option<usize>,
    pub insert: Option<String>,
    pub delete: Option<usize>,
}

/// GET /api/v1/docs
pub async fn list_docs(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListDocsQuery>,
) -> Result<Json<Vec<DocSummaryResponse>>, ApiError> {
    let tag_filter = match (params.tag_ns, params.tag_val) {
        (Some(ns), Some(val)) => Some((ns, val)),
        _ => None,
    };
    let limit = params.limit.unwrap_or(100);

    let bucket_id = params.bucket.as_deref().and_then(|h| {
        let bytes = hex::decode(h).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(memvault_core::BucketId(arr))
    });

    if let Some(bid) = &bucket_id {
        crate::api::auth::enforce_bucket_action(&auth.claims, bid, memvault_auth::Action::Read)?;
    }

    let include_retracted = crate::api::auth::caller_sees_retracted(&state, &auth.claims);
    let docs = state
        .client
        .list_docs_ex(tag_filter, limit, bucket_id.as_ref(), include_retracted)
        .await?;

    let results: Vec<DocSummaryResponse> = docs
        .into_iter()
        .map(|d| DocSummaryResponse {
            id: format!("doc:{}", hex::encode(d.id.0)),
            cid: hex::encode(&d.cid),
            title: d.title,
            tags: d.tags,
            updated_ns: d.updated_ns,
            attachment_count: d.attachment_count,
        })
        .collect();

    Ok(Json(results))
}

/// POST /api/v1/docs
pub async fn create_doc(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateDocRequest>,
) -> Result<(axum::http::StatusCode, Json<DocResponse>), ApiError> {
    let vis = parse_visibility_str(req.visibility.as_deref());

    let bucket_id = req.bucket.as_deref().and_then(|h| {
        let bytes = hex::decode(h).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(memvault_core::BucketId(arr))
    });

    if let Some(bid) = &bucket_id {
        crate::api::auth::enforce_bucket_action(&auth.claims, bid, memvault_auth::Action::Write)?;
    }

    let result = memvault_api::docs::create_doc(
        state.client.as_ref(),
        &req.body,
        None,
        req.frontmatter.clone(),
        req.tags.clone(),
        vis,
        req.vfs_path.as_deref(),
        bucket_id.as_ref(),
    )
    .await?;
    tracing::info!(doc_id = %result.node_id, "API: doc created");

    let resp = DocResponse {
        id: result.node_id,
        cid: hex::encode(&result.cid),
        body: req.body,
        frontmatter: result.frontmatter,
        tags: req.tags,
        updated_ns: 0,
    };

    Ok((axum::http::StatusCode::CREATED, Json(resp)))
}

/// GET /api/v1/docs/:id
pub async fn get_doc(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<DocResponse>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    crate::api::auth::enforce_doc_action(&auth.claims, &doc_id, memvault_auth::Action::Read)?;

    let include_retracted = crate::api::auth::caller_sees_retracted(&state, &auth.claims);
    let doc = state
        .client
        .get_doc_ex(&doc_id, include_retracted)
        .await?
        .ok_or_else(|| ApiError::not_found("Document not found"))?;

    let resp = DocResponse {
        id: format!("doc:{}", hex::encode(doc.id.0)),
        cid: String::new(),
        body: doc.body,
        frontmatter: doc.frontmatter,
        tags: vec![],
        updated_ns: 0,
    };

    Ok(Json(resp))
}

/// PUT /api/v1/docs/:id
pub async fn update_doc(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDocRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    crate::api::auth::enforce_doc_action(&auth.claims, &doc_id, memvault_auth::Action::Write)?;

    let ops: Vec<memvault_doc::TextOp> = req
        .ops
        .into_iter()
        .map(|op| {
            if let Some(n) = op.retain {
                memvault_doc::TextOp::Retain(n)
            } else if let Some(s) = op.insert {
                memvault_doc::TextOp::Insert(s)
            } else if let Some(n) = op.delete {
                memvault_doc::TextOp::Delete(n)
            } else {
                memvault_doc::TextOp::Retain(0)
            }
        })
        .collect();

    let patch = TextPatch { ops };
    let cid = state.client.edit_doc(&doc_id, patch).await?;

    Ok(Json(serde_json::json!({ "cid": hex::encode(&cid) })))
}

/// DELETE /api/v1/docs/:id
pub async fn delete_doc(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    crate::api::auth::enforce_doc_action(&auth.claims, &doc_id, memvault_auth::Action::Write)?;
    let cid_bytes = doc_id.0.to_vec();
    let cid = state.client.retract(&cid_bytes, "deleted via API").await?;
    tracing::info!(id = %id, "API: doc deleted");
    Ok(Json(serde_json::json!({ "cid": hex::encode(&cid) })))
}

/// GET /api/v1/docs/:id/history
pub async fn doc_history(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    crate::api::auth::enforce_doc_action(&auth.claims, &doc_id, memvault_auth::Action::Read)?;
    let records = state.client.history_of(&doc_id).await?;

    let results: Vec<serde_json::Value> = records
        .into_iter()
        .map(|r| {
            let mut row = serde_json::json!({
                "cid": hex::encode(&r.cid),
                "op_kind": r.op_kind,
                "wall_ns": r.wall_ns,
                "author": hex::encode(&r.author),
            });
            if let Some(cid) = r.agent_attestation.as_ref() {
                row["agent_attestation"] = serde_json::Value::String(hex::encode(cid));
            }
            row
        })
        .collect();

    Ok(Json(results))
}

/// Parse a document ID from either "doc:<hex>" or raw "<hex>" format.
pub fn parse_doc_id(input: &str) -> Result<DocId, ApiError> {
    DocId::from_hex(input)
        .map_err(|_| ApiError::bad_request("Invalid document ID — expected hex or doc:<hex>"))
}

pub(crate) use memvault_api::docs::parse_visibility as parse_visibility_str;
