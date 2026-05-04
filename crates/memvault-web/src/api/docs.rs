//! Document CRUD endpoints.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use memvault_core::{DocId, Visibility};
use memvault_doc::{Document, TextPatch};
use serde::{Deserialize, Serialize};

use crate::api::auth::RequireAuth;
use crate::error::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct ListDocsQuery {
    pub tag_ns: Option<String>,
    pub tag_val: Option<String>,
    pub limit: Option<usize>,
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
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListDocsQuery>,
) -> Result<Json<Vec<DocSummaryResponse>>, ApiError> {
    let tag_filter = match (params.tag_ns, params.tag_val) {
        (Some(ns), Some(val)) => Some((ns, val)),
        _ => None,
    };
    let limit = params.limit.unwrap_or(100);

    let docs = state.client.list_docs(tag_filter, limit).await?;

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
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateDocRequest>,
) -> Result<(axum::http::StatusCode, Json<DocResponse>), ApiError> {
    let doc_id = DocId::random();
    let frontmatter = req.frontmatter.unwrap_or_default();
    let doc = Document::new(doc_id.clone(), req.body.clone(), frontmatter.clone());

    let vis = parse_visibility_str(req.visibility.as_deref());

    let cid = state.client.put_doc(doc, req.tags.clone(), vis).await?;
    let node_id = format!("doc:{}", hex::encode(doc_id.0));
    tracing::info!(doc_id = %hex::encode(doc_id.0), "API: doc created");

    // VFS link if requested.
    if let Some(vfs_path) = &req.vfs_path {
        if let Err(e) = super::vfs::link_node_at_path(state.client.as_ref(), vfs_path, &node_id).await {
            tracing::warn!(path = %vfs_path, error = %e, "VFS link failed after doc creation");
        }
    }

    let resp = DocResponse {
        id: node_id,
        cid: hex::encode(&cid),
        body: req.body,
        frontmatter,
        tags: req.tags,
        updated_ns: 0,
    };

    Ok((axum::http::StatusCode::CREATED, Json(resp)))
}

/// GET /api/v1/docs/:id
pub async fn get_doc(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<DocResponse>, ApiError> {
    let doc_id = parse_doc_id(&id)?;

    let doc = state
        .client
        .get_doc(&doc_id)
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
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDocRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let doc_id = parse_doc_id(&id)?;

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
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    let cid_bytes = doc_id.0.to_vec();
    let cid = state.client.retract(&cid_bytes, "deleted via API").await?;
    tracing::info!(id = %id, "API: doc deleted");
    Ok(Json(serde_json::json!({ "cid": hex::encode(&cid) })))
}

/// GET /api/v1/docs/:id/history
pub async fn doc_history(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    let records = state.client.history_of(&doc_id).await?;

    let results: Vec<serde_json::Value> = records
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "cid": hex::encode(&r.cid),
                "op_kind": r.op_kind,
                "wall_ns": r.wall_ns,
                "author": hex::encode(&r.author),
            })
        })
        .collect();

    Ok(Json(results))
}

/// Parse a document ID from either "doc:<hex>" or raw "<hex>" format.
pub fn parse_doc_id(input: &str) -> Result<DocId, ApiError> {
    let hex_str = input.strip_prefix("doc:").unwrap_or(input);
    let bytes = hex::decode(hex_str).map_err(|_| ApiError::bad_request("Invalid document ID — expected hex or doc:<hex>"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request("Document ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(DocId(arr))
}

pub(crate) fn parse_visibility_str(s: Option<&str>) -> Visibility {
    match s {
        Some("public") => Visibility::Public,
        Some("federated") => Visibility::Federated,
        _ => Visibility::Internal,
    }
}
