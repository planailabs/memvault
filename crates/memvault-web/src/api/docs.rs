//! Document CRUD endpoints.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use memvault_api::rest::{
    CidReceipt, CreateDocRequest, DocWire, ListDocsParams, ReasonParams, ScopeParams,
};
use memvault_api::wire::AuditRecordWire;
use memvault_core::{DocId, NodeRef};
use memvault_doc::TextPatch;
use serde::Deserialize;

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

/// GET /api/v1/docs
pub async fn list_docs(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListDocsParams>,
) -> Result<Json<Vec<memvault_api::DocSummary>>, ApiError> {
    let tag_filter = match (params.tag_ns, params.tag_val) {
        (Some(ns), Some(val)) => Some((ns, val)),
        _ => None,
    };
    let limit = params.limit.unwrap_or(100);

    // Retracted documents only for callers who may see them; for those, on
    // request (by default, included).
    let include_retracted = crate::api::auth::caller_sees_retracted(&state, &auth.claims)
        && params.include_retracted.unwrap_or(true);
    // No bucket named: the caller's agent bucket, like writes
    // (standards/bucket-scoping.md) — never every bucket. Admins keep the
    // cross-bucket listing (an aggregation).
    let named = crate::api::auth::parse_bucket_param(params.bucket.as_deref())?;
    let bucket_id = crate::api::auth::read_bucket(&state, &auth.claims, named).await?;
    let docs = state
        .client
        .list_docs_ex(tag_filter, limit, bucket_id.as_ref(), include_retracted)
        .await?;

    // `DocSummary` carries its own wire encoding (hex id, CID-string cid); the
    // client decodes it directly — no hand-built response (see `standards/`).
    Ok(Json(docs))
}

/// POST /api/v1/docs — 201 with the stored document (`node_id`, `cid`).
pub async fn create_doc(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateDocRequest>,
) -> Result<(StatusCode, Json<DocWire>), ApiError> {
    let vis = parse_visibility_str(req.visibility.as_deref());

    // No bucket named: the caller's agent bucket — what memctl's local
    // `put` does via `resolve_target_bucket`.
    let named = crate::api::auth::parse_bucket_param(req.bucket.as_deref())?;
    let bucket_id = crate::api::auth::write_bucket(&state, &auth.claims, named).await?;

    let doc_id = match req.id.as_deref() {
        Some(h) => {
            let id = parse_doc_id(h)?;
            // A client-chosen id must be new: it can't overwrite a document.
            // The answer is the same whoever's document holds it (it named
            // the id, telling the caller what other buckets hold).
            if state.client.get_doc(&id).await?.is_some() {
                return Err(ApiError::conflict("document id unavailable"));
            }
            id
        }
        None => memvault_core::DocId::random(),
    };
    let result = memvault_api::docs::create_doc_with_id(
        state.client.as_ref(),
        doc_id,
        &req.body,
        None,
        req.frontmatter.clone(),
        req.tags.clone(),
        vis,
        req.vfs_path.as_deref(),
        Some(&bucket_id),
    )
    .await?;
    tracing::info!(doc_id = %result.node_id, "API: doc created");

    Ok((
        StatusCode::CREATED,
        Json(DocWire {
            node_id: result.node_id,
            cid: Some(result.cid),
            body: req.body,
            frontmatter: result.frontmatter,
            tags: req.tags,
        }),
    ))
}

/// GET /api/v1/docs/:id — the document, in the scope asked for
/// ([`ScopeParams`]; retracted only for callers who may see it).
pub async fn get_doc(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(scope): Query<ScopeParams>,
) -> Result<Json<DocWire>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    crate::api::auth::enforce_doc_action(&auth.claims, &doc_id, memvault_auth::Action::Read)?;
    let scope = crate::api::auth::scope_from_params(&state, &auth.claims, &scope, false).await?;
    let doc = state
        .client
        .get_doc_scoped(&doc_id, &scope)
        .await?
        .ok_or_else(|| ApiError::not_found("Document not found"))?;
    let node_id = NodeRef::Doc(doc.id.clone()).tag_label();
    let tags = state.client.get_tags(&node_id).await?;
    Ok(Json(DocWire {
        node_id,
        cid: None,
        body: doc.body,
        frontmatter: doc.frontmatter,
        tags,
    }))
}

/// The body of `PUT /docs/{id}`: a [`TextPatch`] (`{"ops": [{"Retain": 5},
/// {"Insert": "x"}, …]}`), or the older `{"ops": [{"retain": 5}, …]}` form.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum UpdateDocRequest {
    Patch(TextPatch),
    Legacy { ops: Vec<LegacyTextOp> },
}

#[derive(Deserialize)]
pub struct LegacyTextOp {
    pub retain: Option<usize>,
    pub insert: Option<String>,
    pub delete: Option<usize>,
}

impl UpdateDocRequest {
    fn into_patch(self) -> Result<TextPatch, ApiError> {
        use memvault_doc::TextOp;
        match self {
            Self::Patch(p) => Ok(p),
            Self::Legacy { ops } => ops
                .into_iter()
                .map(|op| match (op.retain, op.insert, op.delete) {
                    (Some(n), None, None) => Ok(TextOp::Retain(n)),
                    (None, Some(s), None) => Ok(TextOp::Insert(s)),
                    (None, None, Some(n)) => Ok(TextOp::Delete(n)),
                    _ => Err(ApiError::bad_request(
                        "each op needs exactly one of retain, insert, delete",
                    )),
                })
                .collect::<Result<_, _>>()
                .map(|ops| TextPatch { ops }),
        }
    }
}

/// PUT /api/v1/docs/:id — apply a patch; the new envelope's CID.
pub async fn update_doc(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDocRequest>,
) -> Result<Json<CidReceipt>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    crate::api::auth::enforce_doc_action(&auth.claims, &doc_id, memvault_auth::Action::Write)?;
    let cid = state.client.edit_doc(&doc_id, req.into_patch()?).await?;
    Ok(Json(CidReceipt { cid }))
}

/// DELETE /api/v1/docs/:id?reason= — retract a document (by its id, hex) or
/// a block (by its CID); the retraction record's CID.
pub async fn delete_doc(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<ReasonParams>,
) -> Result<Json<CidReceipt>, ApiError> {
    let target = match parse_doc_id(&id) {
        Ok(doc_id) => {
            crate::api::auth::enforce_doc_action(
                &auth.claims,
                &doc_id,
                memvault_auth::Action::Write,
            )?;
            doc_id.0.to_vec()
        }
        Err(_) => {
            let cid = memvault_core::cid_bytes_lenient(&id)
                .map_err(|_| ApiError::bad_request("expected a document id or a CID"))?;
            // `doc:<hex>` resolves an envelope CID to its bucket too.
            crate::api::auth::enforce_node_action(
                &auth.claims,
                &format!("doc:{}", hex::encode(&cid)),
                memvault_auth::Action::Write,
            )?;
            cid
        }
    };
    let reason = params.reason.as_deref().unwrap_or("deleted via API");
    let cid = state.client.retract(&target, reason).await?;
    tracing::info!(id = %id, "API: doc retracted");
    Ok(Json(CidReceipt { cid }))
}

/// GET /api/v1/docs/:id/history
pub async fn doc_history(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<AuditRecordWire>>, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    crate::api::auth::enforce_doc_action(&auth.claims, &doc_id, memvault_auth::Action::Read)?;
    let records = state.client.history_of(&doc_id).await?;
    Ok(Json(
        records
            .iter()
            .map(|r| {
                let mut w = AuditRecordWire::from(r);
                w.doc_id.get_or_insert_with(|| doc_id.clone());
                w
            })
            .collect(),
    ))
}

/// Parse a document ID from either "doc:<hex>" or raw "<hex>" format.
pub fn parse_doc_id(input: &str) -> Result<DocId, ApiError> {
    DocId::from_hex(input)
        .map_err(|_| ApiError::bad_request("Invalid document ID — expected hex or doc:<hex>"))
}

pub(crate) use memvault_api::docs::parse_visibility as parse_visibility_str;
