//! File upload/download endpoints.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use memvault_core::DocId;
use serde::Serialize;

use crate::api::auth::RequireAuth;
use crate::error::ApiError;
use crate::AppState;

#[derive(Serialize)]
pub struct AttachmentListItem {
    pub name: String,
    pub content_type: String,
    pub size: u64,
    pub cid: String,
}

/// POST /api/v1/docs/:id/attachments — upload file attachment (multipart)
pub async fn upload_attachment(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let doc_id = parse_doc_id(&id)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Multipart error: {e}")))?
        .ok_or_else(|| ApiError::bad_request("No file field in multipart body"))?;

    let name = field.file_name().unwrap_or("unnamed").to_string();
    let content_type = field
        .content_type()
        .unwrap_or("application/octet-stream")
        .to_string();
    let data = field
        .bytes()
        .await
        .map_err(|e| ApiError::bad_request(format!("Failed to read file: {e}")))?;

    let cid = state
        .client
        .attach_file(&doc_id, &name, &content_type, &data)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "cid": hex::encode(&cid),
            "name": name,
        })),
    ))
}

/// GET /api/v1/docs/:id/attachments — list attachments for a document
pub async fn list_attachments(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<AttachmentListItem>>, ApiError> {
    let doc_id = parse_doc_id(&id)?;

    let doc = state
        .client
        .get_doc(&doc_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Document not found"))?;

    let items: Vec<AttachmentListItem> = doc
        .attachments
        .iter()
        .map(|a| AttachmentListItem {
            name: a.name.clone(),
            content_type: a.content_type.clone(),
            size: a.size,
            cid: hex::encode(&a.cid),
        })
        .collect();

    Ok(Json(items))
}

/// GET /api/v1/attachments/:cid — download attachment by CID
pub async fn download_attachment(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let cid = hex::decode(&cid_hex).map_err(|_| ApiError::bad_request("Invalid CID hex"))?;

    let data = state.client.get_attachment(&cid).await?;

    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        Bytes::from(data),
    ))
}

/// DELETE /api/v1/docs/:id/attachments/:name — detach file
pub async fn detach_attachment(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path((id, name)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let doc_id = parse_doc_id(&id)?;
    state.client.detach_file(&doc_id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_doc_id(hex_str: &str) -> Result<DocId, ApiError> {
    let bytes = hex::decode(hex_str).map_err(|_| ApiError::bad_request("Invalid document ID"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request("Document ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(DocId(arr))
}
