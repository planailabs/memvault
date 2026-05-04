//! File upload/download endpoints.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

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
    Path(_id): Path<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
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
        .attach_file(&data, Some(&name), &content_type, vec![], "internal")
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "cid": format!("attachment:{}", hex::encode(&cid)),
            "name": name,
        })),
    ))
}

/// GET /api/v1/docs/:id/attachments — list attachments for a document
/// Note: With the new system, attachments are no longer embedded in documents.
/// This endpoint returns an empty list for backwards compatibility.
pub async fn list_attachments(
    _auth: RequireAuth,
    State(_state): State<Arc<AppState>>,
    Path(_id): Path<String>,
) -> Result<Json<Vec<AttachmentListItem>>, ApiError> {
    // Attachments are no longer embedded in documents in the new system.
    // This endpoint is kept for backwards compatibility but returns empty.
    Ok(Json(vec![]))
}

/// POST /api/v1/attachments — upload a standalone file attachment (multipart)
#[derive(Deserialize)]
pub struct UploadQuery {
    /// Optional VFS path to place the attachment at.
    pub vfs_path: Option<String>,
}

pub async fn upload_standalone(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(query): Query<UploadQuery>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
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
        .attach_file(&data, Some(&name), &content_type, vec![], "internal")
        .await?;
    let node_id = format!("attachment:{}", hex::encode(&cid));
    tracing::info!(filename = %name, size = data.len(), "API: file uploaded");

    if let Some(vfs_path) = &query.vfs_path {
        if let Err(e) = super::vfs::link_node_at_path(state.client.as_ref(), vfs_path, &node_id).await {
            tracing::warn!(path = %vfs_path, error = %e, "VFS link failed after attachment upload");
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "cid": node_id,
            "name": name,
        })),
    ))
}

/// GET /api/v1/attachments/:cid — download attachment by CID
pub async fn download_attachment(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let cid = hex::decode(&cid_hex).map_err(|_| ApiError::bad_request("Invalid CID hex"))?;

    let data = state.client.read_attachment(&cid).await?;

    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        Bytes::from(data),
    ))
}

/// GET /api/v1/attachments/:cid/manifest — get attachment manifest metadata
pub async fn attachment_manifest(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let cid = hex::decode(&cid_hex).map_err(|_| ApiError::bad_request("Invalid CID hex"))?;

    match state.client.get_attachment_manifest(&cid).await? {
        Some(data) => Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            Bytes::from(data),
        )),
        None => Err(ApiError::not_found("Manifest not found")),
    }
}

/// DELETE /api/v1/docs/:id/attachments/:name — detach file (no-op in new system)
pub async fn detach_attachment(
    _auth: RequireAuth,
    State(_state): State<Arc<AppState>>,
    Path((_id, _name)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    // In the new system, attachments are standalone objects.
    // Detaching from a doc is a no-op.
    Ok(StatusCode::NO_CONTENT)
}
