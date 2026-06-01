//! File upload/download endpoints.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

#[derive(Serialize)]
pub struct FileListItem {
    pub name: String,
    pub content_type: String,
    pub size: u64,
    pub cid: String,
}

/// POST /api/v1/docs/:id/files — upload file (multipart)
pub async fn upload_doc_file(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if let Ok(doc_id) = super::docs::parse_doc_id(&id) {
        crate::api::auth::enforce_doc_action(&auth.claims, &doc_id, memvault_auth::Action::Write)?;
    }
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
        .upload_file(&data, Some(&name), &content_type, vec![], "internal", None)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "cid": format!("file:{}", hex::encode(&cid)),
            "name": name,
        })),
    ))
}

/// GET /api/v1/docs/:id/files — list files for a document
/// Note: With the new system, files are no longer embedded in documents.
/// This endpoint returns an empty list for backwards compatibility.
pub async fn list_doc_files(
    _auth: RequireAuth,
    State(_state): State<Arc<AppState>>,
    Path(_id): Path<String>,
) -> Result<Json<Vec<FileListItem>>, ApiError> {
    // Files are no longer embedded in documents in the new system.
    // This endpoint is kept for backwards compatibility but returns empty.
    Ok(Json(vec![]))
}

/// POST /api/v1/files — upload a file (multipart)
#[derive(Deserialize)]
pub struct UploadQuery {
    /// Optional VFS path to place the file at.
    pub vfs_path: Option<String>,
    /// Optional bucket ID (hex).
    pub bucket: Option<String>,
}

pub async fn upload_file(
    auth: RequireWrite,
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

    let bucket_id = query.bucket.as_deref().and_then(|h| {
        let bytes = hex::decode(h).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes);
        Some(memvault_core::BucketId(a))
    });
    if let Some(bid) = &bucket_id {
        crate::api::auth::enforce_bucket_action(&auth.claims, bid, memvault_auth::Action::Write)?;
    }
    let (manifest_cid, node_id) = memvault_api::files::upload_file(
        state.client.as_ref(),
        &data,
        Some(&name),
        &content_type,
        vec![],
        "internal",
        query.vfs_path.as_deref(),
        bucket_id.as_ref(),
    )
    .await?;
    tracing::info!(filename = %name, size = data.len(), "API: file uploaded");

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            // `cid` is the canonical manifest CID string; `node_id` is the
            // "file:<hex>" node label (see standards/ §1).
            "cid": memvault_core::cid_string_from_bytes(&manifest_cid)
                .unwrap_or_else(|_| hex::encode(&manifest_cid)),
            "node_id": node_id,
            "name": name,
        })),
    ))
}

/// GET /api/v1/files/:cid — download file by CID
pub async fn download_file(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Read)?;

    let data = state.client.read_file(&cid).await?;

    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        Bytes::from(data),
    ))
}

/// GET /api/v1/files/:cid/manifest — get file manifest metadata
pub async fn file_manifest(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Read)?;

    match state.client.get_file_manifest(&cid).await? {
        Some(data) => Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            Bytes::from(data),
        )),
        None => Err(ApiError::not_found("Manifest not found")),
    }
}

/// POST /api/v1/files/:cid/pin — pin a file so it is never GC'd.
pub async fn pin_file(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Write)?;
    state.client.pin_file(&cid).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/files/:cid/pin — remove a pin.
pub async fn unpin_file(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Write)?;
    state.client.unpin_file(&cid).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/files/:cid/extracted-text — extracted plain text, if any.
pub async fn extracted_text(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Read)?;
    let text = state.client.read_extracted_text(&cid).await?;
    Ok(Json(serde_json::json!({ "text": text })))
}

/// GET /api/v1/pins — list pinned files as [{ cid, name }].
pub async fn list_pinned(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pins = state.client.list_pinned().await?;
    let result: Vec<serde_json::Value> = pins
        .into_iter()
        .map(|(cid, name)| {
            serde_json::json!({
                "cid": memvault_core::cid_string_from_bytes(&cid)
                    .unwrap_or_else(|_| hex::encode(&cid)),
                "name": name,
            })
        })
        .collect();
    Ok(Json(serde_json::json!(result)))
}

/// DELETE /api/v1/docs/:id/files/:name — detach file (no-op in new system)
pub async fn detach_file(
    _auth: RequireWrite,
    State(_state): State<Arc<AppState>>,
    Path((_id, _name)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    // In the new system, files are standalone objects.
    // Detaching from a doc is a no-op.
    Ok(StatusCode::NO_CONTENT)
}
