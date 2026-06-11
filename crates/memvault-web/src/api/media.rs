//! Media extraction endpoints — extraction state (text/OCR/transcript),
//! page-render manifests, and per-page images + selectable text layers.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;

use memvault_api::types::{ExtractionInfo, PageRenderInfo, PageTextLayer};

use crate::AppState;
use crate::api::auth::RequireAuth;
use crate::error::ApiError;

/// GET /api/v1/files/:cid/extraction — unified extraction state for a file
/// (plain text, OCR text, or audio transcript) with job status. Lazily
/// triggers background extraction; `status: "pending"` means poll again.
pub async fn extraction(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<Json<ExtractionInfo>, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Read)?;

    let info = state.client.read_extraction(&cid).await?;
    Ok(Json(info))
}

/// GET /api/v1/files/:cid/pages — page-render manifest (status + per-page
/// dims, no image bytes). Lazily triggers rendering; pending = poll again.
pub async fn page_render(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(cid_hex): Path<String>,
) -> Result<Json<PageRenderInfo>, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Read)?;

    let info = state.client.read_page_render(&cid).await?;
    Ok(Json(info))
}

/// GET /api/v1/files/:cid/pages/:page_no/image — raw image bytes for one
/// rendered page (1-based). Page renders are content-addressed by the file
/// CID, so the image for a given (cid, page) never changes: serve it with
/// an immutable cache policy and a strong ETag.
pub async fn page_image(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path((cid_hex, page_no)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Read)?;

    let etag = format!("\"{}-p{}\"", hex::encode(&cid), page_no);
    const CACHE_CONTROL: &str = "private, max-age=31536000, immutable";

    // Conditional request: the content for a (cid, page) pair is immutable,
    // so a matching If-None-Match short-circuits before touching the blob.
    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok())
        && inm.split(',').any(|t| t.trim() == etag || t.trim() == "*")
    {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag),
                (header::CACHE_CONTROL, CACHE_CONTROL.to_string()),
            ],
        )
            .into_response());
    }

    match state.client.read_page_image(&cid, page_no).await? {
        Some((bytes, mime)) => Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime),
                (header::ETAG, etag),
                (header::CACHE_CONTROL, CACHE_CONTROL.to_string()),
            ],
            Bytes::from(bytes),
        )
            .into_response()),
        None => Err(ApiError::not_found("Page image not available")),
    }
}

/// GET /api/v1/files/:cid/pages/:page_no/text-layer — positioned word boxes
/// for one rendered page (coords in image pixel space).
pub async fn page_text_layer(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path((cid_hex, page_no)): Path<(String, u32)>,
) -> Result<Json<PageTextLayer>, ApiError> {
    // Canonical form is the CID string; legacy bare hex is still accepted.
    let cid = memvault_core::cid_bytes_lenient(&cid_hex)
        .map_err(|_| ApiError::bad_request("Invalid CID"))?;
    crate::api::auth::enforce_file_action(&auth.claims, &cid, memvault_auth::Action::Read)?;

    match state.client.read_page_text_layer(&cid, page_no).await? {
        Some(layer) => Ok(Json(layer)),
        None => Err(ApiError::not_found("Text layer not available")),
    }
}
