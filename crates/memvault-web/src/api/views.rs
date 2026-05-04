//! View management endpoints — CRUD for saved tag filter sets.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::api::auth::RequireAuth;
use crate::error::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct CreateViewRequest {
    pub name: String,
    pub tags: Vec<(String, String)>,
}

/// GET /api/v1/views — list all views.
pub async fn list_views(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let views = state.client.list_views().await?;
    Ok(Json(serde_json::json!(views)))
}

/// POST /api/v1/views — create a view.
pub async fn create_view(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateViewRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let view = memvault_api::View {
        name: req.name.clone(),
        tags: req.tags,
        created_ns: memvault_core::wall_ns(),
    };
    state.client.create_view(view).await?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "name": req.name, "status": "created" }))))
}

/// DELETE /api/v1/views/:name — delete a view.
pub async fn delete_view(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.client.delete_view(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/views/:name — get a single view.
pub async fn get_view(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    match state.client.get_view(&name).await? {
        Some(view) => Ok(Json(serde_json::json!(view))),
        None => Err(ApiError::not_found("View not found")),
    }
}
