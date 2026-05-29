//! View management endpoints — CRUD for saved tag filter sets.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct CreateViewRequest {
    pub name: String,
    pub tags: Vec<(String, String)>,
}

// ── Tag updates ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TagUpdateRequest {
    pub tags: Vec<(String, String)>,
}

/// PUT /api/v1/tags/:node_id — add tags to an item.
pub async fn add_tags(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(req): Json<TagUpdateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Tags drive view membership and search visibility — mutating them is
    // a write to the node's bucket.
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Write)?;
    state.client.add_tags(&node_id, req.tags).await?;
    tracing::debug!(node_id = %node_id, "API: tags added");
    Ok(Json(
        serde_json::json!({ "node_id": node_id, "status": "tags_added" }),
    ))
}

/// DELETE /api/v1/tags/:node_id — remove tags from an item.
pub async fn remove_tags(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(req): Json<TagUpdateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Write)?;
    state.client.remove_tags(&node_id, req.tags).await?;
    Ok(Json(
        serde_json::json!({ "node_id": node_id, "status": "tags_removed" }),
    ))
}

/// GET /api/v1/tags/:node_id — get effective tags for an item.
pub async fn get_tags(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Read)?;
    let tags = state.client.get_tags(&node_id).await?;
    Ok(Json(
        serde_json::json!({ "node_id": node_id, "tags": tags }),
    ))
}

// ── Views ──────────────────────────────────────────────────────────

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
    _auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateViewRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let view = memvault_api::View {
        name: req.name.clone(),
        tags: req.tags,
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    state.client.create_view(view).await?;
    tracing::info!(name = %req.name, "API: view created");
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "name": req.name, "status": "created" })),
    ))
}

/// DELETE /api/v1/views/:name — delete a view.
pub async fn delete_view(
    _auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.client.delete_view(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// PUT /api/v1/views/:name — update a view's tags.
pub async fn update_view(
    _auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<CreateViewRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let view = memvault_api::View {
        name: name.clone(),
        tags: req.tags,
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    state.client.update_view(view).await?;
    Ok(Json(
        serde_json::json!({ "name": name, "status": "updated" }),
    ))
}

/// GET /api/v1/views/:name/members — list node_ids matching this view's tags.
pub async fn view_members(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let members = state.client.view_members(&name).await?;
    let members = crate::api::auth::filter_readable(&auth.claims, members, |m| m.clone())?;
    Ok(Json(
        serde_json::json!({ "view": name, "count": members.len(), "members": members }),
    ))
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
