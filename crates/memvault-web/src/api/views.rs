//! View management endpoints — CRUD for saved tag filter sets — and the
//! per-node tag and label endpoints.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use memvault_api::View;
use memvault_api::rest::{NodeLabel, ScopeParams, TagsRequest};

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

// ── Tag updates ────────────────────────────────────────────────────

/// PUT /api/v1/tags/:node_id — add tags to an item; 204.
pub async fn add_tags(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(req): Json<TagsRequest>,
) -> Result<StatusCode, ApiError> {
    // Tags drive view membership and search visibility — mutating them is
    // a write to the node's bucket.
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Write)?;
    state.client.add_tags(&node_id, req.tags).await?;
    tracing::debug!(node_id = %node_id, "API: tags added");
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/tags/:node_id — remove tags from an item; 204.
pub async fn remove_tags(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(req): Json<TagsRequest>,
) -> Result<StatusCode, ApiError> {
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Write)?;
    state.client.remove_tags(&node_id, req.tags).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/tags/:node_id — an item's effective tags, `[[scope, label], …]`.
pub async fn get_tags(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<Vec<(String, String)>>, ApiError> {
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Read)?;
    Ok(Json(state.client.get_tags(&node_id).await?))
}

/// GET /api/v1/labels/{node_id} — a node's display label (a doc's title, a
/// file's name, an entity's name) from the index, without loading the node,
/// in the scope asked for ([`ScopeParams`]).
pub async fn get_label(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Query(scope): Query<ScopeParams>,
) -> Result<Json<NodeLabel>, ApiError> {
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Read)?;
    let scope = crate::api::auth::scope_from_params(&state, &auth.claims, &scope, false).await?;
    let label = state.client.resolve_label_scoped(&node_id, &scope).await?;
    Ok(Json(NodeLabel { node_id, label }))
}

// ── Views ──────────────────────────────────────────────────────────

/// GET /api/v1/views — list all views.
pub async fn list_views(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<View>>, ApiError> {
    Ok(Json(state.client.list_views().await?))
}

/// A view as written: the name, filter tags and bucket from the request; the
/// time and CID are the server's.
fn view_to_store(name: String, req: View) -> View {
    View {
        name,
        tags: req.tags,
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: req.bucket_id,
    }
}

/// POST /api/v1/views — create a view (a `View` body); 201 with the view.
pub async fn create_view(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<View>,
) -> Result<(StatusCode, Json<View>), ApiError> {
    // A view narrowed to a bucket names that bucket: the caller must read it.
    if let Some(b) = &req.bucket_id {
        crate::api::auth::enforce_bucket_action(&auth.claims, b, memvault_auth::Action::Read)?;
    }
    let view = view_to_store(req.name.clone(), req);
    state.client.create_view(view.clone()).await?;
    tracing::info!(name = %view.name, "API: view created");
    Ok((StatusCode::CREATED, Json(view)))
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

/// PUT /api/v1/views/:name — replace a view's tags (a `View` body); 204.
pub async fn update_view(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<View>,
) -> Result<StatusCode, ApiError> {
    if let Some(b) = &req.bucket_id {
        crate::api::auth::enforce_bucket_action(&auth.claims, b, memvault_auth::Action::Read)?;
    }
    state.client.update_view(view_to_store(name, req)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/views/:name/members — the node ids matching this view's tags
/// that the caller may read, `[node_id, …]`.
pub async fn view_members(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<String>>, ApiError> {
    let retraction = crate::api::auth::retraction_for(&state, &auth.claims, None);
    let members = state
        .client
        .list_scoped(
            &memvault_core::QueryScope::all()
                .with_view(Some(name.clone()))
                .with_retraction(retraction),
            usize::MAX,
        )
        .await?
        .into_iter()
        .map(|n| n.node_id)
        .collect::<Vec<String>>();
    let members = crate::api::auth::filter_readable(&auth.claims, members, |m| m.clone())?;
    Ok(Json(members))
}

/// GET /api/v1/views/:name — get a single view.
pub async fn get_view(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<View>, ApiError> {
    state
        .client
        .get_view(&name)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("View not found"))
}
