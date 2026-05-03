//! API route registration.

pub mod admin;
pub mod attachments;
pub mod audit;
pub mod auth;
pub mod docs;
pub mod events;
pub mod graph;
pub mod links;
pub mod ops;
pub mod search;

use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::AppState;

/// Build all API v1 routes.
pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        // Auth
        .route("/auth", post(auth_placeholder))
        // Documents
        .route("/docs", get(docs::list_docs).post(docs::create_doc))
        .route(
            "/docs/{id}",
            get(docs::get_doc).put(docs::update_doc).delete(docs::delete_doc),
        )
        .route("/docs/{id}/history", get(docs::doc_history))
        // Attachments
        .route(
            "/docs/{id}/attachments",
            post(attachments::upload_attachment).get(attachments::list_attachments),
        )
        .route(
            "/docs/{id}/attachments/{name}",
            delete(attachments::detach_attachment),
        )
        .route("/attachments/{cid}", get(attachments::download_attachment))
        .route("/attachments/{cid}/manifest", get(attachments::attachment_manifest))
        // Graph
        .route("/entities", post(graph::create_entity))
        .route(
            "/entities/{id}",
            get(graph::get_entity).delete(graph::delete_entity),
        )
        .route("/entities/{id}/edges", post(graph::add_edge))
        .route(
            "/entities/{id}/edges/{edge_id}",
            delete(graph::remove_edge),
        )
        .route("/entities/{id}/traverse", get(graph::traverse))
        // Links (cross-type edges)
        .route("/links", post(links::create_link).get(links::list_links))
        .route("/links/{edge_id}", delete(links::delete_link))
        // Search
        .route("/search", get(search::search))
        // Audit
        .route("/audit", get(audit::query_audit))
        // Admin
        .route("/admin/status", get(admin::status))
        .route("/admin/peers", get(admin::peers))
        .route(
            "/admin/tokens",
            post(admin::issue_token).get(admin::list_tokens),
        )
        .route("/admin/tokens/{cid}", delete(admin::revoke_token))
        .route("/admin/rotations", get(admin::list_rotations))
        // Events
        .route("/events", get(events::events_stream))
        // Ops (metrics + health)
        .route("/metrics", get(ops::metrics))
        .route("/health", get(ops::health))
        .with_state(state)
}

/// POST /api/v1/auth — placeholder for Phase 7 (returns the token back).
async fn auth_placeholder(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
    axum::Json(serde_json::json!({ "bearer": token }))
}
