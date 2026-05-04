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
pub mod views;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use axum::Router;

use crate::AppState;

/// Build all API v1 routes.
///
/// All node IDs use "type:hex" format: entity:<hex>, doc:<hex>, attachment:<hex>.
/// Legacy /docs and /entities endpoints accept both raw hex and type:hex.
pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        // ── Nodes (unified) ────────────────────────────────────────
        // The primary API for all node types. Uses type:hex IDs everywhere.
        .route("/nodes", get(links::list_nodes))
        .route("/nodes/{node_id}", get(links::get_node).delete(links::retract_node))

        // ── Links (cross-type edges) ───────────��───────────────────
        .route("/links", post(links::create_link).get(links::list_links))
        .route("/links/{edge_id}", delete(links::delete_link))

        // ── Tags ────────────────────────────────────────────��──────
        .route("/tags/{node_id}", get(views::get_tags).put(views::add_tags).delete(views::remove_tags))

        // ── Views ──────────────────────────────────────────────────
        .route("/views", get(views::list_views).post(views::create_view))
        .route("/views/{name}", get(views::get_view).put(views::update_view).delete(views::delete_view))
        .route("/views/{name}/members", get(views::view_members))

        // ── Search ─────────────────────────────────────────────────
        .route("/search", get(search::search))

        // ── Audit ────────────────────���─────────────────────────────
        .route("/audit", get(audit::query_audit))

        // ── Documents (type-specific, accepts raw hex or doc:hex) ──
        .route("/docs", get(docs::list_docs).post(docs::create_doc))
        .route("/docs/{id}", get(docs::get_doc).put(docs::update_doc).delete(docs::delete_doc))
        .route("/docs/{id}/history", get(docs::doc_history))

        // ── Entities (type-specific, accepts raw hex or entity:hex)
        .route("/entities", post(graph::create_entity))
        .route("/entities/{id}", get(graph::get_entity).delete(graph::delete_entity))

        // ── Attachments ──────────��─────────────────────────────────
        .route("/attachments", post(attachments::upload_standalone))
        .route("/attachments/{cid}", get(attachments::download_attachment))
        .route("/attachments/{cid}/manifest", get(attachments::attachment_manifest))

        // ── File upload body limit (2GB) ───────────────────────────
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024))

        // ─��� Admin ───────────��──────────────────────────────────────
        .route("/admin/status", get(admin::status))
        .route("/admin/peers", get(admin::peers))
        .route("/admin/tokens", post(admin::issue_token).get(admin::list_tokens))
        .route("/admin/tokens/{cid}", delete(admin::revoke_token))
        .route("/admin/rotations", get(admin::list_rotations))

        // ── Events & Ops ───────────────────────────────────────────
        .route("/events", get(events::events_stream))
        .route("/metrics", get(ops::metrics))
        .route("/health", get(ops::health))

        .with_state(state)
}
