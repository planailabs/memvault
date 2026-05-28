//! API route registration.

pub mod admin;
pub mod agents;
pub mod audit;
pub mod auth;
pub mod buckets;
pub mod docs;
pub mod enroll;
pub mod events;
pub mod files;
pub mod graph;
pub mod links;
pub mod ops;
pub mod search;
pub mod vfs;
pub mod views;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};

use crate::AppState;

/// Build all API v1 routes.
///
/// All node IDs use "type:hex" format: entity:<hex>, doc:<hex>, file:<hex>.
/// Legacy /docs and /entities endpoints accept both raw hex and type:hex.
pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        // ── Nodes (unified) ────────────────────────────────────────
        // The primary API for all node types. Uses type:hex IDs everywhere.
        .route("/nodes", get(links::list_nodes))
        .route(
            "/nodes/{node_id}",
            get(links::get_node).delete(links::retract_node),
        )
        // ── Links (cross-type edges) ───────────��───────────────────
        .route("/links", post(links::create_link).get(links::list_links))
        .route("/links/{edge_id}", delete(links::delete_link))
        // ── Tags ────────────────────────────────────────────��──────
        .route(
            "/tags/{node_id}",
            get(views::get_tags)
                .put(views::add_tags)
                .delete(views::remove_tags),
        )
        // ── Views ──────────────────────────────────────────────────
        .route("/views", get(views::list_views).post(views::create_view))
        .route(
            "/views/{name}",
            get(views::get_view)
                .put(views::update_view)
                .delete(views::delete_view),
        )
        .route("/views/{name}/members", get(views::view_members))
        // ── Search ─────────────────────────────────────────────────
        .route("/search", get(search::search))
        // ── Audit ────────────────────���─────────────────────────────
        .route("/audit", get(audit::query_audit))
        // ── Documents (type-specific, accepts raw hex or doc:hex) ──
        .route("/docs", get(docs::list_docs).post(docs::create_doc))
        .route(
            "/docs/{id}",
            get(docs::get_doc)
                .put(docs::update_doc)
                .delete(docs::delete_doc),
        )
        .route("/docs/{id}/history", get(docs::doc_history))
        // ── Entities (type-specific, accepts raw hex or entity:hex)
        .route("/entities", post(graph::create_entity))
        .route(
            "/entities/{id}",
            get(graph::get_entity).delete(graph::delete_entity),
        )
        // ── Files ────────────────────────────────────────────────────
        .route("/files", post(files::upload_file))
        .route("/files/{cid}", get(files::download_file))
        .route("/files/{cid}/manifest", get(files::file_manifest))
        // Backward compat: keep old /attachments routes working
        .route("/attachments", post(files::upload_file))
        .route("/attachments/{cid}", get(files::download_file))
        .route("/attachments/{cid}/manifest", get(files::file_manifest))
        // ── VFS (virtual filesystem) ───────────────────────────────
        .route("/vfs", get(vfs::vfs_ls).delete(vfs::vfs_unlink))
        .route("/vfs/resolve", get(vfs::vfs_resolve))
        .route("/vfs/mkdir", post(vfs::vfs_mkdir))
        .route("/vfs/link", post(vfs::vfs_link))
        .route("/vfs/mv", post(vfs::vfs_mv))
        // ── File upload body limit (2GB) ───────────────────────────
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024))
        // ─��� Admin ───────────��──────────────────────────────────────
        .route("/admin/status", get(admin::status))
        .route("/admin/peers", get(admin::peers))
        .route(
            "/admin/tokens",
            post(admin::issue_token).get(admin::list_tokens),
        )
        .route("/admin/tokens/{cid}", delete(admin::revoke_token))
        .route("/admin/rotations", get(admin::list_rotations))
        // ── Buckets ────────────────────────────────────────────────
        .route(
            "/buckets",
            get(buckets::list_buckets).post(buckets::create_bucket),
        )
        // Register static `/buckets/agent` before the `{id}` route so it
        // is not captured as `id = "agent"`.
        .route("/buckets/agent", post(buckets::ensure_agent_bucket))
        .route(
            "/buckets/{id}",
            get(buckets::get_bucket).patch(buckets::rename_bucket),
        )
        .route("/buckets/{id}/attach", post(buckets::attach_bucket))
        .route("/buckets/{id}/archive", post(buckets::archive_bucket))
        // ── Auth (session token for web UI) ───────────────────────
        .route("/auth/session-token", get(auth::get_session_token))
        // ── Agent enrollment (token-authenticated; no Bearer needed).
        //    Wire equivalent of `memctl agent-enroll`.
        .route("/auth/enroll-agent", post(enroll::enroll_agent))
        // ── Events & Ops ───────────────────────────────────────────
        .route("/events", get(events::events_stream))
        .route("/metrics", get(ops::metrics))
        .route("/health", get(ops::health))
        .with_state(state)
}
