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
pub mod media;
pub mod ops;
pub mod search;
pub mod skills;
pub mod vfs;
pub mod views;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, patch, post};

use crate::AppState;

/// Build all API v1 routes.
///
/// All node IDs use "type:hex" format: entity:<hex>, doc:<hex>, file:<hex>.
/// Legacy /docs and /entities endpoints accept both raw hex and type:hex.
pub fn routes(state: Arc<AppState>) -> Router {
    let origin_layer = from_fn_with_state(Arc::clone(&state), auth::origin_guard);
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
        .route("/entities", post(graph::create_entity).get(graph::list_entities))
        .route("/traverse", get(graph::traverse))
        // ── Skills (first-class entity aggregates) ─────────────────
        .route("/skills", get(skills::list_skills).post(skills::publish_skill))
        .route(
            "/skills/{id}",
            get(skills::get_skill)
                .patch(skills::rename_skill)
                .delete(skills::delete_skill),
        )
        .route("/skills/{id}/resources", post(skills::link_resource))
        .route(
            "/skills/{id}/resources/{edge_id}",
            delete(skills::unlink_resource),
        )
        .route(
            "/entities/{id}",
            get(graph::get_entity).delete(graph::delete_entity),
        )
        // ── Files ────────────────────────────────────────────────────
        .route("/files", post(files::upload_file))
        .route("/files/{cid}", get(files::download_file))
        .route("/files/{cid}/manifest", get(files::file_manifest))
        .route(
            "/files/{cid}/pin",
            post(files::pin_file).delete(files::unpin_file),
        )
        .route("/files/{cid}/extracted-text", get(files::extracted_text))
        // ── Media extraction (text / OCR / transcript / page renders) ──
        .route("/files/{cid}/extraction", get(media::extraction))
        .route("/files/{cid}/pages", get(media::page_render))
        .route("/files/{cid}/pages/{page_no}/image", get(media::page_image))
        .route(
            "/files/{cid}/pages/{page_no}/text-layer",
            get(media::page_text_layer),
        )
        .route("/pins", get(files::list_pinned))
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
        .route("/vfs/tree", get(vfs::vfs_tree))
        .route("/vfs/find", get(vfs::vfs_find))
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
        .route(
            "/admin/keys",
            get(admin::list_admin_keys).post(admin::admit_admin_key),
        )
        .route("/admin/keys/retire", post(admin::retire_admin_key))
        // ── Buckets ────────────────────────────────────────────────
        .route(
            "/buckets",
            get(buckets::list_buckets).post(buckets::create_bucket),
        )
        // Register static `/buckets/agent` before the `{id}` route so it
        // is not captured as `id = "agent"`.
        .route("/buckets/agent", post(buckets::ensure_agent_bucket))
        // Static merge routes before `{id}` so they aren't captured as ids.
        .route("/buckets/merge", post(buckets::merge_buckets))
        .route("/buckets/unmerge", post(buckets::unmerge_buckets))
        .route("/buckets/merges", get(buckets::list_merges))
        .route(
            "/buckets/{id}",
            get(buckets::get_bucket).patch(buckets::rename_bucket),
        )
        .route(
            "/buckets/{id}/grants",
            get(buckets::list_grants).post(buckets::submit_grant),
        )
        // Set an agent's display label (the agent itself or an Admin).
        .route("/agents/{pubkey}", patch(agents::rename_agent))
        .route("/buckets/{id}/issue-grant", post(buckets::issue_grant))
        .route("/grants/{cid}/revoke", post(buckets::revoke_grant))
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
        // CSRF defence: cookie-bearing cross-origin POSTs/PUTs/DELETEs are
        // refused. Bearer-token clients (memctl, curl scripts) keep working
        // because they don't set Origin and don't carry a session cookie.
        .layer(origin_layer)
        .with_state(state)
}
