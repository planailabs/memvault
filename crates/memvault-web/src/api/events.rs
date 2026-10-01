//! SSE events endpoint.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::response::sse::{Event, Sse};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use memvault_api::MemvaultEvent;

use crate::AppState;
use crate::api::auth::RequireAuth;
use crate::error::ApiError;

/// GET /api/v1/events — SSE stream of MemvaultEvents, only those about what
/// the caller may read (standards/client-parity.md): a document, entity or
/// file in a bucket it may read, a bucket it may read, and — to admins and
/// auditors only — cluster membership events (token redemptions, sigchain
/// blocks). Read decisions are cached per bucket for the connection.
pub async fn events_stream(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    let cluster_events = matches!(
        crate::api::auth::caller_role(&state, &auth.claims),
        Some(memvault_auth::AgentRole::Admin) | Some(memvault_auth::AgentRole::Auditor)
    );
    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        // Lagged messages are skipped.
        let event = result.ok()?;
        visible(&event, &mut readable, cluster_events).then(|| Ok(event_to_sse(event)))
    });
    Ok(Sse::new(stream))
}

/// Whether the caller may see `event`.
fn visible(
    event: &MemvaultEvent,
    readable: &mut crate::api::auth::Readable,
    cluster_events: bool,
) -> bool {
    match event {
        MemvaultEvent::DocCreated { doc_id, .. }
        | MemvaultEvent::DocUpdated { doc_id, .. }
        | MemvaultEvent::FileAttached { doc_id, .. } => {
            readable.node(&format!("doc:{}", hex::encode(doc_id.0)))
        }
        MemvaultEvent::EntityCreated { entity_id } => {
            readable.node(&format!("entity:{}", hex::encode(entity_id.0)))
        }
        // `doc:<cid>` resolves an envelope CID to its bucket.
        MemvaultEvent::Retracted { cid } => readable.node(&format!("doc:{}", hex::encode(cid))),
        MemvaultEvent::BucketCreated { bucket_id, .. } => readable.bucket(bucket_id),
        MemvaultEvent::TokenConsumed { .. } | MemvaultEvent::SigchainBlock { .. } => cluster_events,
    }
}

fn event_to_sse(event: MemvaultEvent) -> Event {
    match event {
        MemvaultEvent::DocCreated { doc_id, cid } => Event::default()
            .event("doc_created")
            .data(serde_json::json!({"node_id": format!("doc:{}", hex::encode(doc_id.0)), "cid": hex::encode(&cid)}).to_string()),
        MemvaultEvent::DocUpdated { doc_id, cid } => Event::default()
            .event("doc_updated")
            .data(serde_json::json!({"node_id": format!("doc:{}", hex::encode(doc_id.0)), "cid": hex::encode(&cid)}).to_string()),
        MemvaultEvent::FileAttached { doc_id, name } => Event::default()
            .event("file_attached")
            .data(serde_json::json!({"node_id": format!("doc:{}", hex::encode(doc_id.0)), "name": name}).to_string()),
        MemvaultEvent::EntityCreated { entity_id } => Event::default()
            .event("entity_created")
            .data(serde_json::json!({"node_id": format!("entity:{}", hex::encode(entity_id.0))}).to_string()),
        MemvaultEvent::Retracted { cid } => Event::default()
            .event("retracted")
            .data(serde_json::json!({"cid": hex::encode(&cid)}).to_string()),
        MemvaultEvent::TokenConsumed { token_cid } => Event::default()
            .event("token_consumed")
            .data(serde_json::json!({"token_cid": hex::encode(&token_cid)}).to_string()),
        MemvaultEvent::BucketCreated { bucket_id, cid } => Event::default()
            .event("bucket_created")
            .data(serde_json::json!({"bucket_id": bucket_id.to_string(), "cid": hex::encode(&cid)}).to_string()),
        MemvaultEvent::SigchainBlock { label, cid } => Event::default()
            .event("sigchain_block")
            .data(serde_json::json!({"label": label, "cid": hex::encode(&cid)}).to_string()),
    }
}
