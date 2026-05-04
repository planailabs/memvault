//! SSE events endpoint.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::response::sse::{Event, Sse};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use memvault_api::MemvaultEvent;

use crate::api::auth::RequireAuth;
use crate::AppState;

/// GET /api/v1/events — SSE stream of MemvaultEvents.
pub async fn events_stream(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        match result {
            Ok(event) => Some(Ok(event_to_sse(event))),
            Err(_) => None, // skip lagged messages
        }
    });
    Sse::new(stream)
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
    }
}
