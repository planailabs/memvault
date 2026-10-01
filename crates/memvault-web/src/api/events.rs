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

/// The data of an SSE event (its name is the event type): node references as
/// `"type:hex"` labels, the bucket id hex, CIDs CID strings
/// (standards/api-wire-conventions.md §1).
#[derive(serde::Serialize)]
#[serde(untagged)]
enum EventData {
    /// `doc_created`, `doc_updated`.
    Doc {
        node_id: String,
        #[serde(with = "memvault_api::wire::cid_str")]
        cid: Vec<u8>,
    },
    /// `file_attached`.
    FileAttached { node_id: String, name: String },
    /// `entity_created`.
    Entity { node_id: String },
    /// `retracted`.
    Retracted {
        #[serde(with = "memvault_api::wire::cid_str")]
        cid: Vec<u8>,
    },
    /// `token_consumed`.
    TokenConsumed {
        #[serde(with = "memvault_api::wire::cid_str")]
        token_cid: Vec<u8>,
    },
    /// `bucket_created`.
    BucketCreated {
        #[serde(with = "memvault_api::wire::hex_id")]
        bucket_id: memvault_core::BucketId,
        #[serde(with = "memvault_api::wire::cid_str")]
        cid: Vec<u8>,
    },
    /// `sigchain_block`.
    SigchainBlock {
        label: String,
        #[serde(with = "memvault_api::wire::cid_str")]
        cid: Vec<u8>,
    },
}

fn event_to_sse(event: MemvaultEvent) -> Event {
    use memvault_core::NodeRef;
    let (name, data) = match event {
        MemvaultEvent::DocCreated { doc_id, cid } => (
            "doc_created",
            EventData::Doc {
                node_id: NodeRef::Doc(doc_id).tag_label(),
                cid,
            },
        ),
        MemvaultEvent::DocUpdated { doc_id, cid } => (
            "doc_updated",
            EventData::Doc {
                node_id: NodeRef::Doc(doc_id).tag_label(),
                cid,
            },
        ),
        MemvaultEvent::FileAttached { doc_id, name } => (
            "file_attached",
            EventData::FileAttached {
                node_id: NodeRef::Doc(doc_id).tag_label(),
                name,
            },
        ),
        MemvaultEvent::EntityCreated { entity_id } => (
            "entity_created",
            EventData::Entity {
                node_id: NodeRef::Entity(entity_id).tag_label(),
            },
        ),
        MemvaultEvent::Retracted { cid } => ("retracted", EventData::Retracted { cid }),
        MemvaultEvent::TokenConsumed { token_cid } => {
            ("token_consumed", EventData::TokenConsumed { token_cid })
        }
        MemvaultEvent::BucketCreated { bucket_id, cid } => (
            "bucket_created",
            EventData::BucketCreated { bucket_id, cid },
        ),
        MemvaultEvent::SigchainBlock { label, cid } => {
            ("sigchain_block", EventData::SigchainBlock { label, cid })
        }
    };
    Event::default()
        .event(name)
        .json_data(data)
        .unwrap_or_else(|_| Event::default().event(name))
}
