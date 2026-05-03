//! SSE event client for real-time UI updates.
//!
//! Connects to `/api/v1/events` and bumps a revision counter on each
//! event, which downstream pages can use to trigger refetches.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Recent event for display in activity feeds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecentEvent {
    pub kind: String,
    pub detail: String,
    pub timestamp_ms: u64,
}

/// Shared event bus context — provided at the Layout level.
#[derive(Debug, Clone)]
pub struct EventBusContext {
    /// Bumped on every SSE event. Pages watch this to invalidate data.
    pub revision: Signal<u64>,
    /// Recent events (newest first, capped at 50).
    pub recent: Signal<Vec<RecentEvent>>,
}

/// Provide the event bus context. Call once in the Layout component.
pub fn use_event_bus_provider() -> EventBusContext {
    let revision = use_signal(|| 0u64);
    let recent = use_signal(Vec::<RecentEvent>::new);
    use_context_provider(|| revision);
    use_context_provider(|| recent);

    let ctx = EventBusContext { revision, recent };

    // Start the SSE listener on the client side only.
    #[cfg(feature = "web")]
    {
        let mut rev = ctx.revision;
        let mut rec = ctx.recent;
        use_effect(move || {
            spawn(async move {
                use wasm_bindgen::closure::Closure;
                use wasm_bindgen::JsCast;
                use web_sys::MessageEvent;

                let window = web_sys::window().unwrap();
                let origin = window.location().origin().unwrap_or_default();
                let url = format!("{origin}/api/v1/events");

                let Ok(es) = web_sys::EventSource::new(&url) else {
                    tracing::warn!("failed to create EventSource");
                    return;
                };

                let rev_clone = rev;
                let rec_clone = rec;
                let on_message = Closure::<dyn Fn(MessageEvent)>::new(move |e: MessageEvent| {
                    let data = e.data().as_string().unwrap_or_default();
                    let kind = e.type_().to_string();

                    // Bump revision counter.
                    rev.set(*rev_clone.read() + 1);

                    // Push to recent events (cap at 50).
                    let event = RecentEvent {
                        kind,
                        detail: data,
                        timestamp_ms: js_sys::Date::now() as u64,
                    };
                    let mut list = rec_clone.read().clone();
                    list.insert(0, event);
                    list.truncate(50);
                    rec.set(list);
                });

                // Listen to all named event types.
                for event_type in &[
                    "doc_created",
                    "doc_updated",
                    "file_attached",
                    "entity_created",
                    "retracted",
                    "token_consumed",
                ] {
                    let _ = es.add_event_listener_with_callback(
                        event_type,
                        on_message.as_ref().unchecked_ref(),
                    );
                }

                // Also listen to generic messages.
                es.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

                // Leak the closure so it lives as long as the page.
                on_message.forget();

                // Keep the EventSource alive by not dropping it.
                std::mem::forget(es);
            });
        });
    }

    ctx
}
