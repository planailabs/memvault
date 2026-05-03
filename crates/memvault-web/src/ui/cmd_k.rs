//! Cmd+K command palette — global search across docs, entities, and files.

use dioxus::prelude::*;
use plan_ai_design::{Pill, PillVariant};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PaletteResult {
    kind: String, // "note", "entity", "file"
    id: String,
    label: String,
    detail: String,
}

#[server]
async fn palette_search(query: String) -> Result<Vec<PaletteResult>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let mut results = Vec::new();

    // Search documents.
    if let Ok(hits) = client.search(&query, 5).await {
        for hit in hits {
            results.push(PaletteResult {
                kind: "note".to_string(),
                id: hex::encode(hit.doc_id.0),
                label: hit.snippet.chars().take(60).collect(),
                detail: format!("score {:.2}", hit.score),
            });
        }
    }

    Ok(results)
}

/// The command palette modal. Rendered at the Layout level.
#[component]
pub fn CommandPalette() -> Element {
    let mut open = use_signal(|| false);
    let mut query = use_signal(String::new);
    let mut results = use_signal(Vec::<PaletteResult>::new);
    let mut searching = use_signal(|| false);
    let _navigator = use_navigator();

    // Keyboard shortcut: Cmd/Ctrl + K.
    use_effect(move || {
        #[cfg(feature = "web")]
        {
            spawn(async move {
                use wasm_bindgen::closure::Closure;
                use wasm_bindgen::JsCast;

                let window = web_sys::window().unwrap();
                let cb = Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(
                    move |e: web_sys::KeyboardEvent| {
                        if (e.meta_key() || e.ctrl_key()) && e.key() == "k" {
                            e.prevent_default();
                            open.set(!*open.peek());
                            if *open.peek() {
                                query.set(String::new());
                                results.set(Vec::new());
                            }
                        }
                        if e.key() == "Escape" && *open.peek() {
                            open.set(false);
                        }
                    },
                );
                let _ = window.add_event_listener_with_callback(
                    "keydown",
                    cb.as_ref().unchecked_ref(),
                );
                cb.forget();
            });
        }
    });

    if !*open.read() {
        return rsx! {};
    }

    let do_search = move |_: Event<FormData>| {
        let q = query.read().clone();
        if q.trim().is_empty() {
            results.set(Vec::new());
            return;
        }
        searching.set(true);
        spawn(async move {
            if let Ok(r) = palette_search(q).await {
                results.set(r);
            }
            searching.set(false);
        });
    };

    let result_list = results.read().clone();

    rsx! {
        // Backdrop
        div {
            class: "fixed inset-0 bg-black/50 z-50 flex items-start justify-center pt-[15vh]",
            onclick: move |_| open.set(false),

            // Modal
            div {
                class: "bg-surface rounded-lg shadow-xl w-full max-w-lg border border-line",
                onclick: move |e: Event<MouseData>| e.stop_propagation(),

                // Search input
                form { class: "p-3 border-b border-line", onsubmit: do_search,
                    input {
                        class: "input w-full text-lg",
                        r#type: "search",
                        placeholder: "Search notes, entities, files...",
                        value: "{query}",
                        oninput: move |e: Event<FormData>| query.set(e.value()),
                        autofocus: true,
                    }
                }

                // Results
                div { class: "max-h-80 overflow-y-auto",
                    if *searching.read() {
                        div { class: "p-4 text-center text-fg-muted text-sm", "Searching..." }
                    } else if result_list.is_empty() && !query.read().is_empty() {
                        div { class: "p-4 text-center text-fg-muted text-sm", "No results" }
                    } else {
                        for result in &result_list {
                            {
                                let route = match result.kind.as_str() {
                                    "note" => Route::NoteDetail { id: result.id.clone() },
                                    "entity" => Route::EntityDetail { id: result.id.clone() },
                                    "file" => Route::FileDetail { cid: result.id.clone() },
                                    _ => Route::NoteList {},
                                };
                                let variant = match result.kind.as_str() {
                                    "note" => PillVariant::Info,
                                    "entity" => PillVariant::Accent,
                                    "file" => PillVariant::Muted,
                                    _ => PillVariant::Muted,
                                };
                                rsx! {
                                    Link {
                                        to: route,
                                        onclick: move |_| open.set(false),
                                        div { class: "flex items-center gap-2 px-4 py-2 hover:bg-surface-2 cursor-pointer",
                                            Pill { variant, "{result.kind}" }
                                            span { class: "text-sm flex-1 truncate", "{result.label}" }
                                            span { class: "text-xs text-fg-faint", "{result.detail}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Hint
                div { class: "px-4 py-2 border-t border-line text-xs text-fg-faint",
                    "Press Enter to search, Esc to close"
                }
            }
        }
    }
}
