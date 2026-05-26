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
    /// Up to 3 context snippets showing where matches were found.
    contexts: Vec<String>,
}

#[server]
async fn palette_search(query: String) -> Result<Vec<PaletteResult>, ServerFnError> {
    let client = crate::ui::state::client()?;

    // Unified search across docs, entities, and attachments.
    let hits = client
        .search_unified(&query, 15)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let results: Vec<PaletteResult> = hits
        .into_iter()
        .map(|hit| {
            let (kind, id) = match hit.node_type.as_str() {
                "doc" => (
                    "note",
                    hit.node_id
                        .strip_prefix("doc:")
                        .unwrap_or(&hit.node_id)
                        .to_string(),
                ),
                "file" | "attachment" => (
                    "file",
                    hit.node_id
                        .strip_prefix("file:")
                        .or_else(|| hit.node_id.strip_prefix("attachment:"))
                        .unwrap_or(&hit.node_id)
                        .to_string(),
                ),
                _ => (
                    "entity",
                    hit.node_id
                        .strip_prefix("entity:")
                        .unwrap_or(&hit.node_id)
                        .to_string(),
                ),
            };
            PaletteResult {
                kind: kind.to_string(),
                id,
                label: hit.label,
                detail: if hit.node_type == "entity" {
                    hit.snippet.chars().take(40).collect()
                } else {
                    format!("{:.0}", hit.score)
                },
                contexts: hit.match_contexts,
            }
        })
        .collect();

    Ok(results)
}

/// Shared signal to open/close the command palette from anywhere.
pub type PaletteOpen = Signal<bool>;

/// The command palette modal. Rendered at the Layout level.
#[component]
pub fn CommandPalette() -> Element {
    let mut open = use_context::<PaletteOpen>();
    let mut query = use_signal(String::new);
    let mut results = use_signal(Vec::<PaletteResult>::new);
    let mut searching = use_signal(|| false);
    let _navigator = use_navigator();

    // Keyboard shortcut: Cmd/Ctrl + K.
    use_effect(move || {
        #[cfg(target_arch = "wasm32")]
        {
            spawn(async move {
                use wasm_bindgen::JsCast;
                use wasm_bindgen::closure::Closure;

                let window = web_sys::window().unwrap();
                let mut open = open;
                let mut query = query;
                let mut results = results;
                let cb = Closure::wrap(Box::new(move |e: web_sys::KeyboardEvent| {
                    if (e.meta_key() || e.ctrl_key()) && e.key() == "k" {
                        e.prevent_default();
                        let was_open = *open.peek();
                        open.set(!was_open);
                        if !was_open {
                            query.set(String::new());
                            results.set(Vec::new());
                        }
                    }
                    if e.key() == "Escape" && *open.peek() {
                        open.set(false);
                    }
                })
                    as Box<dyn FnMut(web_sys::KeyboardEvent)>);
                let _ =
                    window.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
                cb.forget();
            });
        }
    });

    // Debounce generation counter — incremented on each keystroke.
    let mut debounce_gen = use_signal(|| 0u64);

    if !*open.read() {
        return rsx! {};
    }

    // Fire search immediately (Enter key).
    let do_search = move |e: Event<FormData>| {
        e.prevent_default();
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

    // On each keystroke: update query and schedule a debounced search after 500ms.
    let on_input = move |e: Event<FormData>| {
        let q = e.value();
        query.set(q.clone());
        let generation = *debounce_gen.read() + 1;
        debounce_gen.set(generation);

        if q.trim().is_empty() {
            results.set(Vec::new());
            return;
        }

        spawn(async move {
            // Wait 500ms, then check if this is still the latest keystroke.
            #[cfg(target_arch = "wasm32")]
            {
                gloo_timers::future::TimeoutFuture::new(500).await;
            }
            #[cfg(all(not(target_arch = "wasm32"), feature = "server"))]
            {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            if *debounce_gen.read() != generation {
                return; // a newer keystroke superseded us
            }
            searching.set(true);
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
                        oninput: on_input,
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
                                        div { class: "px-4 py-2 hover:bg-surface-2 cursor-pointer",
                                            div { class: "flex items-center gap-2",
                                                Pill { variant, "{result.kind}" }
                                                span { class: "text-sm flex-1 truncate font-medium", "{result.label}" }
                                            }
                                            if !result.contexts.is_empty() {
                                                div { class: "mt-1 space-y-0.5 pl-1",
                                                    for ctx in &result.contexts {
                                                        p { class: "text-xs text-fg-muted truncate leading-snug",
                                                            "{ctx}"
                                                        }
                                                    }
                                                }
                                            }
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
