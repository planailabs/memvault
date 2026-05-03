//! Global search page.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SearchHit {
    doc_id: String,
    score: f32,
    snippet: String,
}

#[server]
async fn search_docs(query: String, limit: usize) -> Result<Vec<SearchHit>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let hits = client
        .search(&query, limit)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(hits
        .into_iter()
        .map(|h| SearchHit {
            doc_id: hex::encode(h.doc_id.0),
            score: h.score,
            snippet: h.snippet,
        })
        .collect())
}

#[component]
pub fn SearchPage() -> Element {
    use_topbar("Search");

    let mut query = use_signal(String::new);
    let mut results = use_signal(|| None::<Result<Vec<SearchHit>, String>>);
    let mut searching = use_signal(|| false);

    let do_search = move |_| {
        let q = query.read().clone();
        if q.trim().is_empty() {
            results.set(None);
            return;
        }
        searching.set(true);
        spawn(async move {
            match search_docs(q, 50).await {
                Ok(hits) => results.set(Some(Ok(hits))),
                Err(e) => results.set(Some(Err(e.to_string()))),
            }
            searching.set(false);
        });
    };

    rsx! {
        div { class: "space-y-4 max-w-3xl mx-auto",
            PageHeader { "Search" }
            form { class: "flex gap-2", onsubmit: do_search,
                input {
                    class: "input flex-1 text-lg",
                    r#type: "search",
                    placeholder: "Search notes...",
                    value: "{query}",
                    oninput: move |e: Event<FormData>| query.set(e.value()),
                    autofocus: true,
                }
                button { class: "btn btn-md btn-primary", r#type: "submit",
                    disabled: *searching.read(),
                    "Search"
                }
            }

            {match &*results.read() {
                Some(Ok(hits)) if hits.is_empty() => rsx! {
                    p { class: "text-fg-muted text-center py-8", "No results found." }
                },
                Some(Ok(hits)) => rsx! {
                    p { class: "text-sm text-fg-muted mb-2", "{hits.len()} results" }
                    for hit in hits {
                        Link { to: Route::NoteDetail { id: hit.doc_id.clone() },
                            Card { class: "hover:border-brand transition-colors",
                                div { class: "p-4",
                                    div { class: "flex items-center gap-2 mb-1",
                                        CidDisplay { cid: hit.doc_id.clone(), len: Some(12) }
                                        span { class: "text-xs text-fg-faint font-mono", "score {hit.score:.2}" }
                                    }
                                    p { class: "text-sm text-fg-muted", "{hit.snippet}" }
                                }
                            }
                        }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! {},
            }}
        }
    }
}
