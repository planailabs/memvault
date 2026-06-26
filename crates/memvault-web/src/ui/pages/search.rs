//! Global search page with highlighted results.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader, Pill, PillVariant};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::components::tag_pills::TagPills;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SearchHit {
    /// "doc" | "entity" | "file" — drives the result link target and badge.
    node_type: String,
    /// Hex id without the node-type prefix: DocId, EntityId, or file CID.
    id: String,
    /// Display title (doc frontmatter title / entity name / filename).
    title: Option<String>,
    score: f32,
    snippet: String,
    /// Pre-rendered snippet with `<mark>` tags around matching terms.
    snippet_html: String,
    tags: Vec<(String, String)>,
}

#[server]
async fn search_docs(
    query: String,
    limit: usize,
    show_retracted: bool,
) -> Result<Vec<SearchHit>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let q_lower = query.to_lowercase();
    let hits = client
        .search_scoped(
            &memvault_core::QueryScope::all().with_include_retracted(show_retracted),
            &query,
            limit,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut results = Vec::new();
    for h in hits {
        // Strip the node-type prefix to the bare hex id (DocId / EntityId /
        // file CID). Unknown node types are skipped.
        let (node_type, id) = match h.node_type.as_str() {
            "doc" => ("doc", h.node_id.strip_prefix("doc:").unwrap_or(&h.node_id)),
            "entity" => ("entity", h.node_id.strip_prefix("entity:").unwrap_or(&h.node_id)),
            "file" => ("file", h.node_id.strip_prefix("file:").unwrap_or(&h.node_id)),
            _ => continue,
        };
        let id = id.to_string();

        // Title: docs carry it in frontmatter; entities and files surface the
        // index label (entity name / filename). Fall back to the label, then
        // to nothing (the snippet still shows).
        let label = (!h.label.is_empty()).then(|| h.label.clone());
        let title = if node_type == "doc" {
            match hex::decode(&id) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    let scope = memvault_core::QueryScope::all()
                        .with_include_retracted(show_retracted);
                    client
                        .get_doc_scoped(&memvault_core::DocId(arr), &scope)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|doc| {
                            doc.frontmatter
                                .get("title")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                        })
                        .or(label)
                }
                _ => label,
            }
        } else {
            label
        };

        // Highlight matching terms in snippet.
        let snippet_html = highlight_snippet(&h.snippet, &q_lower);

        results.push(SearchHit {
            node_type: node_type.to_string(),
            id,
            title,
            score: h.score,
            snippet: h.snippet,
            snippet_html,
            tags: vec![],
        });
    }

    Ok(results)
}

/// Insert `<mark>` tags around query terms in the snippet.
#[cfg(feature = "server")]
fn highlight_snippet(snippet: &str, query: &str) -> String {
    let words: Vec<&str> = query.split_whitespace().filter(|w| w.len() > 1).collect();
    if words.is_empty() {
        return html_escape(snippet);
    }

    let lower = snippet.to_lowercase();
    let mut result = String::new();
    let mut i = 0;
    let chars: Vec<char> = snippet.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();

    while i < chars.len() {
        let mut matched = false;
        for word in &words {
            let wchars: Vec<char> = word.chars().collect();
            if i + wchars.len() <= lower_chars.len()
                && lower_chars[i..i + wchars.len()] == wchars[..]
            {
                result.push_str("<mark>");
                for c in &chars[i..i + wchars.len()] {
                    push_escaped(&mut result, *c);
                }
                result.push_str("</mark>");
                i += wchars.len();
                matched = true;
                break;
            }
        }
        if !matched {
            push_escaped(&mut result, chars[i]);
            i += 1;
        }
    }
    result
}

#[cfg(feature = "server")]
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_escaped(&mut out, c);
    }
    out
}

#[cfg(feature = "server")]
fn push_escaped(out: &mut String, c: char) {
    match c {
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '&' => out.push_str("&amp;"),
        '"' => out.push_str("&quot;"),
        _ => out.push(c),
    }
}

#[component]
pub fn SearchPage() -> Element {
    use_topbar("Search");

    let mut query = use_signal(String::new);
    let mut results = use_signal(|| None::<Result<Vec<SearchHit>, String>>);
    let mut searching = use_signal(|| false);
    let show_retracted = use_context::<crate::ui::topbar::ShowRetractedSignal>();

    let do_search = move |e: Event<FormData>| {
        e.prevent_default();
        let q = query.read().clone();
        if q.trim().is_empty() {
            results.set(None);
            return;
        }
        let r = show_retracted().0;
        searching.set(true);
        spawn(async move {
            match search_docs(q, 50, r).await {
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
                    placeholder: "Search notes, graph, files...",
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
                        Link {
                            to: match hit.node_type.as_str() {
                                "entity" => Route::EntityDetail { id: hit.id.clone() },
                                "file" => Route::FileDetail { cid: hit.id.clone() },
                                _ => Route::NoteDetail { id: hit.id.clone() },
                            },
                            Card { class: "hover:border-brand transition-colors",
                                div { class: "p-4",
                                    div { class: "flex items-center gap-2 mb-1",
                                        Pill { variant: PillVariant::Info, "{hit.node_type}" }
                                        if let Some(title) = &hit.title {
                                            span { class: "font-medium", "{title}" }
                                        }
                                        Pill { variant: PillVariant::Muted, "score {hit.score:.2}" }
                                    }
                                    p {
                                        class: "text-sm text-fg-muted [&>mark]:bg-warn-soft [&>mark]:text-fg [&>mark]:px-0.5 [&>mark]:rounded",
                                        dangerous_inner_html: "{hit.snippet_html}",
                                    }
                                    if !hit.tags.is_empty() {
                                        div { class: "mt-2",
                                            TagPills { tags: hit.tags.clone() }
                                        }
                                    }
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
