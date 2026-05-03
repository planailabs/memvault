//! Note detail page — view a single document.

use dioxus::prelude::*;
use plan_ai_design::{Button, ButtonVariant, Card, PageHeader, SectionHeading};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::ui::app::Route;
use crate::ui::components::tag_pills::TagPills;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NoteData {
    id: String,
    body: String,
    body_html: String,
    frontmatter: BTreeMap<String, serde_json::Value>,
    tags: Vec<(String, String)>,
}

#[server]
async fn get_note(id: String) -> Result<NoteData, ServerFnError> {
    let client = crate::ui::state::client()?;
    let doc_id = crate::api::docs::parse_doc_id(&id)
        .map_err(|e| ServerFnError::new(format!("{e}")))?;
    let doc = client
        .get_doc(&doc_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Document not found"))?;

    // Render markdown to HTML server-side.
    let parser = pulldown_cmark::Parser::new(&doc.body);
    let mut body_html = String::new();
    pulldown_cmark::html::push_html(&mut body_html, parser);

    Ok(NoteData {
        id: hex::encode(doc.id.0),
        body: doc.body,
        body_html,
        frontmatter: doc.frontmatter,
        tags: vec![],
    })
}

#[component]
pub fn NoteDetail(id: String) -> Element {
    use_topbar("Note");
    let note = use_server_future(move || {
        let id = id.clone();
        async move { get_note(id).await }
    })?;

    match &*note.read() {
        Some(Ok(data)) => rsx! { NoteView { data: data.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", "Loading..." } },
    }
}

#[component]
fn NoteView(data: NoteData) -> Element {
    let title = data
        .frontmatter
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled")
        .to_string();

    rsx! {
        div { class: "space-y-4",
            // Header
            div { class: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3",
                PageHeader { class: "mb-0", "{title}" }
                div { class: "flex gap-2",
                    Link { to: Route::NoteHistory { id: data.id.clone() },
                        Button { variant: ButtonVariant::Secondary, "History" }
                    }
                }
            }

            // Body
            Card {
                div { class: "p-5 prose prose-sm max-w-none dark:prose-invert",
                    dangerous_inner_html: "{data.body_html}",
                }
                if !data.tags.is_empty() {
                    div { class: "px-5 pb-4 border-t border-line pt-3",
                        TagPills { tags: data.tags.clone() }
                    }
                }
            }

            // Frontmatter
            if data.frontmatter.len() > 1 || (data.frontmatter.len() == 1 && !data.frontmatter.contains_key("title")) {
                Card {
                    div { class: "p-5",
                        SectionHeading { "Metadata" }
                        table { class: "table mt-2",
                            tbody { class: "tbody",
                                for (key, val) in &data.frontmatter {
                                    if key != "title" {
                                        tr {
                                            td { class: "td font-medium text-sm", "{key}" }
                                            td { class: "td text-sm font-mono text-fg-muted", "{val}" }
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
