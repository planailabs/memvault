//! Note detail page — view a single document.

use dioxus::prelude::*;
use plan_ai_design::{Button, ButtonVariant, Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::ui::app::Route;
use crate::ui::components::tag_pills::TagPills;
use crate::ui::components::visibility_pill::VisibilityPill;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NoteData {
    id: String,
    body: String,
    body_html: String,
    frontmatter: BTreeMap<String, serde_json::Value>,
    tags: Vec<(String, String)>,
    visibility: String,
    attachment_cids: Vec<AttachmentInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AttachmentInfo {
    cid: String,
    filename: String,
    mime_type: String,
    size: u64,
}

impl AttachmentInfo {
    fn size_display(&self) -> String {
        if self.size < 1024 {
            format!("{} B", self.size)
        } else if self.size < 1024 * 1024 {
            format!("{:.1} KB", self.size as f64 / 1024.0)
        } else {
            format!("{:.1} MB", self.size as f64 / (1024.0 * 1024.0))
        }
    }
}

#[server]
async fn get_note(id: String) -> Result<NoteData, ServerFnError> {
    let client = crate::ui::state::client()?;
    let doc_id =
        crate::api::docs::parse_doc_id(&id).map_err(|e| ServerFnError::new(format!("{e}")))?;
    let doc = client
        .get_doc(&doc_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Document not found"))?;

    // Render markdown to HTML server-side.
    let parser = pulldown_cmark::Parser::new(&doc.body);
    let mut body_html = String::new();
    pulldown_cmark::html::push_html(&mut body_html, parser);

    // Fetch attachments from audit log for this document.
    let mut attachments = Vec::new();
    if let Ok(records) = client
        .audit(memvault_query::AuditQuery {
            doc_id: Some(doc_id.clone()),
            op_kind: Some(memvault_query::OpKind::AttachFile),
            limit: Some(50),
            ..Default::default()
        })
        .await
    {
        for record in records {
            if let Ok(Some(manifest_bytes)) =
                client.get_attachment_manifest(&record.cid).await
            {
                if let Ok(manifest) =
                    serde_json::from_slice::<serde_json::Value>(&manifest_bytes)
                {
                    attachments.push(AttachmentInfo {
                        cid: hex::encode(&record.cid),
                        filename: manifest
                            .get("filename")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unnamed")
                            .to_string(),
                        mime_type: manifest
                            .get("mime_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("application/octet-stream")
                            .to_string(),
                        size: manifest
                            .get("content_size")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                    });
                }
            }
        }
    }

    Ok(NoteData {
        id: hex::encode(doc.id.0),
        body: doc.body,
        body_html,
        frontmatter: doc.frontmatter,
        tags: vec![],
        visibility: "internal".to_string(),
        attachment_cids: attachments,
    })
}

#[server]
async fn delete_note(id: String) -> Result<(), ServerFnError> {
    let client = crate::ui::state::client()?;
    let doc_id =
        crate::api::docs::parse_doc_id(&id).map_err(|e| ServerFnError::new(format!("{e}")))?;
    client
        .retract(&doc_id.0, "deleted via web UI")
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
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
    let navigator = use_navigator();
    let title = data
        .frontmatter
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled")
        .to_string();

    let id = data.id.clone();
    let on_delete = move |_| {
        let id = id.clone();
        spawn(async move {
            if let Ok(()) = delete_note(id).await {
                navigator.push(Route::NoteList {});
            }
        });
    };

    rsx! {
        div { class: "space-y-4",
            // Header
            div { class: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3",
                div { class: "flex items-center gap-3",
                    PageHeader { class: "mb-0", "{title}" }
                    VisibilityPill { visibility: data.visibility.clone() }
                }
                div { class: "flex gap-2",
                    Link { to: Route::NoteEdit { id: data.id.clone() },
                        Button { variant: ButtonVariant::Secondary, "Edit" }
                    }
                    Link { to: Route::NoteHistory { id: data.id.clone() },
                        Button { variant: ButtonVariant::Secondary, "History" }
                    }
                    Button { variant: ButtonVariant::Danger, onclick: on_delete, "Delete" }
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

            // Attachments
            if !data.attachment_cids.is_empty() {
                Card {
                    div { class: "p-5",
                        SectionHeading { "Attachments ({data.attachment_cids.len()})" }
                        div { class: "mt-2 divide-y divide-line",
                            for att in &data.attachment_cids {
                                div { class: "flex items-center gap-3 py-2",
                                    Pill { variant: PillVariant::Muted, "{att.mime_type}" }
                                    Link { to: Route::FileDetail { cid: att.cid.clone() }, class: "link flex-1 truncate",
                                        "{att.filename}"
                                    }
                                    span { class: "text-xs text-fg-muted font-mono", "{att.size_display()}" }
                                }
                            }
                        }
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
