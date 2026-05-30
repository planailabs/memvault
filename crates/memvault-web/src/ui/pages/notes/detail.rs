//! Note detail page — view a single document.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Button, ButtonVariant, Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::ui::app::Route;
use crate::ui::components::sandboxed_content::SandboxedContent;
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
    linked_items: Vec<LinkedItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LinkedItem {
    edge_id: String,
    direction: String, // "outgoing" or "incoming"
    relation: String,
    other_node: String, // tag_label format: "entity:hex", "doc:hex", etc.
    other_label: Option<String>,
    /// `"body_markdown"`, `"frontmatter"`, or `"asserted"` (None for legacy
    /// edges without a provenance prop).
    provenance: Option<String>,
    /// Unresolved alias text, if the edge's target is a pending placeholder.
    pending_alias: Option<String>,
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
async fn get_note(id: String, show_retracted: bool) -> Result<NoteData, ServerFnError> {
    let client = crate::ui::state::client()?;
    let doc_id =
        crate::api::docs::parse_doc_id(&id).map_err(|e| ServerFnError::new(format!("{e}")))?;
    let doc = client
        .get_doc_scoped(&doc_id, &memvault_core::QueryScope::all().with_include_retracted(show_retracted))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Document not found"))?;

    // Render markdown to HTML server-side. Wikilinks (`[[doc:hex]]`,
    // `[[Alice]]`, `[[entity:hex|alias]]`) and `memvault://…` URIs are
    // rewritten to the matching in-app routes by `notes::render`.
    let body_html = crate::ui::pages::notes::render::render_doc_body(&doc.body);

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
            // record.cid is the AttachFile envelope CID — the manifest
            // sits at record.attachment_cid. Skip records without one.
            let Some(manifest_cid) = record.attachment_cid.clone() else {
                continue;
            };
            if let Ok(Some(manifest_bytes)) = client.get_file_manifest(&manifest_cid).await {
                // DAG-CBOR via the canonical helper — plain
                // serde_json::from_slice would silently drop every
                // field and produce blank "unnamed" rows.
                if let Some(manifest) =
                    memvault_store::deserialize_block(&manifest_bytes)
                {
                    attachments.push(AttachmentInfo {
                        cid: hex::encode(&manifest_cid),
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

    // Fetch linked items via edges_of.
    let doc_node = memvault_core::NodeRef::Doc(doc_id.clone());
    let mut linked_items = Vec::new();
    if let Ok(edges) = client.edges_of(&doc_node).await {
        for (source, edge) in edges {
            let (direction, other_node) = if source == doc_node {
                ("outgoing".to_string(), edge.target.tag_label())
            } else {
                ("incoming".to_string(), source.tag_label())
            };
            let other_label = client.resolve_label(&other_node).await.unwrap_or(None);
            let provenance = edge
                .props
                .get("provenance")
                .and_then(|v| v.as_str())
                .map(String::from);
            let pending_alias = edge
                .props
                .get("pending_alias")
                .and_then(|v| v.as_str())
                .map(String::from);
            linked_items.push(LinkedItem {
                edge_id: hex::encode(edge.id.0),
                direction,
                relation: edge.relation.clone(),
                other_node,
                other_label,
                provenance,
                pending_alias,
            });
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
        linked_items,
    })
}

#[server]
async fn create_link(
    source: String,
    target: String,
    relation: String,
) -> Result<String, ServerFnError> {
    let client = crate::ui::state::client()?;
    let source_ref = memvault_core::NodeRef::from_tag_label(&source)
        .ok_or_else(|| ServerFnError::new("Invalid source node"))?;
    let target_ref = memvault_core::NodeRef::from_tag_label(&target).ok_or_else(|| {
        ServerFnError::new(
            "Invalid target — use format: entity:<hex>, doc:<hex>, or attachment:<hex>",
        )
    })?;

    let edge = memvault_doc::Edge {
        id: memvault_core::EdgeId::random(),
        relation,
        target: target_ref,
        weight: None,
        props: std::collections::BTreeMap::new(),
        provenance: None,
    };
    let edge_id = client
        .add_link(&source_ref, edge, memvault_core::Visibility::Internal)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(hex::encode(edge_id.0))
}

#[server]
async fn search_link_targets(
    query: String,
) -> Result<Vec<(String, String, String)>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let hits = client
        .search_unified(&query, 8)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    // Returns (node_id, node_type, label)
    Ok(hits
        .into_iter()
        .map(|h| (h.node_id, h.node_type, h.label))
        .collect())
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

fn provenance_pill_variant(prov: &str) -> PillVariant {
    match prov {
        "body_markdown" | "frontmatter" => PillVariant::Muted,
        "asserted" => PillVariant::Muted,
        _ => PillVariant::Muted,
    }
}

#[component]
pub fn NoteDetail(id: String) -> Element {
    use_topbar(&t!("notes-detail-title"));
    let show_retracted = use_context::<crate::ui::topbar::ShowRetractedSignal>();
    let note = use_server_future(move || {
        let id = id.clone();
        let r = show_retracted().0;
        async move { get_note(id, r).await }
    })?;

    match &*note.read() {
        Some(Ok(data)) => rsx! { NoteView { data: data.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
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
                        Button { variant: ButtonVariant::Secondary, {t!("edit")} }
                    }
                    Link { to: Route::NoteHistory { id: data.id.clone() },
                        Button { variant: ButtonVariant::Secondary, {t!("history")} }
                    }
                    Button { variant: ButtonVariant::Danger, onclick: on_delete, {t!("delete")} }
                }
            }

            // Body (rendered in sandboxed iframe — card is inside the iframe for correct bg)
            SandboxedContent { html: data.body_html.clone() }
            if !data.tags.is_empty() {
                Card {
                    div { class: "px-5 py-3",
                        TagPills { tags: data.tags.clone() }
                    }
                }
            }

            // Attachments
            if !data.attachment_cids.is_empty() {
                Card {
                    div { class: "p-5",
                        SectionHeading { {t!("notes-attachments", count: data.attachment_cids.len())} }
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

            // Linked Items + Add Link
            Card {
                div { class: "p-5",
                    SectionHeading { {t!("notes-links", count: data.linked_items.len())} }
                    if !data.linked_items.is_empty() {
                        div { class: "mt-2 divide-y divide-line",
                            for item in &data.linked_items {
                                div { class: "flex items-center gap-3 py-2",
                                    Pill { variant: PillVariant::Muted, "{item.direction}" }
                                    Pill { variant: PillVariant::Muted, "{item.relation}" }
                                    if let Some(prov) = &item.provenance {
                                        Pill { variant: provenance_pill_variant(prov), "{prov}" }
                                    }
                                    if let Some(alias) = &item.pending_alias {
                                        span { class: "text-sm truncate flex-1 text-warning",
                                            "[[{alias}]] (pending)"
                                        }
                                    } else if let Some(label) = &item.other_label {
                                        span { class: "text-sm truncate flex-1", "{label}" }
                                    } else {
                                        span { class: "font-mono text-sm text-fg-muted truncate flex-1",
                                            "{item.other_node}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Quick-link form
                    QuickLinkForm { source_id: format!("doc:{}", data.id) }
                }
            }

            // Frontmatter
            if data.frontmatter.len() > 1 || (data.frontmatter.len() == 1 && !data.frontmatter.contains_key("title")) {
                Card {
                    div { class: "p-5",
                        SectionHeading { {t!("notes-metadata")} }
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

/// Inline form to create a link from this node to another, with search-as-you-type.
#[component]
fn QuickLinkForm(source_id: String) -> Element {
    let mut search_input = use_signal(String::new);
    let mut selected_target = use_signal(|| None::<(String, String)>); // (node_id, label)
    let mut suggestions = use_signal(Vec::<(String, String, String)>::new); // (node_id, type, label)
    let mut relation_input = use_signal(|| "related_to".to_string());
    let mut status_msg = use_signal(|| None::<String>);

    let on_search_input = move |e: Event<FormData>| {
        let q = e.value();
        search_input.set(q.clone());
        selected_target.set(None);
        if q.len() >= 2 {
            spawn(async move {
                if let Ok(results) = search_link_targets(q).await {
                    suggestions.set(results);
                }
            });
        } else {
            suggestions.set(Vec::new());
        }
    };

    let source = source_id.clone();
    let on_submit = move |_| {
        let source = source.clone();
        let (target, _label) = match &*selected_target.read() {
            Some(t) => t.clone(),
            None => {
                // Allow raw node_id input as fallback
                let raw = search_input.read().clone();
                if raw.contains(':') {
                    (raw.clone(), raw)
                } else {
                    status_msg.set(Some("Select a target from search results".to_string()));
                    return;
                }
            }
        };
        let relation = relation_input.read().clone();
        spawn(async move {
            match create_link(source, target, relation).await {
                Ok(edge_id) => {
                    status_msg.set(Some(format!("Linked (edge {})", &edge_id[..8])));
                    search_input.set(String::new());
                    selected_target.set(None);
                    suggestions.set(Vec::new());
                }
                Err(e) => status_msg.set(Some(format!("Error: {e}"))),
            }
        });
    };

    let suggestion_list = suggestions.read().clone();

    rsx! {
        div { class: "mt-3 pt-3 border-t border-line",
            h4 { class: "text-xs font-semibold text-fg-muted uppercase mb-2", {t!("notes-add-link")} }
            div { class: "flex gap-2 items-end",
                div { class: "flex-1 relative",
                    label { class: "text-xs text-fg-muted", {t!("notes-link-target")} }
                    {
                        let display_val = if let Some((_, ref lbl)) = *selected_target.read() {
                            lbl.clone()
                        } else {
                            search_input.read().clone()
                        };
                        rsx! {
                            input {
                                class: "input input-sm w-full mt-1",
                                r#type: "text",
                                placeholder: t!("notes-link-search-placeholder"),
                                value: "{display_val}",
                                oninput: on_search_input,
                            }
                        }
                    }
                    // Suggestion dropdown
                    if !suggestion_list.is_empty() && selected_target.read().is_none() {
                        div { class: "absolute z-10 w-full mt-1 bg-surface border border-line rounded shadow-lg max-h-48 overflow-y-auto",
                            for (node_id, node_type, label) in &suggestion_list {
                                {
                                    let nid = node_id.clone();
                                    let lbl = label.clone();
                                    rsx! {
                                        div {
                                            class: "px-3 py-2 hover:bg-surface-2 cursor-pointer flex items-center gap-2 text-sm",
                                            onclick: move |_| {
                                                selected_target.set(Some((nid.clone(), lbl.clone())));
                                                suggestions.set(Vec::new());
                                            },
                                            Pill { variant: PillVariant::Muted, "{node_type}" }
                                            span { class: "truncate", "{label}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div {
                    label { class: "text-xs text-fg-muted", {t!("notes-link-relation")} }
                    input {
                        class: "input input-sm w-24 mt-1",
                        r#type: "text",
                        value: "{relation_input}",
                        oninput: move |e: Event<FormData>| relation_input.set(e.value()),
                    }
                }
                Button { variant: ButtonVariant::Secondary, onclick: on_submit, {t!("notes-link-btn")} }
            }
            if let Some(msg) = &*status_msg.read() {
                p { class: "text-xs mt-1 text-fg-muted", "{msg}" }
            }
        }
    }
}
