//! File detail page — preview and manifest metadata.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Button, ButtonVariant, Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};

use crate::ui::components::cid_display::CidDisplay;
use crate::ui::components::sandboxed_content::SandboxedContent;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FileData {
    cid: String,
    filename: String,
    mime_type: String,
    content_size: u64,
    sha256: Option<String>,
    width_height: Option<(u32, u32)>,
    duration_ms: Option<u64>,
    replication: String,
    has_extracted_text: bool,
    extracted_text: Option<String>,
    linked_items: Vec<FileLinkedItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FileLinkedItem {
    direction: String,
    relation: String,
    other_node: String,
    other_label: Option<String>,
}

impl FileData {
    fn size_display(&self) -> String {
        if self.content_size < 1024 {
            format!("{} B", self.content_size)
        } else if self.content_size < 1024 * 1024 {
            format!("{:.1} KB", self.content_size as f64 / 1024.0)
        } else {
            format!("{:.1} MB", self.content_size as f64 / (1024.0 * 1024.0))
        }
    }

    fn is_image(&self) -> bool {
        self.mime_type.starts_with("image/")
    }

    fn is_text(&self) -> bool {
        self.mime_type.starts_with("text/") || self.mime_type == "application/json"
    }
}

#[server]
async fn get_file_detail(cid: String) -> Result<FileData, ServerFnError> {
    let client = crate::ui::state::client()?;
    let cid_bytes = hex::decode(&cid).map_err(|_| ServerFnError::new("Invalid CID hex"))?;

    // Read manifest block (always exists after repair-index).
    let manifest: serde_json::Value = client
        .get_file_manifest(&cid_bytes)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();

    let extracted_text = client.read_extracted_text(&cid_bytes).await.unwrap_or(None);

    Ok(FileData {
        cid,
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
        content_size: manifest
            .get("content_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        sha256: manifest
            .get("sha256")
            .and_then(|v| v.as_str())
            .map(String::from),
        width_height: manifest.get("width_height").and_then(|v| {
            let arr = v.as_array()?;
            Some((arr.first()?.as_u64()? as u32, arr.get(1)?.as_u64()? as u32))
        }),
        duration_ms: manifest.get("duration_ms").and_then(|v| v.as_u64()),
        replication: manifest
            .get("replication")
            .and_then(|v| v.as_str())
            .unwrap_or("Eager")
            .to_string(),
        has_extracted_text: manifest.get("extracted_text").is_some(),
        extracted_text,
        linked_items: {
            let att_node = memvault_core::NodeRef::Attachment(cid_bytes.clone());
            let mut items = Vec::new();
            if let Ok(edges) = client.edges_of(&att_node).await {
                for (source, edge) in edges {
                    let (direction, other_node) = if source == att_node {
                        ("outgoing".to_string(), edge.target.tag_label())
                    } else {
                        ("incoming".to_string(), source.tag_label())
                    };
                    let other_label = client.resolve_label(&other_node).await.unwrap_or(None);
                    items.push(FileLinkedItem {
                        direction,
                        relation: edge.relation.clone(),
                        other_node,
                        other_label,
                    });
                }
            }
            items
        },
    })
}

#[component]
pub fn FileDetail(cid: String) -> Element {
    use_topbar(&t!("file-title"));
    let file = use_server_future(move || {
        let cid = cid.clone();
        async move { get_file_detail(cid).await }
    })?;

    match &*file.read() {
        Some(Ok(data)) => rsx! { FileView { data: data.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
    }
}

#[component]
fn FileView(data: FileData) -> Element {
    let download_url = format!("/api/v1/files/{}", data.cid);

    rsx! {
        div { class: "space-y-4",
            // Header
            div { class: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3",
                PageHeader { class: "mb-0", "{data.filename}" }
                a { href: "{download_url}", class: "btn btn-md btn-primary", download: "{data.filename}",
                    {t!("file-download")}
                }
            }

            // Preview
            if data.is_image() {
                Card {
                    div { class: "p-5 flex justify-center",
                        img {
                            src: "{download_url}",
                            alt: "{data.filename}",
                            class: "max-h-[500px] rounded border border-line",
                        }
                    }
                }
            }

            // Manifest metadata
            Card {
                div { class: "p-5",
                    SectionHeading { {t!("file-section-metadata")} }
                    table { class: "table mt-2",
                        tbody { class: "tbody",
                            tr {
                                td { class: "td font-medium text-sm", {t!("file-meta-filename")} }
                                td { class: "td text-sm font-mono", "{data.filename}" }
                            }
                            tr {
                                td { class: "td font-medium text-sm", {t!("file-meta-mime")} }
                                td { class: "td text-sm font-mono", "{data.mime_type}" }
                            }
                            tr {
                                td { class: "td font-medium text-sm", {t!("file-meta-size")} }
                                td { class: "td text-sm font-mono", "{data.size_display()}" }
                            }
                            if let Some(hash) = &data.sha256 {
                                tr {
                                    td { class: "td font-medium text-sm", {t!("file-meta-sha256")} }
                                    td { class: "td text-sm", CidDisplay { cid: hash.clone(), len: Some(16) } }
                                }
                            }
                            if let Some((w, h)) = data.width_height {
                                tr {
                                    td { class: "td font-medium text-sm", {t!("file-meta-dimensions")} }
                                    td { class: "td text-sm font-mono", "{w} x {h}" }
                                }
                            }
                            if let Some(ms) = data.duration_ms {
                                tr {
                                    td { class: "td font-medium text-sm", {t!("file-meta-duration")} }
                                    td { class: "td text-sm font-mono", "{ms / 1000}s" }
                                }
                            }
                            tr {
                                td { class: "td font-medium text-sm", {t!("file-meta-cid")} }
                                td { class: "td text-sm", CidDisplay { cid: data.cid.clone(), len: Some(24) } }
                            }
                            tr {
                                td { class: "td font-medium text-sm", {t!("file-meta-replication")} }
                                td { class: "td text-sm font-mono", "{data.replication}" }
                            }
                        }
                    }
                }
            }

            // Linked Items + Add Link
            Card {
                div { class: "p-5",
                    SectionHeading { {t!("file-section-links", count: data.linked_items.len())} }
                    if !data.linked_items.is_empty() {
                        div { class: "mt-2 divide-y divide-line",
                            for item in &data.linked_items {
                                div { class: "flex items-center gap-3 py-2",
                                    Pill { variant: PillVariant::Muted, "{item.direction}" }
                                    Pill { variant: PillVariant::Muted, "{item.relation}" }
                                    if let Some(label) = &item.other_label {
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
                    FileQuickLinkForm { source_id: format!("file:{}", data.cid) }
                }
            }

            // Extracted text (rendered in sandboxed iframe for isolation)
            if let Some(text) = &data.extracted_text {
                Card {
                    div { class: "p-5",
                        SectionHeading { {t!("file-section-text")} }
                        SandboxedContent {
                            html: format!("<pre style=\"white-space:pre-wrap;word-break:break-word;margin:0;font-size:0.8125rem;color:rgba(0,0,0,0.6)\">{}</pre>", html_escape_text(text)),
                            class: "mt-2 max-h-[400px] overflow-y-auto".to_string(),
                        }
                    }
                }
            }
        }
    }
}

fn html_escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[server]
async fn search_file_link_targets(
    query: String,
) -> Result<Vec<(String, String, String)>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let hits = client
        .search_unified(&query, 8)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(hits
        .into_iter()
        .map(|h| (h.node_id, h.node_type, h.label))
        .collect())
}

#[server]
async fn create_file_link(
    source: String,
    target: String,
    relation: String,
) -> Result<String, ServerFnError> {
    let client = crate::ui::state::client()?;
    let source_ref = memvault_core::NodeRef::from_tag_label(&source)
        .ok_or_else(|| ServerFnError::new("Invalid source node"))?;
    let target_ref = memvault_core::NodeRef::from_tag_label(&target).ok_or_else(|| {
        ServerFnError::new("Invalid target — use format: entity:<hex>, doc:<hex>, or file:<hex>")
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

#[component]
fn FileQuickLinkForm(source_id: String) -> Element {
    let mut search_input = use_signal(String::new);
    let mut selected_target = use_signal(|| None::<(String, String)>);
    let mut suggestions = use_signal(Vec::<(String, String, String)>::new);
    let mut relation_input = use_signal(|| "related_to".to_string());
    let mut status_msg = use_signal(|| None::<String>);

    let on_search_input = move |e: Event<FormData>| {
        let q = e.value();
        search_input.set(q.clone());
        selected_target.set(None);
        if q.len() >= 2 {
            spawn(async move {
                if let Ok(results) = search_file_link_targets(q).await {
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
                let raw = search_input.read().clone();
                if raw.contains(':') {
                    (raw.clone(), raw)
                } else {
                    status_msg.set(Some(t!("link-select-target")));
                    return;
                }
            }
        };
        let relation = relation_input.read().clone();
        spawn(async move {
            match create_file_link(source, target, relation).await {
                Ok(edge_id) => {
                    status_msg.set(Some(t!("link-linked", edgeId: &edge_id[..8])));
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
            h4 { class: "text-xs font-semibold text-fg-muted uppercase mb-2", {t!("link-add")} }
            div { class: "flex gap-2 items-end",
                div { class: "flex-1 relative",
                    label { class: "text-xs text-fg-muted", {t!("link-label-target")} }
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
                                placeholder: t!("link-placeholder-search"),
                                value: "{display_val}",
                                oninput: on_search_input,
                            }
                        }
                    }
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
                    label { class: "text-xs text-fg-muted", {t!("link-label-relation")} }
                    input {
                        class: "input input-sm w-24 mt-1",
                        r#type: "text",
                        value: "{relation_input}",
                        oninput: move |e: Event<FormData>| relation_input.set(e.value()),
                    }
                }
                Button { variant: ButtonVariant::Secondary, onclick: on_submit, {t!("link-btn")} }
            }
            if let Some(msg) = &*status_msg.read() {
                p { class: "text-xs mt-1 text-fg-muted", "{msg}" }
            }
        }
    }
}
