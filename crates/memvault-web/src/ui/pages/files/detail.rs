//! File detail page — preview and manifest metadata.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};

use crate::ui::components::cid_display::CidDisplay;
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

    let manifest_bytes = client
        .get_attachment_manifest(&cid_bytes)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Manifest not found"))?;

    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|e| ServerFnError::new(e.to_string()))?;

    let extracted_text = client
        .read_extracted_text(&cid_bytes)
        .await
        .unwrap_or(None);

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
                    items.push(FileLinkedItem { direction, relation: edge.relation.clone(), other_node });
                }
            }
            items
        },
    })
}

#[component]
pub fn FileDetail(cid: String) -> Element {
    use_topbar("File");
    let file = use_server_future(move || {
        let cid = cid.clone();
        async move { get_file_detail(cid).await }
    })?;

    match &*file.read() {
        Some(Ok(data)) => rsx! { FileView { data: data.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", "Loading..." } },
    }
}

#[component]
fn FileView(data: FileData) -> Element {
    let download_url = format!("/api/v1/attachments/{}", data.cid);

    rsx! {
        div { class: "space-y-4",
            // Header
            div { class: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3",
                PageHeader { class: "mb-0", "{data.filename}" }
                a { href: "{download_url}", class: "btn btn-md btn-primary", download: "{data.filename}",
                    "Download"
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
                    SectionHeading { "Metadata" }
                    table { class: "table mt-2",
                        tbody { class: "tbody",
                            tr {
                                td { class: "td font-medium text-sm", "Filename" }
                                td { class: "td text-sm font-mono", "{data.filename}" }
                            }
                            tr {
                                td { class: "td font-medium text-sm", "MIME Type" }
                                td { class: "td text-sm font-mono", "{data.mime_type}" }
                            }
                            tr {
                                td { class: "td font-medium text-sm", "Size" }
                                td { class: "td text-sm font-mono", "{data.size_display()}" }
                            }
                            if let Some(hash) = &data.sha256 {
                                tr {
                                    td { class: "td font-medium text-sm", "SHA256" }
                                    td { class: "td text-sm", CidDisplay { cid: hash.clone(), len: Some(16) } }
                                }
                            }
                            if let Some((w, h)) = data.width_height {
                                tr {
                                    td { class: "td font-medium text-sm", "Dimensions" }
                                    td { class: "td text-sm font-mono", "{w} x {h}" }
                                }
                            }
                            if let Some(ms) = data.duration_ms {
                                tr {
                                    td { class: "td font-medium text-sm", "Duration" }
                                    td { class: "td text-sm font-mono", "{ms / 1000}s" }
                                }
                            }
                            tr {
                                td { class: "td font-medium text-sm", "CID" }
                                td { class: "td text-sm", CidDisplay { cid: data.cid.clone(), len: Some(24) } }
                            }
                            tr {
                                td { class: "td font-medium text-sm", "Replication" }
                                td { class: "td text-sm font-mono", "{data.replication}" }
                            }
                        }
                    }
                }
            }

            // Linked Items
            if !data.linked_items.is_empty() {
                Card {
                    div { class: "p-5",
                        SectionHeading { "Links ({data.linked_items.len()})" }
                        div { class: "mt-2 divide-y divide-line",
                            for item in &data.linked_items {
                                div { class: "flex items-center gap-3 py-2",
                                    Pill { variant: PillVariant::Muted, "{item.direction}" }
                                    Pill { variant: PillVariant::Muted, "{item.relation}" }
                                    span { class: "font-mono text-sm text-fg-muted truncate flex-1",
                                        "{item.other_node}"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Extracted text
            if let Some(text) = &data.extracted_text {
                Card {
                    div { class: "p-5",
                        SectionHeading { "Extracted Text" }
                        pre { class: "mt-2 text-sm text-fg-muted bg-surface-2 p-3 rounded overflow-x-auto max-h-[400px] overflow-y-auto",
                            "{text}"
                        }
                    }
                }
            }
        }
    }
}
