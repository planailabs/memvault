//! File detail page — preview and manifest metadata.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Button, ButtonVariant, Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
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
    /// Hex-encoded envelope author (node pubkey post-Signed<T>, or
    /// agent pubkey for legacy unsigned writes). Empty when the
    /// attachment envelope can't be located.
    uploaded_by_author: String,
    /// Human-readable agent_id when the attachment envelope carries an
    /// `agent_attestation` cid resolvable via the trust state.
    uploaded_by_agent: Option<String>,
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

    fn is_audio(&self) -> bool {
        self.mime_type.starts_with("audio/")
    }
}

// ── Media extraction view models ────────────────────────────────────────
//
// Local DTOs mirroring `memvault_api::types::{ExtractionInfo,
// PageRenderInfo}` — the memvault-api types don't compile to wasm, so
// pages keep their own serde structs (same pattern as `FileData`).

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TranscriptSegmentView {
    start_ms: u64,
    end_ms: u64,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ExtractionView {
    /// Wire status string: pending | done | failed | unavailable | unsupported.
    status: String,
    text: Option<String>,
    segments: Option<Vec<TranscriptSegmentView>>,
    error: Option<String>,
    extractor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PageRenderSummary {
    status: String,
    page_count: u32,
    error: Option<String>,
}

/// `MediaJobStatus` → its wire string ("pending", "done", …) via the serde
/// snake_case rename, so the UI's string matching can't drift from the enum.
#[cfg(feature = "server")]
fn media_status_str(status: memvault_api::types::MediaJobStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "unavailable".into())
}

/// Format a millisecond offset as `mm:ss` for transcript timestamps.
fn fmt_mmss(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02}", s / 60, s % 60)
}

#[server]
async fn get_extraction(cid: String) -> Result<ExtractionView, ServerFnError> {
    let client = crate::ui::state::client()?;
    let cid_bytes = hex::decode(&cid).map_err(|_| ServerFnError::new("Invalid CID hex"))?;
    let info = client
        .read_extraction(&cid_bytes)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(ExtractionView {
        status: media_status_str(info.status),
        text: info.text,
        segments: info.segments.map(|segs| {
            segs.into_iter()
                .map(|s| TranscriptSegmentView {
                    start_ms: s.start_ms,
                    end_ms: s.end_ms,
                    text: s.text,
                })
                .collect()
        }),
        error: info.error,
        extractor: info.extractor,
    })
}

#[server]
async fn get_page_render_summary(cid: String) -> Result<PageRenderSummary, ServerFnError> {
    let client = crate::ui::state::client()?;
    let cid_bytes = hex::decode(&cid).map_err(|_| ServerFnError::new("Invalid CID hex"))?;
    let info = client
        .read_page_render(&cid_bytes)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(PageRenderSummary {
        status: media_status_str(info.status),
        page_count: info.page_count,
        error: info.error,
    })
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
        // Manifests are stored as DAG-CBOR; the canonical helper falls
        // through to JSON for legacy blocks.
        .and_then(|bytes| memvault_store::deserialize_block(&bytes))
        .unwrap_or_default();

    let extracted_text = client.read_extracted_text(&cid_bytes).await.unwrap_or(None);

    // Locate the attachment envelope via the `_manifest` tag so we can
    // surface who uploaded the file. Falls back to empty author/agent
    // when the envelope can't be found (legacy data or sync gaps).
    let (uploaded_by_author, uploaded_by_agent) = {
        let local = crate::ui::state::local_client().ok();
        let mcid_hex = hex::encode(&cid_bytes);
        let mut author_hex = String::new();
        let mut agent_id: Option<String> = None;
        if let Some(local) = local.as_ref() {
            if let Ok(env_cids) = local
                .store()
                .query_by_tag("_manifest", &mcid_hex, 0, 1)
            {
                if let Some(env_cid) = env_cids.into_iter().next() {
                    if let Ok(Some(bytes)) = local.store().get_block(&env_cid) {
                        if let Some(view) = memvault_store::EnvelopeView::parse(&bytes) {
                            let author = view.author();
                            if !author.is_empty() {
                                author_hex = hex::encode(&author);
                            }
                            if let Some(att_cid) = view.agent_attestation_cid() {
                                let index =
                                    crate::api::agents::build_agent_id_index(local);
                                agent_id = index.get(&att_cid).cloned();
                            }
                        }
                    }
                }
            }
        }
        (author_hex, agent_id)
    };

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
        uploaded_by_author,
        uploaded_by_agent,
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

    // ── Media extraction state ──────────────────────────────────────
    // Reading the state lazily *triggers* background extraction, so we
    // poll every 2s until it reaches a terminal status. Dioxus cancels
    // the spawned task when the component unmounts (navigation).
    let mut extraction = use_signal(|| None::<ExtractionView>);
    let mut page_summary = use_signal(|| None::<PageRenderSummary>);

    let extraction_cid = data.cid.clone();
    use_effect(move || {
        let cid = extraction_cid.clone();
        spawn(async move {
            loop {
                match get_extraction(cid.clone()).await {
                    Ok(view) => {
                        let pending = view.status == "pending";
                        extraction.set(Some(view));
                        if !pending {
                            break;
                        }
                    }
                    Err(_) => break,
                }
                super::media_poll_delay().await;
            }
        });
    });

    let pages_cid = data.cid.clone();
    use_effect(move || {
        let cid = pages_cid.clone();
        spawn(async move {
            loop {
                match get_page_render_summary(cid.clone()).await {
                    Ok(view) => {
                        let pending = view.status == "pending";
                        page_summary.set(Some(view));
                        if !pending {
                            break;
                        }
                    }
                    Err(_) => break,
                }
                super::media_poll_delay().await;
            }
        });
    });

    let ext = extraction.read().clone();
    let pages = page_summary.read().clone();
    // Audio when the manifest says so, or when a transcript with timed
    // segments showed up (covers containers with loose mime types).
    let is_audio = data.is_audio() || ext.as_ref().is_some_and(|e| e.segments.is_some());
    // Prefer freshly polled text; fall back to the SSR-time value.
    let extracted_text = ext
        .as_ref()
        .and_then(|e| e.text.clone())
        .or_else(|| data.extracted_text.clone());
    let segments = ext.as_ref().and_then(|e| e.segments.clone()).unwrap_or_default();
    let page_count = pages.as_ref().map(|p| p.page_count).unwrap_or(0);
    let show_pages_link = pages
        .as_ref()
        .is_some_and(|p| p.status == "done" || (p.status == "pending" && p.page_count > 0));

    rsx! {
        div { class: "space-y-4",
            // Header
            div { class: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3",
                PageHeader { class: "mb-0", "{data.filename}" }
                div { class: "flex items-center gap-2",
                    if show_pages_link {
                        Link {
                            to: Route::FilePages { cid: data.cid.clone() },
                            class: "btn btn-md btn-secondary",
                            {t!("file-view-pages", count: page_count)}
                        }
                    }
                    a { href: "{download_url}", class: "btn btn-md btn-primary", download: "{data.filename}",
                        {t!("file-download")}
                    }
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
                            if !data.uploaded_by_author.is_empty() || data.uploaded_by_agent.is_some() {
                                tr {
                                    td { class: "td font-medium text-sm", {t!("file-meta-uploaded-by")} }
                                    td { class: "td text-sm",
                                        if let Some(agent_id) = &data.uploaded_by_agent {
                                            span { class: "font-medium", "{agent_id}" }
                                            span { class: "text-[10px] opacity-60 ml-1",
                                                CidDisplay { cid: data.uploaded_by_author.clone(), len: Some(8) }
                                            }
                                        } else {
                                            CidDisplay { cid: data.uploaded_by_author.clone(), len: Some(8) }
                                        }
                                    }
                                }
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

            // Extracted text / transcript. Plain text (no HTML) rendered via
            // text nodes — Dioxus escapes them, so there's no injection risk
            // and no need for an isolating sandbox iframe.
            if is_audio {
                Card {
                    div { class: "p-5",
                        div { class: "flex flex-wrap items-center gap-2",
                            SectionHeading { {t!("file-section-transcript")} }
                            ExtractionStatusPill { extraction: ext.clone() }
                        }
                        audio {
                            controls: true,
                            id: "mv-audio",
                            src: "{download_url}",
                            class: "w-full mt-3",
                        }
                        if !segments.is_empty() {
                            div { class: "mt-3 max-h-[400px] overflow-y-auto divide-y divide-line",
                                for seg in segments {
                                    {
                                        let start_ms = seg.start_ms;
                                        let stamp = fmt_mmss(start_ms);
                                        rsx! {
                                            div { class: "flex items-start gap-3 py-1.5",
                                                button {
                                                    class: "font-mono text-xs text-brand hover:underline shrink-0 mt-0.5 cursor-pointer",
                                                    onclick: move |_| {
                                                        document::eval(&format!(
                                                            "document.getElementById('mv-audio').currentTime = {};",
                                                            start_ms as f64 / 1000.0
                                                        ));
                                                    },
                                                    "[{stamp}]"
                                                }
                                                span { class: "text-sm text-fg-muted", "{seg.text}" }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if let Some(text) = &extracted_text {
                            pre {
                                class: "mt-2 max-h-[400px] overflow-y-auto whitespace-pre-wrap break-words text-[0.8125rem] text-fg-muted m-0",
                                "{text}"
                            }
                        }
                    }
                }
            } else if extracted_text.is_some() || ext.is_some() {
                Card {
                    div { class: "p-5",
                        div { class: "flex flex-wrap items-center gap-2",
                            SectionHeading { {t!("file-section-text")} }
                            ExtractionStatusPill { extraction: ext.clone() }
                        }
                        if let Some(text) = &extracted_text {
                            pre {
                                class: "mt-2 max-h-[400px] overflow-y-auto whitespace-pre-wrap break-words text-[0.8125rem] text-fg-muted m-0",
                                "{text}"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Job-status pill rendered next to the extracted-text / transcript
/// heading. `done` renders nothing — the text itself is the signal.
#[component]
fn ExtractionStatusPill(extraction: Option<ExtractionView>) -> Element {
    let Some(ext) = extraction else {
        return rsx! {};
    };
    match ext.status.as_str() {
        "pending" => rsx! {
            Pill { variant: PillVariant::Info,
                svg {
                    class: "animate-spin h-3 w-3 mr-1 inline",
                    fill: "none",
                    view_box: "0 0 24 24",
                    circle {
                        class: "opacity-25",
                        cx: "12", cy: "12", r: "10",
                        stroke: "currentColor", stroke_width: "4",
                    }
                    path {
                        class: "opacity-75",
                        fill: "currentColor",
                        d: "M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z",
                    }
                }
                {t!("file-extraction-pending")}
            }
        },
        "failed" => rsx! {
            Pill { variant: PillVariant::Bad, {t!("file-extraction-failed")} }
            if let Some(err) = &ext.error {
                span { class: "text-xs text-fg-muted", "{err}" }
            }
        },
        "unavailable" | "unsupported" => rsx! {
            Pill { variant: PillVariant::Warn, {t!("file-extraction-unavailable")} }
            if let Some(err) = &ext.error {
                span { class: "text-xs text-fg-muted", "{err}" }
            }
        },
        _ => rsx! {},
    }
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
