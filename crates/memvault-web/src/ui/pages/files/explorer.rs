//! File explorer page — browse files.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{
    Card, DataTable, PageHeader, Pill, PillVariant, SortState, SortableTh, Td, TdMuted, page_window,
};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::components::time_ago::TimeAgo;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FileRow {
    cid: String,
    filename: String,
    mime_type: String,
    size: u64,
    wall_ns: u64,
}

impl FileRow {
    fn matches_search(&self, query: &str) -> bool {
        self.filename.to_lowercase().contains(query)
            || self.mime_type.to_lowercase().contains(query)
    }

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
async fn list_files(
    view: Option<String>,
    bucket_hex: Option<String>,
    show_retracted: bool,
) -> Result<Vec<FileRow>, ServerFnError> {
    let client = crate::ui::state::client()?;

    // Every file in scope comes from the index (`list_scoped` combines
    // view ∩ bucket ∩ retraction).
    let scope = crate::ui::state::query_scope(
        view,
        bucket_hex.into_iter().collect(),
        show_retracted,
        Some(memvault_core::NodeKind::File),
    );
    let scoped: std::collections::BTreeSet<String> = client
        .list_scoped(&scope, 5000)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .into_iter()
        .filter_map(|n| {
            n.node_id
                .strip_prefix("file:")
                .or_else(|| n.node_id.strip_prefix("attachment:"))
                .map(|s| s.to_string())
        })
        .collect();

    // Upload times from the audit log: the newest 5000 uploads (the op
    // filter applies before the limit). A file beyond them, or uploaded
    // before the log recorded uploads, shows no time rather than going
    // missing.
    let query = memvault_query::AuditQuery {
        op_kind: Some(memvault_query::OpKind::AttachFile),
        limit: Some(5000),
        ..Default::default()
    };
    let mut uploaded = std::collections::HashMap::new();
    match client.audit(query).await {
        Ok(records) => {
            for r in records {
                if let Some(cid) = r.attachment_cid {
                    uploaded.entry(hex::encode(cid)).or_insert(r.wall_ns);
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "files: no upload times from the audit log"),
    }

    // Manifests (name, type, size), a few at a time.
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    for cid_hex in scoped {
        let (client, limit) = (client.clone(), limit.clone());
        let wall_ns = uploaded.get(&cid_hex).copied().unwrap_or(0);
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await;
            let manifest = match hex::decode(&cid_hex) {
                Ok(cid) => client.get_file_manifest(&cid).await.ok().flatten(),
                Err(_) => None,
            };
            // DAG-CBOR locally, JSON over HTTP: deserialize_block reads both.
            let m: serde_json::Value = manifest
                .as_deref()
                .and_then(memvault_store::deserialize_block)
                .unwrap_or_default();
            FileRow {
                filename: m
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed")
                    .to_string(),
                mime_type: m
                    .get("mime_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("application/octet-stream")
                    .to_string(),
                size: m.get("content_size").and_then(|v| v.as_u64()).unwrap_or(0),
                cid: cid_hex,
                wall_ns,
            }
        });
    }
    let mut files: Vec<FileRow> = tasks.join_all().await;
    files.sort_by(|a, b| b.wall_ns.cmp(&a.wall_ns));
    Ok(files)
}

#[component]
pub fn FileExplorer() -> Element {
    use_topbar(&t!("files-title"));
    let filters = crate::ui::filters::use_filters();
    let files = use_server_future(move || {
        let f = filters.read();
        async move { list_files(f.view, f.bucket, f.show_retracted).await }
    })?;
    // Re-fetch on in-place scope change (use_server_future only re-runs on
    // remount, not on signal change).
    use_effect(move || {
        let _ = filters.read();
        let mut r = files;
        r.restart();
    });
    let mut grid_view = use_signal(|| false);

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center justify-between",
                PageHeader { class: "mb-0", {t!("files-title")} }
                div { class: "flex gap-1",
                    button {
                        class: if !*grid_view.read() { "btn btn-xs btn-primary" } else { "btn btn-xs btn-secondary" },
                        onclick: move |_| grid_view.set(false),
                        {t!("list")}
                    }
                    button {
                        class: if *grid_view.read() { "btn btn-xs btn-primary" } else { "btn btn-xs btn-secondary" },
                        onclick: move |_| grid_view.set(true),
                        {t!("grid")}
                    }
                }
            }
            {match &*files.read() {
                Some(Ok(list)) => {
                    if *grid_view.read() {
                        rsx! { FileGrid { list: list.clone() } }
                    } else {
                        rsx! { FileTable { list: list.clone() } }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
            }}
        }
    }
}

#[component]
fn FileGrid(list: Vec<FileRow>) -> Element {
    if list.is_empty() {
        return rsx! {
            Card {
                div { class: "p-8 text-center text-fg-muted", {t!("files-empty")} }
            }
        };
    }

    rsx! {
        div { class: "grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3",
            for file in &list {
                Link { to: Route::FileDetail { cid: file.cid.clone() },
                    Card { class: "hover:border-brand transition-colors",
                        div { class: "p-4 text-center space-y-2",
                            // Thumbnail or icon
                            if file.mime_type.starts_with("image/") {
                                img {
                                    src: "/api/v1/files/{file.cid}",
                                    alt: "{file.filename}",
                                    class: "w-full h-32 object-cover rounded",
                                }
                            } else {
                                div { class: "w-full h-32 flex items-center justify-center bg-surface-2 rounded",
                                    span { class: "text-3xl text-fg-faint", "\u{1F4C4}" }
                                }
                            }
                            p { class: "text-sm font-medium truncate", "{file.filename}" }
                            div { class: "flex items-center justify-center gap-2",
                                Pill { variant: PillVariant::Muted, "{file.mime_type}" }
                            }
                            span { class: "text-xs text-fg-muted font-mono", "{file.size_display()}" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn FileTable(list: ReadSignal<Vec<FileRow>>) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 20usize);
    let page = use_signal(|| 0usize);
    let sort = use_signal::<SortState>(|| ("wall_ns".to_string(), false));

    let filtered = use_memo(move || {
        // Read `list` reactively so the table refreshes when the parent
        // re-fetches on a scope (bucket/view/retracted) change.
        let list = list.read();
        let q = search.read().to_lowercase();
        let mut items: Vec<FileRow> = if q.is_empty() {
            list.clone()
        } else {
            list.iter()
                .filter(|f| f.matches_search(&q))
                .cloned()
                .collect()
        };
        let (key, asc) = sort.read().clone();
        items.sort_by(|a, b| {
            let ord = match key.as_str() {
                "name" => a.filename.to_lowercase().cmp(&b.filename.to_lowercase()),
                "type" => a.mime_type.cmp(&b.mime_type),
                "size" => a.size.cmp(&b.size),
                _ => a.wall_ns.cmp(&b.wall_ns),
            };
            if asc { ord } else { ord.reverse() }
        });
        items
    });

    let total = list.read().len();
    let filtered_count = filtered.read().len();
    let limit_val = *limit.read();
    let (start, shown) = page_window(*page.read(), limit_val, filtered_count);

    rsx! {
        DataTable {
            search, limit, page, total, filtered: filtered_count, shown,
            headers: rsx! {
                SortableTh { label: t!("files-th-name"), sort_key: "name".to_string(), sort }
                SortableTh { label: t!("files-th-type"), sort_key: "type".to_string(), sort }
                SortableTh { label: t!("files-th-size"), sort_key: "size".to_string(), sort }
                th { class: "th", {t!("files-th-cid")} }
                SortableTh { label: t!("files-th-uploaded"), sort_key: "wall_ns".to_string(), sort }
            },
            body: rsx! {
                for file in filtered.read().iter().skip(start).take(limit_val) {
                    tr { key: "{file.cid}",
                        Td {
                            Link { to: Route::FileDetail { cid: file.cid.clone() }, class: "link",
                                "{file.filename}"
                            }
                        }
                        Td { Pill { variant: PillVariant::Muted, "{file.mime_type}" } }
                        TdMuted { "{file.size_display()}" }
                        Td { CidDisplay { cid: file.cid.clone() } }
                        TdMuted { TimeAgo { wall_ns: file.wall_ns } }
                    }
                }
            },
        }
    }
}
