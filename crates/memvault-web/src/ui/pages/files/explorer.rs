//! File explorer page — browse files.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{
    Card, DataTable, PageHeader, Pill, PillVariant, SortState, SortableTh, Td, TdMuted,
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

    // Authoritative scoped file set: the (view, bucket, retracted) triplet is
    // resolved server-side by `list_scoped` (which combines view ∩ bucket ∩
    // retraction — the per-bucket inferred-bucket filter the old per-page logic
    // got wrong). We then enrich + time-order via the audit log below.
    let scope = crate::ui::state::query_scope(
        view,
        bucket_hex.into_iter().collect(),
        show_retracted,
        Some(memvault_core::NodeKind::File),
    );
    let scoped_files: std::collections::HashSet<String> = client
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

    use memvault_query::AuditQuery;

    // Query audit log for AttachFile operations to discover files (gives us
    // wall_ns + manifest metadata), filtered to the scoped set.
    let query = AuditQuery {
        op_kind: Some(memvault_query::OpKind::AttachFile),
        limit: Some(5000),
        ..Default::default()
    };
    let records = client
        .audit(query)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for record in records {
        let manifest_cid = match &record.attachment_cid {
            Some(cid) => cid.clone(),
            None => continue,
        };
        let cid_hex = hex::encode(&manifest_cid);
        if !scoped_files.contains(&cid_hex) {
            continue;
        }
        if !seen.insert(cid_hex.clone()) {
            continue;
        }
        // Read manifest block (always exists after repair-index). The
        // block is DAG-CBOR, not JSON — use the canonical helper so
        // filename/mime_type/content_size come through instead of
        // collapsing to defaults ("unnamed" / octet-stream / 0).
        let (filename, mime_type, size) = match client.get_file_manifest(&manifest_cid).await {
            Ok(Some(bytes)) => {
                let m: serde_json::Value =
                    memvault_store::deserialize_block(&bytes).unwrap_or_default();
                (
                    m.get("filename")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed")
                        .to_string(),
                    m.get("mime_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("application/octet-stream")
                        .to_string(),
                    m.get("content_size").and_then(|v| v.as_u64()).unwrap_or(0),
                )
            }
            _ => (
                "unnamed".to_string(),
                "application/octet-stream".to_string(),
                0,
            ),
        };

        files.push(FileRow {
            cid: cid_hex,
            filename,
            mime_type,
            size,
            wall_ns: record.wall_ns,
        });
    }

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
fn FileTable(list: Vec<FileRow>) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 20usize);
    let sort = use_signal::<SortState>(|| ("wall_ns".to_string(), false));

    let list_clone = list.clone();
    let filtered = use_memo(move || {
        let q = search.read().to_lowercase();
        let mut items: Vec<FileRow> = if q.is_empty() {
            list_clone.clone()
        } else {
            list_clone
                .iter()
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

    let total = list.len();
    let filtered_count = filtered.read().len();
    let limit_val = *limit.read();
    let shown = filtered_count.min(limit_val);

    rsx! {
        DataTable {
            search, limit, total, filtered: filtered_count, shown,
            headers: rsx! {
                SortableTh { label: t!("files-th-name"), sort_key: "name".to_string(), sort }
                SortableTh { label: t!("files-th-type"), sort_key: "type".to_string(), sort }
                SortableTh { label: t!("files-th-size"), sort_key: "size".to_string(), sort }
                th { class: "th", {t!("files-th-cid")} }
                SortableTh { label: t!("files-th-uploaded"), sort_key: "wall_ns".to_string(), sort }
            },
            body: rsx! {
                for file in filtered.read().iter().take(limit_val) {
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
