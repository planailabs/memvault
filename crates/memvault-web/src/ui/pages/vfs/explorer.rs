//! VFS explorer page — browse the virtual filesystem.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Card, DataTable, Pill, PillVariant, SortState, SortableTh, Td, TdMuted};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct VfsRow {
    name: String,
    node_id: String,
    node_type: String,
    edge_id: String,
}

impl VfsRow {
    fn matches_search(&self, query: &str) -> bool {
        self.name.to_lowercase().contains(query)
            || self.node_type.to_lowercase().contains(query)
            || self.node_id.to_lowercase().contains(query)
    }

    fn type_icon(&self) -> &'static str {
        match self.node_type.as_str() {
            "dir" => "\u{1F4C1}",
            "doc" => "\u{1F4DD}",
            "file" | "attachment" => "\u{1F4CE}",
            "entity" => "\u{1F7E3}",
            _ => "\u{2753}",
        }
    }
}

// ── Server functions ───────────────────────────────────────────────

#[server]
async fn list_vfs_entries(
    path: String,
    bucket_hex: String,
) -> Result<Vec<VfsRow>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let bucket = memvault_core::BucketId::from_hex(&bucket_hex)
        .map_err(|e| ServerFnError::new(format!("invalid bucket: {e}")))?;

    let entries = client
        .vfs_ls(&bucket, &path, false)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut rows: Vec<VfsRow> = entries
        .into_iter()
        .map(|e| VfsRow {
            name: e.name,
            node_id: e.node_id,
            node_type: e.node_type,
            edge_id: e.edge_id,
        })
        .collect();
    // UX: directories first, then alphabetical (case-insensitive).
    rows.sort_by(|a, b| {
        let dir_ord = (a.node_type != "dir").cmp(&(b.node_type != "dir"));
        dir_ord.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(rows)
}

#[server]
async fn vfs_mkdir(path: String, bucket_hex: String) -> Result<String, ServerFnError> {
    let client = crate::ui::state::client()?;
    let bucket = memvault_core::BucketId::from_hex(&bucket_hex)
        .map_err(|e| ServerFnError::new(format!("invalid bucket: {e}")))?;
    let id = client
        .vfs_mkdir(&bucket, &path)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(format!("entity:{}", hex::encode(id.0)))
}

// ── UI Components ──────────────────────────────────────────────────

/// VFS explorer — single route at `/vfs`, path tracked via signal + URL hash.
#[component]
pub fn VfsExplorer() -> Element {
    use_topbar(&t!("vfs-title"));

    let mut path = use_signal(|| "/".to_string());

    // Restore path from URL hash on mount (e.g. /vfs#/projects/acme).
    use_effect(move || {
        spawn(async move {
            let result = document::eval(
                "try { var h = window.location.hash.slice(1); return h || '/'; } catch(e) { return '/'; }"
            ).await;
            if let Ok(val) = result {
                if let Some(p) = val.as_str() {
                    if !p.is_empty() && p != path.peek().as_str() {
                        path.set(p.to_string());
                    }
                }
            }
        });
    });

    // Sync path to URL hash when it changes.
    use_effect(move || {
        let p = path.read().clone();
        let hash = if p == "/" {
            String::new()
        } else {
            format!("#{p}")
        };
        document::eval(&format!(
            "try {{ history.replaceState(null, '', window.location.pathname + '{hash}'); }} catch(e) {{}}"
        ));
    });

    let active_bucket = use_context::<crate::ui::topbar::ActiveBucketSignal>();

    // Each bucket has its own VFS root — "All buckets" has no single tree to show.
    if active_bucket.read().id.is_none() {
        return rsx! {
            div { class: "space-y-4",
                plan_ai_design::PageHeader { {t!("vfs-title")} }
                plan_ai_design::Card {
                    div { class: "p-8 text-center text-fg-muted space-y-2",
                        p { "Each bucket has its own virtual filesystem." }
                        p { "Select a bucket from the dropdown above to browse its files." }
                    }
                }
            }
        };
    }

    let mut entries = use_server_future(move || {
        let p = path.read().clone();
        // The early-return above guarantees `id` is Some when we get here.
        let b = active_bucket.read().id.clone().unwrap_or_default();
        async move { list_vfs_entries(p, b).await }
    })?;
    let mut grid_view = use_signal(|| true);
    let mut new_dir_name = use_signal(String::new);
    let mut creating = use_signal(|| false);

    let breadcrumbs = {
        let p = path.read().clone();
        let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
        let mut crumbs: Vec<(String, String)> = vec![("/".to_string(), "/".to_string())];
        let mut accum = String::new();
        for part in parts {
            accum.push('/');
            accum.push_str(part);
            crumbs.push((accum.clone(), part.to_string()));
        }
        crumbs
    };

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center justify-between flex-wrap gap-2",
                nav { class: "flex items-center gap-1 text-sm",
                    for (i, (crumb_path, label)) in breadcrumbs.iter().enumerate() {
                        if i > 0 {
                            span { class: "text-fg-muted", "/" }
                        }
                        button {
                            class: "link text-sm",
                            onclick: {
                                let p = crumb_path.clone();
                                move |_| path.set(p.clone())
                            },
                            "{label}"
                        }
                    }
                }
                div { class: "flex gap-1 items-center",
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

            div { class: "flex gap-2 items-center",
                input {
                    class: "input input-sm flex-1",
                    r#type: "text",
                    placeholder: t!("vfs-placeholder-folder"),
                    value: "{new_dir_name}",
                    oninput: move |e| new_dir_name.set(e.value()),
                }
                button {
                    class: "btn btn-sm btn-secondary",
                    disabled: *creating.read() || new_dir_name.read().is_empty(),
                    onclick: move |_| {
                        let dir_name = new_dir_name.read().clone();
                        if dir_name.is_empty() { return; }
                        let current_path = path.read().clone();
                        let mkdir_path = if current_path == "/" {
                            format!("/{dir_name}")
                        } else {
                            format!("{current_path}/{dir_name}")
                        };
                        // The early-return above guarantees `id` is Some when we get here.
                        let bucket_hex = active_bucket.read().id.clone().unwrap_or_default();
                        creating.set(true);
                        spawn(async move {
                            let _ = vfs_mkdir(mkdir_path, bucket_hex).await;
                            creating.set(false);
                            new_dir_name.set(String::new());
                            entries.restart();
                        });
                    },
                    if *creating.read() { {t!("vfs-creating")} } else { {t!("vfs-new-folder")} }
                }
            }

            {match &*entries.read() {
                Some(Ok(list)) => {
                    if list.is_empty() {
                        rsx! {
                            Card {
                                div { class: "p-8 text-center text-fg-muted", {t!("vfs-empty")} }
                            }
                        }
                    } else if *grid_view.read() {
                        rsx! { VfsGrid { list: list.clone(), path } }
                    } else {
                        rsx! { VfsTable { list: list.clone(), path } }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
            }}
        }
    }
}

#[component]
fn VfsGrid(list: Vec<VfsRow>, path: Signal<String>) -> Element {
    rsx! {
        div { class: "grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3",
            for entry in &list {
                {render_grid_card(entry, path)}
            }
        }
    }
}

fn render_grid_card(entry: &VfsRow, mut path: Signal<String>) -> Element {
    let entry_clone = entry.clone();
    if entry.node_type == "dir" {
        let target_path = {
            let current = path.read().clone();
            if current == "/" {
                format!("/{}", entry.name)
            } else {
                format!("{current}/{}", entry.name)
            }
        };
        rsx! {
            div {
                onclick: move |_| path.set(target_path.clone()),
                class: "cursor-pointer",
                Card { class: "hover:border-brand transition-colors",
                    div { class: "p-4 text-center space-y-2",
                        div { class: "w-full h-20 flex items-center justify-center bg-surface-2 rounded",
                            span { class: "text-4xl", "\u{1F4C1}" }
                        }
                        p { class: "text-sm font-medium truncate", "{entry_clone.name}" }
                        Pill { variant: PillVariant::Muted, "dir" }
                    }
                }
            }
        }
    } else {
        let route = node_route(&entry.node_id, &entry.node_type);
        rsx! {
            if let Some(route) = route {
                Link { to: route,
                    Card { class: "hover:border-brand transition-colors",
                        div { class: "p-4 text-center space-y-2",
                            div { class: "w-full h-20 flex items-center justify-center bg-surface-2 rounded",
                                span { class: "text-3xl", "{entry_clone.type_icon()}" }
                            }
                            p { class: "text-sm font-medium truncate", "{entry_clone.name}" }
                            Pill { variant: PillVariant::Muted, "{entry_clone.node_type}" }
                        }
                    }
                }
            } else {
                Card { class: "opacity-75",
                    div { class: "p-4 text-center space-y-2",
                        div { class: "w-full h-20 flex items-center justify-center bg-surface-2 rounded",
                            span { class: "text-3xl", "{entry_clone.type_icon()}" }
                        }
                        p { class: "text-sm font-medium truncate", "{entry_clone.name}" }
                        Pill { variant: PillVariant::Muted, "{entry_clone.node_type}" }
                    }
                }
            }
        }
    }
}

#[component]
fn VfsTable(list: ReadSignal<Vec<VfsRow>>, path: Signal<String>) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 50usize);
    let sort = use_signal::<SortState>(|| ("name".to_string(), true));

    let filtered = use_memo(move || {
        // Read `list` reactively so the table refreshes when the parent re-fetches.
        let list = list.read();
        let q = search.read().to_lowercase();
        let mut items: Vec<VfsRow> = if q.is_empty() {
            list.clone()
        } else {
            list.iter()
                .filter(|e| e.matches_search(&q))
                .cloned()
                .collect()
        };
        let (key, asc) = sort.read().clone();
        items.sort_by(|a, b| {
            let ord = match key.as_str() {
                "type" => a.node_type.cmp(&b.node_type),
                "node_id" => a.node_id.cmp(&b.node_id),
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            };
            if asc { ord } else { ord.reverse() }
        });
        items
    });

    let total = list.read().len();
    let filtered_count = filtered.read().len();
    let limit_val = *limit.read();
    let shown = filtered_count.min(limit_val);

    rsx! {
        DataTable {
            search, limit, total, filtered: filtered_count, shown,
            headers: rsx! {
                SortableTh { label: t!("vfs-th-name"), sort_key: "name".to_string(), sort }
                SortableTh { label: t!("vfs-th-type"), sort_key: "type".to_string(), sort }
                SortableTh { label: t!("vfs-th-node-id"), sort_key: "node_id".to_string(), sort }
            },
            body: rsx! {
                for entry in filtered.read().iter().take(limit_val) {
                    VfsTableRow { entry: entry.clone(), path }
                }
            },
        }
    }
}

#[component]
fn VfsTableRow(entry: VfsRow, path: Signal<String>) -> Element {
    let entry_clone = entry.clone();
    rsx! {
        tr { key: "{entry.edge_id}",
            Td {
                if entry.node_type == "dir" {
                    {render_dir_button(&entry_clone, path)}
                } else if let Some(route) = node_route(&entry.node_id, &entry.node_type) {
                    Link { to: route, class: "link",
                        "{entry.type_icon()} {entry.name}"
                    }
                } else {
                    span { "{entry.type_icon()} {entry.name}" }
                }
            }
            Td { Pill { variant: PillVariant::Muted, "{entry.node_type}" } }
            TdMuted { class: "font-mono text-xs", "{entry.node_id}" }
        }
    }
}

fn render_dir_button(entry: &VfsRow, mut path: Signal<String>) -> Element {
    let target_path = {
        let current = path.read().clone();
        if current == "/" {
            format!("/{}", entry.name)
        } else {
            format!("{current}/{}", entry.name)
        }
    };
    rsx! {
        button {
            class: "link font-medium",
            onclick: move |_| path.set(target_path.clone()),
            "\u{1F4C1} {entry.name}"
        }
    }
}

fn node_route(node_id: &str, node_type: &str) -> Option<Route> {
    match node_type {
        "doc" => {
            let id = node_id.strip_prefix("doc:").unwrap_or(node_id).to_string();
            Some(Route::NoteDetail { id })
        }
        "entity" => {
            let id = node_id
                .strip_prefix("entity:")
                .unwrap_or(node_id)
                .to_string();
            Some(Route::EntityDetail { id })
        }
        "file" | "attachment" => {
            let cid = node_id
                .strip_prefix("file:")
                .or_else(|| node_id.strip_prefix("attachment:"))
                .unwrap_or(node_id)
                .to_string();
            Some(Route::FileDetail { cid })
        }
        _ => None,
    }
}
