//! VFS explorer page — browse the virtual filesystem.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Card, DataTable, Pill, PillVariant, SortState, SortableTh, Td, TdMuted};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::topbar::use_topbar;

const VFS_DIR_KIND: &str = "vfs:dir";
const VFS_CHILD_REL: &str = "vfs:child";

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
            "attachment" => "\u{1F4CE}",
            "entity" => "\u{1F7E3}",
            _ => "\u{2753}",
        }
    }
}

// ── Server functions ───────────────────────────────────────────────

#[server]
async fn list_vfs_entries(path: String) -> Result<Vec<VfsRow>, ServerFnError> {
    use memvault_core::NodeRef;
    let client = crate::ui::state::client()?;

    let root_id = vfs_ensure_root(&*client).await?;
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let mut current = NodeRef::Entity(root_id);
    for component in &components {
        let child = vfs_find_named_child(&*client, &current, component).await?
            .ok_or_else(|| ServerFnError::new(format!("path component '{component}' not found")))?;
        current = child;
    }

    let edges = client.edges_of(&current).await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut entries = Vec::new();
    for (src, edge) in &edges {
        // Only outgoing edges (source == current dir); edges_of returns both directions.
        if src != &current {
            continue;
        }
        if edge.relation != VFS_CHILD_REL {
            continue;
        }
        let name = edge.props.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let node_id = edge.target.tag_label();
        let node_type = vfs_resolve_type(&*client, &edge.target).await;
        entries.push(VfsRow {
            name,
            node_id,
            node_type,
            edge_id: hex::encode(edge.id.0),
        });
    }
    entries.sort_by(|a, b| {
        let dir_ord = (a.node_type != "dir").cmp(&(b.node_type != "dir"));
        dir_ord.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

#[server]
async fn vfs_mkdir(path: String) -> Result<String, ServerFnError> {
    use memvault_core::NodeRef;
    let client = crate::ui::state::client()?;
    let root_id = vfs_ensure_root(&*client).await?;
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        return Ok(format!("entity:{}", hex::encode(root_id.0)));
    }
    let mut current = NodeRef::Entity(root_id);
    for component in &components {
        match vfs_find_named_child(&*client, &current, component).await? {
            Some(child) => current = child,
            None => {
                let id = vfs_create_dir(&*client, component).await?;
                let child = NodeRef::Entity(id);
                vfs_create_edge(&*client, &current, &child, component).await?;
                current = child;
            }
        }
    }
    Ok(current.tag_label())
}

// ── Server-side helpers ────────────────────────────────────────────

#[cfg(feature = "server")]
async fn vfs_ensure_root(
    client: &dyn memvault_api::MemvaultClient,
) -> Result<memvault_core::EntityId, ServerFnError> {
    use memvault_core::{EntityId, Visibility};
    use memvault_doc::Entity;
    use std::collections::BTreeMap;

    let entities = client.list_entities(500).await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let mut candidates: Vec<[u8; 32]> = Vec::new();
    for e in &entities {
        if e.kind == VFS_DIR_KIND {
            let node_id = format!("entity:{}", hex::encode(e.id.0));
            let tags = client.get_tags(&node_id).await.unwrap_or_default();
            if tags.iter().any(|(s, l)| s == "vfs" && l == "root") {
                candidates.push(e.id.0);
            }
        }
    }
    if !candidates.is_empty() {
        candidates.sort();
        return Ok(EntityId(candidates[0]));
    }
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!("/"));
    let entity = Entity {
        id: EntityId::random(),
        kind: VFS_DIR_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    let id = client.add_entity(entity, Visibility::Internal).await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let node_id = format!("entity:{}", hex::encode(id.0));
    client.add_tags(&node_id, vec![("vfs".into(), "root".into())]).await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(id)
}

#[cfg(feature = "server")]
async fn vfs_find_named_child(
    client: &dyn memvault_api::MemvaultClient,
    parent: &memvault_core::NodeRef,
    name: &str,
) -> Result<Option<memvault_core::NodeRef>, ServerFnError> {
    let edges = client.edges_of(parent).await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let mut best: Option<(memvault_core::NodeRef, [u8; 32])> = None;
    for (src, edge) in &edges {
        if src != parent {
            continue;
        }
        if edge.relation != VFS_CHILD_REL {
            continue;
        }
        let edge_name = edge.props.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        if edge_name != name {
            continue;
        }
        match &best {
            Some((_, eid)) if *eid <= edge.id.0 => {}
            _ => best = Some((edge.target.clone(), edge.id.0)),
        }
    }
    Ok(best.map(|(node, _)| node))
}

#[cfg(feature = "server")]
async fn vfs_resolve_type(
    client: &dyn memvault_api::MemvaultClient,
    node: &memvault_core::NodeRef,
) -> String {
    match node {
        memvault_core::NodeRef::Entity(eid) => {
            if let Ok(Some(e)) = client.get_entity(eid).await {
                if e.kind == VFS_DIR_KIND {
                    return "dir".to_string();
                }
            }
            "entity".to_string()
        }
        memvault_core::NodeRef::Doc(_) => "doc".to_string(),
        memvault_core::NodeRef::Attachment(_) => "attachment".to_string(),
    }
}

#[cfg(feature = "server")]
async fn vfs_create_dir(
    client: &dyn memvault_api::MemvaultClient,
    name: &str,
) -> Result<memvault_core::EntityId, ServerFnError> {
    use memvault_core::{EntityId, Visibility};
    use memvault_doc::Entity;
    use std::collections::BTreeMap;

    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!(name));
    let entity = Entity {
        id: EntityId::random(),
        kind: VFS_DIR_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    client.add_entity(entity, Visibility::Internal).await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[cfg(feature = "server")]
async fn vfs_create_edge(
    client: &dyn memvault_api::MemvaultClient,
    parent: &memvault_core::NodeRef,
    child: &memvault_core::NodeRef,
    name: &str,
) -> Result<memvault_core::EdgeId, ServerFnError> {
    use memvault_core::{EdgeId, Visibility};
    use memvault_doc::Edge;
    use std::collections::BTreeMap;

    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::Value::String(name.to_string()));
    let edge = Edge {
        id: EdgeId::random(),
        relation: VFS_CHILD_REL.to_string(),
        target: child.clone(),
        weight: None,
        props,
        provenance: None,
    };
    client.add_link(parent, edge, Visibility::Internal).await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// ── UI Components ──────────────────────────────────────────────────

/// Route component for `/vfs` (root directory).
#[component]
pub fn VfsRoot() -> Element {
    rsx! { VfsExplorerInner { path: "/".to_string() } }
}

/// Route component for `/vfs/*segments` (subdirectory).
#[component]
pub fn VfsBrowse(segments: String) -> Element {
    let path = format!("/{segments}");
    rsx! { VfsExplorerInner { path } }
}

/// Compute the Dioxus route for a directory path.
fn dir_route(current_path: &str, name: &str) -> Route {
    let child_path = if current_path == "/" {
        name.to_string()
    } else {
        let trimmed = current_path.strip_prefix('/').unwrap_or(current_path);
        format!("{trimmed}/{name}")
    };
    Route::VfsBrowse { segments: child_path }
}

#[component]
fn VfsExplorerInner(path: String) -> Element {
    use_topbar(&t!("vfs-title"));

    let path_clone = path.clone();
    let mut entries = use_server_future(move || {
        let p = path_clone.clone();
        async move { list_vfs_entries(p).await }
    })?;
    let mut grid_view = use_signal(|| true);
    let mut new_dir_name = use_signal(String::new);
    let mut creating = use_signal(|| false);

    let breadcrumbs = {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut crumbs: Vec<(Route, String)> = vec![(Route::VfsRoot {}, "/".to_string())];
        let mut accum = String::new();
        for part in parts {
            if !accum.is_empty() {
                accum.push('/');
            }
            accum.push_str(part);
            crumbs.push((Route::VfsBrowse { segments: accum.clone() }, part.to_string()));
        }
        crumbs
    };

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center justify-between flex-wrap gap-2",
                nav { class: "flex items-center gap-1 text-sm",
                    for (i, (route, label)) in breadcrumbs.iter().enumerate() {
                        if i > 0 {
                            span { class: "text-fg-muted", "/" }
                        }
                        Link { to: route.clone(), class: "link text-sm", "{label}" }
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
                    onclick: {
                        let current_path = path.clone();
                        move |_| {
                            let dir_name = new_dir_name.read().clone();
                            if dir_name.is_empty() { return; }
                            let mkdir_path = if current_path == "/" {
                                format!("/{dir_name}")
                            } else {
                                format!("{current_path}/{dir_name}")
                            };
                            creating.set(true);
                            spawn(async move {
                                let _ = vfs_mkdir(mkdir_path).await;
                                creating.set(false);
                                new_dir_name.set(String::new());
                                entries.restart();
                            });
                        }
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
                        rsx! { VfsGrid { list: list.clone(), current_path: path.clone() } }
                    } else {
                        rsx! { VfsTable { list: list.clone(), current_path: path.clone() } }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
            }}
        }
    }
}

#[component]
fn VfsGrid(list: Vec<VfsRow>, current_path: String) -> Element {
    rsx! {
        div { class: "grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3",
            for entry in &list {
                {render_grid_card(entry, &current_path)}
            }
        }
    }
}

fn render_grid_card(entry: &VfsRow, current_path: &str) -> Element {
    let entry_clone = entry.clone();
    if entry.node_type == "dir" {
        let route = dir_route(current_path, &entry.name);
        rsx! {
            Link { to: route,
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
fn VfsTable(list: Vec<VfsRow>, current_path: String) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 50usize);
    let sort = use_signal::<SortState>(|| ("name".to_string(), true));

    let list_clone = list.clone();
    let filtered = use_memo(move || {
        let q = search.read().to_lowercase();
        let mut items: Vec<VfsRow> = if q.is_empty() {
            list_clone.clone()
        } else {
            list_clone.iter().filter(|e| e.matches_search(&q)).cloned().collect()
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

    let total = list.len();
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
                    VfsTableRow { entry: entry.clone(), current_path: current_path.clone() }
                }
            },
        }
    }
}

#[component]
fn VfsTableRow(entry: VfsRow, current_path: String) -> Element {
    rsx! {
        tr { key: "{entry.edge_id}",
            Td {
                if entry.node_type == "dir" {
                    Link { to: dir_route(&current_path, &entry.name), class: "link font-medium",
                        "\u{1F4C1} {entry.name}"
                    }
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

fn node_route(node_id: &str, node_type: &str) -> Option<Route> {
    match node_type {
        "doc" => {
            let id = node_id.strip_prefix("doc:").unwrap_or(node_id).to_string();
            Some(Route::NoteDetail { id })
        }
        "entity" => {
            let id = node_id.strip_prefix("entity:").unwrap_or(node_id).to_string();
            Some(Route::EntityDetail { id })
        }
        "attachment" => {
            let cid = node_id.strip_prefix("attachment:").unwrap_or(node_id).to_string();
            Some(Route::FileDetail { cid })
        }
        _ => None,
    }
}
