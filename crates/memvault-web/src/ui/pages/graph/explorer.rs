//! Graph explorer page — interactive force-directed knowledge graph.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Card, PageHeader, Pill};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::layout_engine::{ForceSimulation, GraphEdge, GraphNode};
use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::topbar::use_topbar;

// ── Data types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NodeSummary {
    /// Unique ID in tag_label format: "entity:<hex>", "doc:<hex>", "file:<hex>"
    id: String,
    /// "entity", "doc", "file"
    node_type: String,
    /// Entity kind (e.g. "person") or "document"/"file" for docs/files
    kind: String,
    label: String,
    edges: Vec<EdgeSummary>,
    props: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EdgeSummary {
    edge_id: String,
    relation: String,
    target_id: String,
    weight: f32,
}

/// Lazy-loaded detail for the sidebar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NodeDetail {
    id: String,
    node_type: String,
    kind: String,
    label: String,
    props: BTreeMap<String, serde_json::Value>,
    edges: Vec<EdgeDetail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EdgeDetail {
    edge_id: String,
    relation: String,
    direction: String,
    other_node: String,
    other_label: Option<String>,
}

// ── Server functions ───────────────────────────────────────────────────

#[server]
async fn list_graph_nodes(view: Option<String>) -> Result<Vec<NodeSummary>, ServerFnError> {
    let client = crate::ui::state::client()?;

    // If a view is active, get all nodes matching the view.
    if let Some(ref view_name) = view {
        let items = client.list_all(Some(view_name), 200).await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let mut nodes = Vec::new();
        for (id, node_type, label, _tags) in &items {
            // Skip vfs:dir entities from graph view.
            if node_type == "entity" {
                if let Some(memvault_core::NodeRef::Entity(eid)) = memvault_core::NodeRef::from_tag_label(id) {
                    if let Ok(Some(e)) = client.get_entity(&eid).await {
                        if e.kind == "vfs:dir" { continue; }
                    }
                }
            }
            let mut edges = Vec::new();
            if let Some(node_ref) = memvault_core::NodeRef::from_tag_label(id) {
                if let Ok(edge_list) = client.edges_of(&node_ref).await {
                    for (src, edge) in &edge_list {
                        if src != &node_ref || edge.relation == "vfs:child" { continue; }
                        edges.push(EdgeSummary {
                            edge_id: hex::encode(edge.id.0),
                            relation: edge.relation.clone(),
                            target_id: edge.target.tag_label(),
                            weight: edge.weight.unwrap_or(1.0),
                        });
                    }
                }
            }
            nodes.push(NodeSummary {
                id: id.clone(), node_type: node_type.clone(), kind: node_type.clone(),
                label: label.clone(), edges, props: std::collections::BTreeMap::new(),
            });
        }
        return Ok(nodes);
    }

    // Load entities
    let entities = client
        .list_entities(200, None)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut nodes: Vec<NodeSummary> = entities
        .into_iter()
        .filter(|entity| entity.kind != "vfs:dir")
        .map(|entity| {
            let label = entity
                .props
                .get("name")
                .or_else(|| entity.props.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or(&entity.kind)
                .to_string();
            let id = format!("entity:{}", hex::encode(entity.id.0));
            NodeSummary {
                id,
                node_type: "entity".to_string(),
                kind: entity.kind,
                label,
                edges: entity
                    .edges_out
                    .iter()
                    .filter(|e| e.relation != "vfs:child")
                    .map(|e| EdgeSummary {
                        edge_id: hex::encode(e.id.0),
                        relation: e.relation.clone(),
                        target_id: e.target.tag_label(),
                        weight: e.weight.unwrap_or(1.0),
                    })
                    .collect(),
                props: entity.props,
            }
        })
        .collect();

    // Collect doc/attachment nodes that are targets of edges but not yet in the list
    let mut extra_ids: Vec<String> = Vec::new();
    for node in &nodes {
        for edge in &node.edges {
            if !edge.target_id.starts_with("entity:") && !nodes.iter().any(|n| n.id == edge.target_id) {
                extra_ids.push(edge.target_id.clone());
            }
        }
    }
    extra_ids.sort();
    extra_ids.dedup();

    for extra_id in &extra_ids {
        let node_ref = match memvault_core::NodeRef::from_tag_label(extra_id) {
            Some(r) => r,
            None => continue,
        };
        let (node_type, kind, label) = match &node_ref {
            memvault_core::NodeRef::Doc(did) => {
                let title = client.get_doc(did).await.ok().flatten()
                    .and_then(|d| d.frontmatter.get("title").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| "Untitled".to_string());
                ("doc".to_string(), "doc".to_string(), title)
            }
            memvault_core::NodeRef::Attachment(cid) => {
                let name = client.get_file_manifest(cid).await.ok().flatten()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .and_then(|v| v.get("filename").and_then(|f| f.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| "Unnamed file".to_string());
                ("file".to_string(), "file".to_string(), name)
            }
            memvault_core::NodeRef::Entity(eid) => {
                // Skip vfs:dir entities that appear as edge targets.
                if let Ok(Some(e)) = client.get_entity(eid).await {
                    if e.kind == "vfs:dir" { continue; }
                    let label = e.props.get("name").or_else(|| e.props.get("title"))
                        .and_then(|v| v.as_str()).unwrap_or(&e.kind).to_string();
                    ("entity".to_string(), e.kind.clone(), label)
                } else {
                    continue;
                }
            }
        };
        nodes.push(NodeSummary {
            id: extra_id.clone(),
            node_type,
            kind,
            label,
            edges: vec![],
            props: BTreeMap::new(),
        });
    }

    Ok(nodes)
}

#[server]
async fn get_node_detail(node_id: String) -> Result<NodeDetail, ServerFnError> {
    let client = crate::ui::state::client()?;

    let node_ref = memvault_core::NodeRef::from_tag_label(&node_id)
        .ok_or_else(|| ServerFnError::new("Invalid node ID"))?;

    // Get properties + basic info
    let (kind, label, props) = match &node_ref {
        memvault_core::NodeRef::Entity(id) => {
            if let Ok(Some(entity)) = client.get_entity(id).await {
                let label = entity
                    .props
                    .get("name")
                    .or_else(|| entity.props.get("title"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&entity.kind)
                    .to_string();
                (entity.kind, label, entity.props)
            } else {
                ("entity".to_string(), "Unknown".to_string(), BTreeMap::new())
            }
        }
        memvault_core::NodeRef::Doc(id) => {
            let label = if let Ok(Some(doc)) = client.get_doc(id).await {
                doc.frontmatter
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Untitled")
                    .to_string()
            } else {
                "Document".to_string()
            };
            ("document".to_string(), label, BTreeMap::new())
        }
        memvault_core::NodeRef::Attachment(_) => {
            ("file".to_string(), "File".to_string(), BTreeMap::new())
        }
    };

    // Get edges
    let mut edges = Vec::new();
    if let Ok(edge_list) = client.edges_of(&node_ref).await {
        for (source, edge) in edge_list {
            let (direction, other_node) = if source == node_ref {
                ("outgoing".to_string(), edge.target.tag_label())
            } else {
                ("incoming".to_string(), source.tag_label())
            };
            edges.push(EdgeDetail {
                edge_id: hex::encode(edge.id.0),
                relation: edge.relation,
                direction,
                other_node,
                other_label: None,
            });
        }
    }

    let node_type = match &node_ref {
        memvault_core::NodeRef::Entity(_) => "entity",
        memvault_core::NodeRef::Doc(_) => "doc",
        memvault_core::NodeRef::Attachment(_) => "file",
    };

    Ok(NodeDetail {
        id: node_id,
        node_type: node_type.to_string(),
        kind,
        label,
        props,
        edges,
    })
}

#[server]
async fn expand_node(id: String) -> Result<Vec<NodeSummary>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let node_ref = memvault_core::NodeRef::from_tag_label(&id)
        .ok_or_else(|| ServerFnError::new("Invalid node ID"))?;

    let mut neighbors = Vec::new();
    if let Ok(edge_list) = client.edges_of(&node_ref).await {
        for (source, edge) in edge_list {
            let other = if source == node_ref { &edge.target } else { &source };
            let other_id = other.tag_label();
            // Try to get entity details for entity nodes
            if let memvault_core::NodeRef::Entity(eid) = other {
                if let Ok(Some(entity)) = client.get_entity(eid).await {
                    let label = entity
                        .props
                        .get("name")
                        .or_else(|| entity.props.get("title"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&entity.kind)
                        .to_string();
                    neighbors.push(NodeSummary {
                        id: other_id.clone(),
                        node_type: "entity".to_string(),
                        kind: entity.kind,
                        label,
                        edges: entity
                            .edges_out
                            .iter()
                            .map(|e| EdgeSummary {
                                edge_id: hex::encode(e.id.0),
                                relation: e.relation.clone(),
                                target_id: e.target.tag_label(),
                                weight: e.weight.unwrap_or(1.0),
                            })
                            .collect(),
                        props: entity.props,
                    });
                    continue;
                }
            }
            // Non-entity or unfetchable: add stub
            let (node_type, kind, label) = match other {
                memvault_core::NodeRef::Doc(_) => ("doc", "document", "Document"),
                memvault_core::NodeRef::Attachment(_) => ("file", "file", "File"),
                memvault_core::NodeRef::Entity(_) => ("entity", "entity", "Entity"),
            };
            neighbors.push(NodeSummary {
                id: other_id,
                node_type: node_type.to_string(),
                kind: kind.to_string(),
                label: label.to_string(),
                edges: vec![],
                props: BTreeMap::new(),
            });
        }
    }
    Ok(neighbors)
}

// ── Color & shape helpers ─────────────────────────────────────────────

/// Deterministic HSL color from a string hash. Picks a hue on the color wheel,
/// keeps saturation/lightness in a pleasant range.
fn hash_color(s: &str) -> String {
    let mut h: u32 = 0;
    for b in s.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    let hue = h % 360;
    format!("hsl({hue}, 55%, 55%)")
}

fn node_color(node_type: &str, kind: &str) -> String {
    match node_type {
        "doc" => "rgb(var(--c-warn))".to_string(),
        "file" | "attachment" => "rgb(var(--c-success))".to_string(),
        _ => match kind {
            "person" => "rgb(var(--c-info))".to_string(),
            "project" => "rgb(var(--c-brand))".to_string(),
            "concept" => "rgb(var(--c-success))".to_string(),
            _ => hash_color(kind),
        },
    }
}


// ── Viewport state ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct Viewport {
    offset_x: f64,
    offset_y: f64,
    zoom: f64,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            offset_x: 0.0,
            offset_y: 0.0,
            zoom: 1.0,
        }
    }
}

impl Viewport {
    /// Auto-fit the viewport to contain all given nodes with some padding.
    fn fit_to_nodes(nodes: &[GraphNode]) -> Self {
        if nodes.is_empty() {
            return Self::default();
        }
        let min_x = nodes.iter().map(|n| n.x - n.radius).fold(f64::INFINITY, f64::min);
        let max_x = nodes.iter().map(|n| n.x + n.radius).fold(f64::NEG_INFINITY, f64::max);
        let min_y = nodes.iter().map(|n| n.y - n.radius).fold(f64::INFINITY, f64::min);
        let max_y = nodes.iter().map(|n| n.y + n.radius).fold(f64::NEG_INFINITY, f64::max);

        let cx = (min_x + max_x) / 2.0;
        let cy = (min_y + max_y) / 2.0;
        let w = (max_x - min_x).max(100.0);
        let h = (max_y - min_y).max(100.0);
        // Use the larger axis to determine zoom, with padding
        let span = w.max(h) + 100.0; // 50px padding on each side
        let zoom = 800.0 / span; // 800 is the SVG base size

        Self {
            offset_x: cx,
            offset_y: cy,
            zoom: zoom.clamp(0.2, 5.0),
        }
    }
}

// ── Components ─────────────────────────────────────────────────────────

#[component]
pub fn GraphExplorer() -> Element {
    use_topbar(&t!("graph-title"));
    let active_view = use_context::<crate::ui::topbar::ActiveViewSignal>();
    let nodes_res = use_server_future(move || {
        let v = active_view.read().name.clone();
        async move { list_graph_nodes(v).await }
    })?;

    match &*nodes_res.read() {
        Some(Ok(nodes)) => rsx! { GraphView { initial_nodes: nodes.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", {t!("graph-loading")} } },
    }
}

#[component]
fn GraphView(initial_nodes: Vec<NodeSummary>) -> Element {
    // Build the simulation graph structure without running physics.
    // Physics only runs client-side in use_effect below.
    let mut sim = use_signal(|| {
        let mut s = ForceSimulation::new();
        for node in &initial_nodes {
            s.add_node(node.id.clone(), node.kind.clone(), node.label.clone());
        }
        for node in &initial_nodes {
            let source = s.nodes.iter().position(|n| n.id == node.id).unwrap_or(0);
            for edge in &node.edges {
                if let Some(target) = s.nodes.iter().position(|n| n.id == edge.target_id) {
                    s.add_edge(source, target, edge.relation.clone(), edge.weight);
                }
            }
        }
        // Don't run physics here — use_signal runs on both server (SSR)
        // and client (hydration). Physics runs only client-side below.
        s
    });

    let mut selected = use_signal(|| None::<String>);
    let mut viewport = use_signal(Viewport::default);
    let mut sim_ran = use_signal(|| false);
    let mut dragging_node = use_signal(|| None::<usize>);
    let mut did_drag = use_signal(|| false);
    let mut panning = use_signal(|| false);
    let mut pan_start = use_signal(|| (0.0f64, 0.0f64));
    let mut sidebar_search = use_signal(String::new);
    let mut kind_filter = use_signal(|| None::<String>);
    let mut focus_node = use_signal(|| None::<String>);
    let mut detail = use_signal(|| None::<NodeDetail>);

    // Run simulation client-side only (use_effect doesn't fire during SSR).
    use_effect(move || {
        if *sim_ran.read() {
            return;
        }
        sim_ran.set(true);
        let mut s = sim.write();
        for _ in 0..300 {
            if s.is_settled() { break; }
            s.tick();
        }
        viewport.set(Viewport::fit_to_nodes(&s.nodes));
    });

    let s = sim.read();
    let all_nodes: Vec<GraphNode> = s.nodes.clone();
    let all_edges: Vec<GraphEdge> = s.edges.clone();
    drop(s);

    // If focus mode is active, filter to just the focused node and its neighbors.
    let (nodes, edges) = if let Some(ref focus_id) = *focus_node.read() {
        let focus_idx = all_nodes.iter().position(|n| &n.id == focus_id);
        if let Some(fi) = focus_idx {
            let mut visible_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
            visible_indices.insert(fi);
            let relevant_edges: Vec<&GraphEdge> = all_edges
                .iter()
                .filter(|e| e.source == fi || e.target == fi)
                .collect();
            for e in &relevant_edges {
                visible_indices.insert(e.source);
                visible_indices.insert(e.target);
            }
            // Re-index nodes and edges for the filtered view
            let idx_map: std::collections::HashMap<usize, usize> = visible_indices
                .iter()
                .enumerate()
                .map(|(new, &old)| (old, new))
                .collect();
            let filtered_nodes: Vec<GraphNode> = visible_indices
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .into_iter()
                .map(|i| all_nodes[i].clone())
                .collect();
            let filtered_edges: Vec<GraphEdge> = relevant_edges
                .into_iter()
                .filter_map(|e| {
                    Some(GraphEdge {
                        source: *idx_map.get(&e.source)?,
                        target: *idx_map.get(&e.target)?,
                        relation: e.relation.clone(),
                        weight: e.weight,
                    })
                })
                .collect();
            (filtered_nodes, filtered_edges)
        } else {
            (all_nodes.clone(), all_edges.clone())
        }
    } else {
        (all_nodes.clone(), all_edges.clone())
    };

    // Collect unique node kinds for the filter.
    let mut kinds: Vec<String> = initial_nodes.iter().map(|e| {
        if e.node_type != "entity" { e.node_type.clone() } else { e.kind.clone() }
    }).collect();
    kinds.sort();
    kinds.dedup();

    // Filter sidebar list.
    let sidebar_q = sidebar_search.read().to_lowercase();
    let active_kind = kind_filter.read().clone();
    let filtered_list: Vec<&NodeSummary> = initial_nodes
        .iter()
        .filter(|e| {
            let display_kind = if e.node_type != "entity" { &e.node_type } else { &e.kind };
            let kind_match = active_kind.as_ref().map_or(true, |k| display_kind == k);
            let search_match = sidebar_q.is_empty()
                || e.label.to_lowercase().contains(&sidebar_q)
                || e.kind.to_lowercase().contains(&sidebar_q);
            kind_match && search_match
        })
        .collect();

    // Compute viewBox with viewport transform.
    let vp = *viewport.read();
    let base_half = 400.0 / vp.zoom;
    let vb = format!(
        "{} {} {} {}",
        vp.offset_x - base_half,
        vp.offset_y - base_half,
        base_half * 2.0,
        base_half * 2.0,
    );

    // ── Event handlers ─────────────────────────────────────────────

    let on_wheel = move |e: Event<WheelData>| {
        let delta = e.delta().strip_units().y;
        let mut vp = viewport.write();
        let factor = if delta > 0.0 { 0.9 } else { 1.1 };
        vp.zoom = (vp.zoom * factor).clamp(0.1, 10.0);
    };

    let on_svg_mousedown = move |e: Event<MouseData>| {
        panning.set(true);
        let coords = e.client_coordinates();
        pan_start.set((coords.x, coords.y));
    };

    let on_svg_mousemove = {
        move |e: Event<MouseData>| {
            let coords = e.client_coordinates();

            // Node dragging takes priority.
            if let Some(idx) = *dragging_node.read() {
                let ps = *pan_start.read();
                let screen_dx = coords.x - ps.0;
                let screen_dy = coords.y - ps.1;
                // Only start moving the node after a small threshold to
                // distinguish clicks from drags.
                if screen_dx.abs() > 3.0 || screen_dy.abs() > 3.0 || *did_drag.read() {
                    did_drag.set(true);
                    let mut s = sim.write();
                    let vp = *viewport.read();
                    let scale = (base_half * 2.0) / 800.0;
                    if let Some(node) = s.nodes.get_mut(idx) {
                        let dx = screen_dx * scale / vp.zoom;
                        let dy = screen_dy * scale / vp.zoom;
                        node.fx = Some(node.x + dx);
                        node.fy = Some(node.y + dy);
                        node.x = node.fx.unwrap();
                        node.y = node.fy.unwrap();
                    }
                    pan_start.set((coords.x, coords.y));
                }
                return;
            }

            // Panning.
            if *panning.read() {
                let ps = *pan_start.read();
                let vp_val = *viewport.read();
                let scale = (base_half * 2.0) / 800.0;
                let dx = (coords.x - ps.0) * scale / vp_val.zoom;
                let dy = (coords.y - ps.1) * scale / vp_val.zoom;
                viewport.write().offset_x -= dx;
                viewport.write().offset_y -= dy;
                pan_start.set((coords.x, coords.y));
            }
        }
    };

    let on_svg_mouseup = move |_: Event<MouseData>| {
        if let Some(idx) = *dragging_node.read() {
            // Only reheat the simulation if the mouse actually moved (real drag).
            if *did_drag.read() {
                let mut s = sim.write();
                if let Some(node) = s.nodes.get_mut(idx) {
                    node.fx = None;
                    node.fy = None;
                }
                s.reheat();
                for _ in 0..100 {
                    if s.is_settled() {
                        break;
                    }
                    s.tick();
                }
            }
        }
        dragging_node.set(None);
        did_drag.set(false);
        panning.set(false);
    };

    let is_focus_active = focus_node.read().is_some();

    rsx! {
        div { class: "space-y-4",
            PageHeader { {t!("graph-title")} }

            if nodes.is_empty() && !is_focus_active {
                Card {
                    div { class: "p-8 text-center text-fg-muted",
                        {t!("graph-empty")}
                    }
                }
            } else {
                // Toolbar
                div { class: "flex items-center gap-2 text-sm flex-wrap",
                    span { class: "text-fg-muted", {t!("graph-node-count", nodes: nodes.len(), edges: edges.len())} }
                    span { class: "text-fg-faint", "|" }
                    span { class: "text-fg-muted", {t!("graph-zoom", level: format!("{:.1}", vp.zoom))} }
                    button {
                        class: "btn btn-xs btn-secondary",
                        onclick: move |_| {
                            let s = sim.read();
                            viewport.set(Viewport::fit_to_nodes(&s.nodes));
                        },
                        {t!("graph-fit-view")}
                    }
                    if is_focus_active {
                        button {
                            class: "btn btn-xs btn-secondary",
                            onclick: move |_| focus_node.set(None),
                            {t!("graph-show-all")}
                        }
                    }
                }

                div { class: "flex gap-4",
                    // ── Left sidebar ────────────────────────────────
                    div { class: "w-64 shrink-0 space-y-2",
                        input {
                            class: "input input-sm w-full",
                            r#type: "search",
                            placeholder: t!("graph-filter-nodes"),
                            value: "{sidebar_search}",
                            oninput: move |e: Event<FormData>| sidebar_search.set(e.value()),
                        }
                        // Kind filter pills
                        div { class: "flex flex-wrap gap-1",
                            for kind in &kinds {
                                {
                                    let k = kind.clone();
                                    let is_active = active_kind.as_ref() == Some(kind);
                                    rsx! {
                                        button {
                                            class: if is_active { "pill pill-accent" } else { "pill pill-muted" },
                                            onclick: move |_| {
                                                if is_active {
                                                    kind_filter.set(None);
                                                } else {
                                                    kind_filter.set(Some(k.clone()));
                                                }
                                            },
                                            "{kind}"
                                        }
                                    }
                                }
                            }
                        }
                        // Node list
                        div { class: "space-y-1 overflow-y-auto max-h-[500px]",
                            for node in &filtered_list {
                                div {
                                    class: "card p-3 cursor-pointer hover:border-brand transition-colors",
                                    class: if selected.read().as_ref() == Some(&node.id) { "border-brand" } else { "" },
                                    onclick: {
                                        let id = node.id.clone();
                                        move |_| {
                                            selected.set(Some(id.clone()));
                                            // Lazy-load detail
                                            let nid = id.clone();
                                            spawn(async move {
                                                if let Ok(d) = get_node_detail(nid).await {
                                                    detail.set(Some(d));
                                                }
                                            });
                                        }
                                    },
                                    div { class: "flex items-center gap-2",
                                        {
                                            let color = node_color(&node.node_type, &node.kind);
                                            let display_kind = if node.node_type != "entity" { node.node_type.clone() } else { node.kind.clone() };
                                            rsx! {
                                                Pill { color: color, "{display_kind}" }
                                            }
                                        }
                                        span { class: "text-sm font-medium truncate", "{node.label}" }
                                    }
                                    if !node.edges.is_empty() {
                                        span { class: "text-xs text-fg-muted", {t!("graph-edges-count", count: node.edges.len())} }
                                    }
                                }
                            }
                        }
                    }

                    // ── Main canvas ─────────────────────────────────
                    Card { class: "flex-1",
                        svg {
                            class: "w-full select-none",
                            style: "min-height: 500px; cursor: grab",
                            view_box: "{vb}",
                            onwheel: on_wheel,
                            onmousedown: on_svg_mousedown,
                            onmousemove: on_svg_mousemove,
                            onmouseup: on_svg_mouseup,
                            onmouseleave: move |_| {
                                dragging_node.set(None);
                                panning.set(false);
                            },

                            // Arrow marker definition
                            defs {
                                marker {
                                    id: "arrowhead",
                                    marker_width: "10",
                                    marker_height: "7",
                                    ref_x: "10",
                                    ref_y: "3.5",
                                    orient: "auto",
                                    marker_units: "strokeWidth",
                                    path {
                                        d: "M0,0 L10,3.5 L0,7",
                                        fill: "rgb(var(--c-line))",
                                        opacity: "0.6",
                                    }
                                }
                            }

                            // Edges with arrowheads
                            for edge in &edges {
                                {
                                    let sn = &nodes[edge.source];
                                    let tn = &nodes[edge.target];
                                    // Shorten line so arrow tip meets the node border, not center.
                                    let dx = tn.x - sn.x;
                                    let dy = tn.y - sn.y;
                                    let dist = (dx * dx + dy * dy).sqrt().max(1.0);
                                    let shorten = tn.radius + 4.0; // stop before node edge
                                    let end_x = tn.x - dx / dist * shorten;
                                    let end_y = tn.y - dy / dist * shorten;
                                    let mid_x = (sn.x + tn.x) / 2.0;
                                    let mid_y = (sn.y + tn.y) / 2.0;
                                    let thickness = 1.0 + edge.weight as f64;
                                    rsx! {
                                        line {
                                            x1: "{sn.x}", y1: "{sn.y}",
                                            x2: "{end_x}", y2: "{end_y}",
                                            stroke: "rgb(var(--c-line))",
                                            stroke_width: "{thickness}",
                                            stroke_opacity: "0.6",
                                            marker_end: "url(#arrowhead)",
                                        }
                                        text {
                                            x: "{mid_x}", y: "{mid_y}",
                                            text_anchor: "middle",
                                            font_size: "9",
                                            fill: "rgb(var(--c-fg-muted))",
                                            "{edge.relation}"
                                        }
                                    }
                                }
                            }

                            // Nodes — different shapes per type
                            for (idx, node) in nodes.iter().enumerate() {
                                {
                                    // Determine node_type from the id prefix
                                    let nt = if node.id.starts_with("doc:") { "doc" }
                                        else if node.id.starts_with("file:") || node.id.starts_with("attachment:") { "file" }
                                        else { "entity" };
                                    let color = node_color(nt, &node.kind);
                                    let is_selected = selected.read().as_ref() == Some(&node.id);
                                    let stroke = if is_selected { "rgb(var(--c-brand))" } else { "transparent" };
                                    let id = node.id.clone();
                                    let expand_id = node.id.clone();
                                    let _focus_id = node.id.clone();
                                    rsx! {
                                        g {
                                            style: "cursor: pointer",
                                            onclick: {
                                                let click_id = id.clone();
                                                move |_| {
                                                    selected.set(Some(click_id.clone()));
                                                    let nid = click_id.clone();
                                                    spawn(async move {
                                                        if let Ok(d) = get_node_detail(nid).await {
                                                            detail.set(Some(d));
                                                        }
                                                    });
                                                }
                                            },
                                            onmousedown: move |e: Event<MouseData>| {
                                                e.stop_propagation();
                                                dragging_node.set(Some(idx));
                                                let coords = e.client_coordinates();
                                                pan_start.set((coords.x, coords.y));
                                            },
                                            ondoubleclick: {
                                                let eid = expand_id.clone();
                                                move |_| {
                                                    let eid = eid.clone();
                                                    spawn(async move {
                                                        if let Ok(neighbors) = expand_node(eid).await {
                                                            let mut s = sim.write();
                                                            for neighbor in &neighbors {
                                                                s.add_node(neighbor.id.clone(), neighbor.kind.clone(), neighbor.label.clone());
                                                            }
                                                            for neighbor in &neighbors {
                                                                let src = s.nodes.iter().position(|n| n.id == neighbor.id).unwrap_or(0);
                                                                for edge in &neighbor.edges {
                                                                    if let Some(tgt) = s.nodes.iter().position(|n| n.id == edge.target_id) {
                                                                        s.add_edge(src, tgt, edge.relation.clone(), edge.weight);
                                                                    }
                                                                }
                                                            }
                                                            s.reheat();
                                                            for _ in 0..200 {
                                                                if s.is_settled() { break; }
                                                                s.tick();
                                                            }
                                                        }
                                                    });
                                                }
                                            },

                                            // Shape: circle for entity, rounded rect for doc, diamond for file
                                            match nt {
                                                "doc" => rsx! {
                                                    rect {
                                                        x: "{node.x - node.radius}",
                                                        y: "{node.y - node.radius * 0.7}",
                                                        width: "{node.radius * 2.0}",
                                                        height: "{node.radius * 1.4}",
                                                        rx: "4", ry: "4",
                                                        fill: "{color}",
                                                        stroke: "{stroke}",
                                                        stroke_width: "3",
                                                        opacity: "0.85",
                                                    }
                                                },
                                                "file" | "attachment" => {
                                                    // Diamond shape via polygon
                                                    let r = node.radius;
                                                    let pts = format!(
                                                        "{},{} {},{} {},{} {},{}",
                                                        node.x, node.y - r,
                                                        node.x + r, node.y,
                                                        node.x, node.y + r,
                                                        node.x - r, node.y,
                                                    );
                                                    rsx! {
                                                        polygon {
                                                            points: "{pts}",
                                                            fill: "{color}",
                                                            stroke: "{stroke}",
                                                            stroke_width: "3",
                                                            opacity: "0.85",
                                                        }
                                                    }
                                                },
                                                _ => rsx! {
                                                    circle {
                                                        cx: "{node.x}", cy: "{node.y}", r: "{node.radius}",
                                                        fill: "{color}",
                                                        stroke: "{stroke}",
                                                        stroke_width: "3",
                                                        opacity: "0.85",
                                                    }
                                                },
                                            }

                                            text {
                                                x: "{node.x}",
                                                y: "{node.y + node.radius + 14.0}",
                                                text_anchor: "middle",
                                                font_size: "11",
                                                fill: "rgb(var(--c-fg-strong))",
                                                pointer_events: "none",
                                                "{node.label}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ── Right detail panel ──────────────────────────
                    if let Some(d) = &*detail.read() {
                        div { class: "w-72 shrink-0 space-y-3",
                            Card {
                                div { class: "p-4 space-y-3",
                                    div { class: "flex items-center gap-2",
                                        {
                                            let color = node_color(&d.node_type, &d.kind);
                                            let display_kind = if d.node_type != "entity" { d.node_type.clone() } else { d.kind.clone() };
                                            rsx! {
                                                Pill { color: color, "{display_kind}" }
                                            }
                                        }
                                    }
                                    h3 { class: "h-card font-semibold", "{d.label}" }
                                    CidDisplay { cid: d.id.clone() }

                                    // Focus button
                                    button {
                                        class: "btn btn-xs btn-secondary w-full",
                                        onclick: {
                                            let fid = d.id.clone();
                                            move |_| focus_node.set(Some(fid.clone()))
                                        },
                                        {t!("graph-focus-node")}
                                    }

                                    // Properties
                                    if !d.props.is_empty() {
                                        div { class: "pt-2 border-t border-line",
                                            h4 { class: "text-xs font-semibold text-fg-muted uppercase mb-2", {t!("graph-section-properties")} }
                                            for (key, val) in &d.props {
                                                div { class: "flex justify-between text-sm py-0.5",
                                                    span { class: "text-fg-muted truncate mr-2", "{key}" }
                                                    span { class: "font-mono text-fg-strong truncate text-right", "{val}" }
                                                }
                                            }
                                        }
                                    }

                                    // Edges
                                    if !d.edges.is_empty() {
                                        div { class: "pt-2 border-t border-line",
                                            h4 { class: "text-xs font-semibold text-fg-muted uppercase mb-2",
                                                {t!("graph-section-edges", count: d.edges.len())}
                                            }
                                            for edge in &d.edges {
                                                div { class: "flex items-center gap-1 text-sm py-1 flex-wrap",
                                                    span { class: "text-xs text-fg-faint",
                                                        if edge.direction == "outgoing" { "\u{2192}" } else { "\u{2190}" }
                                                    }
                                                    span { class: "text-fg-muted", "{edge.relation}" }
                                                    span { class: "text-xs font-mono text-fg-faint truncate",
                                                        "{edge.other_node}"
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Navigation link
                                    if d.node_type == "entity" {
                                        if let Some(hex_id) = d.id.strip_prefix("entity:") {
                                            Link { to: Route::EntityDetail { id: hex_id.to_string() },
                                                class: "btn btn-sm btn-secondary w-full mt-2",
                                                {t!("graph-view-details")}
                                            }
                                        }
                                    }
                                    if d.node_type == "doc" {
                                        if let Some(hex_id) = d.id.strip_prefix("doc:") {
                                            Link { to: Route::NoteDetail { id: hex_id.to_string() },
                                                class: "btn btn-sm btn-secondary w-full mt-2",
                                                {t!("graph-view-document")}
                                            }
                                        }
                                    }
                                    if d.node_type == "file" || d.node_type == "attachment" {
                                        if let Some(hex_cid) = d.id.strip_prefix("file:").or_else(|| d.id.strip_prefix("attachment:")) {
                                            Link { to: Route::FileDetail { cid: hex_cid.to_string() },
                                                class: "btn btn-sm btn-secondary w-full mt-2",
                                                {t!("graph-view-file")}
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
}
