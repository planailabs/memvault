//! Graph explorer page — interactive force-directed knowledge graph.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader, Pill, PillVariant};
use serde::{Deserialize, Serialize};

use super::layout_engine::{ForceSimulation, GraphEdge, GraphNode};
use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::topbar::use_topbar;

// ── Data types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EntitySummary {
    id: String,
    kind: String,
    label: String,
    edges: Vec<EdgeSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EdgeSummary {
    relation: String,
    target_id: String,
    weight: f32,
}

// ── Server functions ───────────────────────────────────────────────────

#[server]
async fn list_entities() -> Result<Vec<EntitySummary>, ServerFnError> {
    use memvault_query::{AuditQuery, OpKind};

    let client = crate::ui::state::client()?;
    let records = client
        .audit(AuditQuery {
            op_kind: Some(OpKind::EntityCreate),
            limit: Some(200),
            ..Default::default()
        })
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut entities = Vec::new();
    for record in records {
        let entity_id = {
            if record.cid.len() != 32 {
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&record.cid);
            memvault_core::EntityId(arr)
        };
        if let Ok(Some(entity)) = client.get_entity(&entity_id).await {
            let label = entity
                .props
                .get("name")
                .or_else(|| entity.props.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or(&entity.kind)
                .to_string();
            entities.push(EntitySummary {
                id: hex::encode(entity.id.0),
                kind: entity.kind,
                label,
                edges: entity
                    .edges_out
                    .iter()
                    .map(|e| EdgeSummary {
                        relation: e.relation.clone(),
                        target_id: hex::encode(e.target.0),
                        weight: e.weight.unwrap_or(1.0),
                    })
                    .collect(),
            });
        }
    }
    Ok(entities)
}

#[server]
async fn expand_entity(id: String) -> Result<Vec<EntitySummary>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let bytes = hex::decode(&id).map_err(|_| ServerFnError::new("Invalid entity ID"))?;
    if bytes.len() != 32 {
        return Err(ServerFnError::new("Entity ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let entity_id = memvault_core::EntityId(arr);

    let hits = client
        .traverse(&entity_id, None, 1)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut neighbors = Vec::new();
    for hit in hits {
        if let Ok(Some(entity)) = client.get_entity(&hit.entity_id).await {
            let label = entity
                .props
                .get("name")
                .or_else(|| entity.props.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or(&entity.kind)
                .to_string();
            neighbors.push(EntitySummary {
                id: hex::encode(entity.id.0),
                kind: entity.kind,
                label,
                edges: entity
                    .edges_out
                    .iter()
                    .map(|e| EdgeSummary {
                        relation: e.relation.clone(),
                        target_id: hex::encode(e.target.0),
                        weight: e.weight.unwrap_or(1.0),
                    })
                    .collect(),
            });
        }
    }
    Ok(neighbors)
}

// ── Color helpers ──────────────────────────────────────────────────────

fn kind_color(kind: &str) -> &'static str {
    match kind {
        "person" => "rgb(var(--c-info))",
        "project" => "rgb(var(--c-brand))",
        "concept" => "rgb(var(--c-success))",
        "document" => "rgb(var(--c-warn))",
        _ => "rgb(var(--c-fg-muted))",
    }
}

fn kind_pill_variant(kind: &str) -> PillVariant {
    match kind {
        "person" => PillVariant::Info,
        "project" => PillVariant::Accent,
        "concept" => PillVariant::Ok,
        "document" => PillVariant::Warn,
        _ => PillVariant::Muted,
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

// ── Components ─────────────────────────────────────────────────────────

#[component]
pub fn GraphExplorer() -> Element {
    use_topbar("Graph");
    let entities_res = use_server_future(list_entities)?;

    match &*entities_res.read() {
        Some(Ok(entities)) => rsx! { GraphView { entities: entities.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", "Loading graph..." } },
    }
}

#[component]
fn GraphView(entities: Vec<EntitySummary>) -> Element {
    let mut sim = use_signal(|| {
        let mut s = ForceSimulation::new();
        for entity in &entities {
            s.add_node(entity.id.clone(), entity.kind.clone(), entity.label.clone());
        }
        for entity in &entities {
            let source = s.nodes.iter().position(|n| n.id == entity.id).unwrap_or(0);
            for edge in &entity.edges {
                if let Some(target) = s.nodes.iter().position(|n| n.id == edge.target_id) {
                    s.add_edge(source, target, edge.relation.clone(), edge.weight);
                }
            }
        }
        s
    });

    let mut selected = use_signal(|| None::<String>);
    let mut viewport = use_signal(Viewport::default);
    let mut dragging_node = use_signal(|| None::<usize>);
    let mut panning = use_signal(|| false);
    let mut pan_start = use_signal(|| (0.0f64, 0.0f64));
    let mut sidebar_search = use_signal(String::new);
    let mut kind_filter = use_signal(|| None::<String>);

    // Run the simulation to settle on initial load.
    use_effect(move || {
        let mut s = sim.write();
        for _ in 0..300 {
            if s.is_settled() {
                break;
            }
            s.tick();
        }
    });

    let s = sim.read();
    let nodes: Vec<GraphNode> = s.nodes.clone();
    let edges: Vec<GraphEdge> = s.edges.clone();
    drop(s);

    let selected_entity = selected
        .read()
        .as_ref()
        .and_then(|id| entities.iter().find(|e| e.id == *id))
        .cloned();

    // Collect unique entity kinds for the filter.
    let mut kinds: Vec<String> = entities.iter().map(|e| e.kind.clone()).collect();
    kinds.sort();
    kinds.dedup();

    // Filter sidebar entities.
    let sidebar_q = sidebar_search.read().to_lowercase();
    let active_kind = kind_filter.read().clone();
    let filtered_entities: Vec<&EntitySummary> = entities
        .iter()
        .filter(|e| {
            let kind_match = active_kind.as_ref().map_or(true, |k| &e.kind == k);
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
                // Approximate: convert screen delta to graph coords.
                let mut s = sim.write();
                let vp = *viewport.read();
                let scale = (base_half * 2.0) / 800.0; // rough SVG-to-screen
                if let Some(node) = s.nodes.get_mut(idx) {
                    let ps = *pan_start.read();
                    let dx = (coords.x - ps.0) * scale / vp.zoom;
                    let dy = (coords.y - ps.1) * scale / vp.zoom;
                    node.fx = Some(node.x + dx);
                    node.fy = Some(node.y + dy);
                    node.x = node.fx.unwrap();
                    node.y = node.fy.unwrap();
                }
                pan_start.set((coords.x, coords.y));
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
            let mut s = sim.write();
            if let Some(node) = s.nodes.get_mut(idx) {
                node.fx = None;
                node.fy = None;
            }
            s.reheat();
            // Re-settle after drag.
            for _ in 0..100 {
                if s.is_settled() {
                    break;
                }
                s.tick();
            }
        }
        dragging_node.set(None);
        panning.set(false);
    };

    rsx! {
        div { class: "space-y-4",
            PageHeader { "Knowledge Graph" }

            if nodes.is_empty() {
                Card {
                    div { class: "p-8 text-center text-fg-muted",
                        "No entities found. Create entities via the MCP tools to populate the graph."
                    }
                }
            } else {
                // Toolbar
                div { class: "flex items-center gap-2 text-sm",
                    span { class: "text-fg-muted", "{nodes.len()} nodes, {edges.len()} edges" }
                    span { class: "text-fg-faint", "|" }
                    span { class: "text-fg-muted", "Zoom: {vp.zoom:.1}x" }
                    button {
                        class: "btn btn-xs btn-secondary",
                        onclick: move |_| viewport.set(Viewport::default()),
                        "Reset View"
                    }
                }

                div { class: "flex gap-4",
                    // ── Left sidebar ────────────────────────────────
                    div { class: "w-64 shrink-0 space-y-2",
                        input {
                            class: "input input-sm w-full",
                            r#type: "search",
                            placeholder: "Filter entities...",
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
                        // Entity list
                        div { class: "space-y-1 overflow-y-auto max-h-[500px]",
                            for entity in &filtered_entities {
                                div {
                                    class: "card p-3 cursor-pointer hover:border-brand transition-colors",
                                    class: if selected.read().as_ref() == Some(&entity.id) { "border-brand" } else { "" },
                                    onclick: {
                                        let id = entity.id.clone();
                                        move |_| selected.set(Some(id.clone()))
                                    },
                                    div { class: "flex items-center gap-2",
                                        Pill { variant: kind_pill_variant(&entity.kind), "{entity.kind}" }
                                        span { class: "text-sm font-medium truncate", "{entity.label}" }
                                    }
                                    span { class: "text-xs text-fg-muted", "{entity.edges.len()} edges" }
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

                            // Edges
                            for edge in &edges {
                                {
                                    let sn = &nodes[edge.source];
                                    let tn = &nodes[edge.target];
                                    let mid_x = (sn.x + tn.x) / 2.0;
                                    let mid_y = (sn.y + tn.y) / 2.0;
                                    let thickness = 1.0 + edge.weight as f64;
                                    rsx! {
                                        line {
                                            x1: "{sn.x}", y1: "{sn.y}",
                                            x2: "{tn.x}", y2: "{tn.y}",
                                            stroke: "rgb(var(--c-line))",
                                            stroke_width: "{thickness}",
                                            stroke_opacity: "0.6",
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

                            // Nodes
                            for (idx, node) in nodes.iter().enumerate() {
                                {
                                    let color = kind_color(&node.kind);
                                    let is_selected = selected.read().as_ref() == Some(&node.id);
                                    let stroke = if is_selected { "rgb(var(--c-brand))" } else { "transparent" };
                                    let id = node.id.clone();
                                    let expand_id = node.id.clone();
                                    rsx! {
                                        g {
                                            style: "cursor: pointer",
                                            onclick: move |_| selected.set(Some(id.clone())),
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
                                                        if let Ok(neighbors) = expand_entity(eid).await {
                                                            let mut s = sim.write();
                                                            for neighbor in &neighbors {
                                                                s.add_node(neighbor.id.clone(), neighbor.kind.clone(), neighbor.label.clone());
                                                            }
                                                            for neighbor in &neighbors {
                                                                let source = s.nodes.iter().position(|n| n.id == neighbor.id).unwrap_or(0);
                                                                for edge in &neighbor.edges {
                                                                    if let Some(target) = s.nodes.iter().position(|n| n.id == edge.target_id) {
                                                                        s.add_edge(source, target, edge.relation.clone(), edge.weight);
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
                                            circle {
                                                cx: "{node.x}", cy: "{node.y}", r: "{node.radius}",
                                                fill: "{color}",
                                                stroke: "{stroke}",
                                                stroke_width: "3",
                                                opacity: "0.85",
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
                    if let Some(entity) = &selected_entity {
                        div { class: "w-72 shrink-0",
                            Card {
                                div { class: "p-4 space-y-3",
                                    div { class: "flex items-center gap-2",
                                        Pill { variant: kind_pill_variant(&entity.kind), "{entity.kind}" }
                                    }
                                    h3 { class: "h-card font-semibold", "{entity.label}" }
                                    CidDisplay { cid: entity.id.clone() }

                                    if !entity.edges.is_empty() {
                                        div { class: "pt-2 border-t border-line",
                                            h4 { class: "text-xs font-semibold text-fg-muted uppercase mb-2", "Edges" }
                                            for edge in &entity.edges {
                                                div { class: "flex items-center gap-2 text-sm py-1",
                                                    span { class: "text-fg-muted", "{edge.relation}" }
                                                    span { class: "text-fg-faint", "\u{2192}" }
                                                    CidDisplay { cid: edge.target_id.clone(), len: Some(8) }
                                                }
                                            }
                                        }
                                    }

                                    Link { to: Route::EntityDetail { id: entity.id.clone() },
                                        class: "btn btn-sm btn-secondary w-full mt-2",
                                        "View Details"
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
