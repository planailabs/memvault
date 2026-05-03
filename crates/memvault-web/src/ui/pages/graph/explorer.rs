//! Graph explorer page — interactive force-directed knowledge graph.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader, Pill, PillVariant};
use serde::{Deserialize, Serialize};

use super::layout_engine::{ForceSimulation, GraphEdge, GraphNode};
use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::topbar::use_topbar;

// ── Server functions ───────────────────────────────────────────────────

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
        let _id_hex = hex::encode(&record.cid);
        // Try to get each entity (some may have been retracted).
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

// ── Color mapping ──────────────────────────────────────────────────────

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

// ── Component ──────────────────────────────────────────────────────────

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
        // Build initial graph from all entities.
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

    // Run the simulation: tick until settled on initial load.
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
    let selected_entity = selected
        .read()
        .as_ref()
        .and_then(|id| entities.iter().find(|e| e.id == *id))
        .cloned();
    drop(s);

    // Compute viewBox to fit all nodes with padding.
    let (min_x, min_y, max_x, max_y) = if nodes.is_empty() {
        (-200.0, -200.0, 200.0, 200.0)
    } else {
        let pad = 80.0;
        let min_x = nodes.iter().map(|n| n.x).fold(f64::MAX, f64::min) - pad;
        let min_y = nodes.iter().map(|n| n.y).fold(f64::MAX, f64::min) - pad;
        let max_x = nodes.iter().map(|n| n.x).fold(f64::MIN, f64::max) + pad;
        let max_y = nodes.iter().map(|n| n.y).fold(f64::MIN, f64::max) + pad;
        (min_x, min_y, max_x, max_y)
    };
    let vb = format!("{min_x} {min_y} {} {}", max_x - min_x, max_y - min_y);

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
                div { class: "flex gap-4",
                    // Sidebar: entity list
                    div { class: "w-64 shrink-0 space-y-1 overflow-y-auto max-h-[600px]",
                        for entity in &entities {
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

                    // Main canvas
                    Card { class: "flex-1",
                        svg {
                            class: "w-full",
                            style: "min-height: 500px",
                            view_box: "{vb}",
                            // Edges
                            for edge in &edges {
                                {
                                    let s = &nodes[edge.source];
                                    let t = &nodes[edge.target];
                                    let mid_x = (s.x + t.x) / 2.0;
                                    let mid_y = (s.y + t.y) / 2.0;
                                    rsx! {
                                        line {
                                            x1: "{s.x}", y1: "{s.y}",
                                            x2: "{t.x}", y2: "{t.y}",
                                            stroke: "rgb(var(--c-line))",
                                            stroke_width: "1.5",
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
                            for node in &nodes {
                                {
                                    let color = kind_color(&node.kind);
                                    let is_selected = selected.read().as_ref() == Some(&node.id);
                                    let stroke = if is_selected { "rgb(var(--c-brand))" } else { "transparent" };
                                    let id = node.id.clone();
                                    rsx! {
                                        g {
                                            onclick: move |_| selected.set(Some(id.clone())),
                                            style: "cursor: pointer",
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
                                                "{node.label}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Detail panel (when selected)
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
                                                    span { class: "text-fg-faint", "→" }
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
