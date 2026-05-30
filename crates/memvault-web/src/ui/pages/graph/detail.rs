//! Entity detail page.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Card, Kicker, PageHeader, Pill, PillVariant, Td, TdMuted};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EntityData {
    id: String,
    kind: String,
    props: BTreeMap<String, serde_json::Value>,
    edges: Vec<EdgeData>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EdgeData {
    id: String,
    relation: String,
    target: String,
    target_label: Option<String>,
    weight: Option<f32>,
}

#[server]
async fn get_entity_detail(id: String, show_retracted: bool) -> Result<EntityData, ServerFnError> {
    let client = crate::ui::state::client()?;
    let hex_id = id.strip_prefix("entity:").unwrap_or(&id);
    let bytes = hex::decode(hex_id).map_err(|_| ServerFnError::new("Invalid entity ID"))?;
    if bytes.len() != 32 {
        return Err(ServerFnError::new("Entity ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let entity_id = memvault_core::EntityId(arr);

    let entity = client
        .get_entity_ex(&entity_id, show_retracted)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Entity not found"))?;

    // Get all edges (outgoing + incoming) via edges_of, not just edges_out.
    let node_ref = memvault_core::NodeRef::Entity(entity_id);
    let all_edges = client
        .edges_of(&node_ref)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut edges = Vec::new();
    for (source, e) in &all_edges {
        let (_direction, other_node) = if source == &node_ref {
            ("outgoing", e.target.tag_label())
        } else {
            ("incoming", source.tag_label())
        };
        let target_label = client.resolve_label(&other_node).await.unwrap_or(None);
        edges.push(EdgeData {
            id: hex::encode(e.id.0),
            relation: e.relation.clone(),
            target: other_node,
            target_label,
            weight: e.weight,
        });
    }

    Ok(EntityData {
        id: hex::encode(entity.id.0),
        kind: entity.kind,
        props: entity.props,
        edges,
    })
}

#[component]
pub fn EntityDetail(id: ReadSignal<String>) -> Element {
    use_topbar(&t!("entity-title"));
    let show_retracted = use_context::<crate::ui::topbar::ShowRetractedSignal>();
    let entity = use_server_future(move || {
        let id = id.read().clone();
        let r = *show_retracted.read();
        async move { get_entity_detail(id, r).await }
    })?;

    match &*entity.read() {
        Some(Ok(data)) => rsx! { EntityView { data: data.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
    }
}

#[component]
fn EntityView(data: EntityData) -> Element {
    let unnamed = t!("unnamed");
    let label = data
        .props
        .get("name")
        .or_else(|| data.props.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or(&unnamed)
        .to_string();

    rsx! {
        div { class: "space-y-4",
            div { class: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3",
                div {
                    Kicker { "{data.kind}" }
                    PageHeader { class: "mb-0", "{label}" }
                }
                div { class: "flex gap-2",
                    Link { to: Route::EntityHistory { id: data.id.clone() }, class: "btn btn-sm btn-secondary",
                        {t!("history")}
                    }
                    Link { to: Route::GraphExplorer {}, class: "btn btn-sm btn-secondary",
                        {t!("entity-view-in-graph")}
                    }
                }
            }

            // Properties
            Card {
                div { class: "p-5",
                    h3 { class: "h-section mb-2", {t!("graph-section-properties")} }
                    table { class: "table",
                        tbody { class: "tbody",
                            for (key, val) in &data.props {
                                tr {
                                    td { class: "td font-medium text-sm", "{key}" }
                                    td { class: "td text-sm font-mono text-fg-muted", "{val}" }
                                }
                            }
                            if data.props.is_empty() {
                                tr {
                                    td { class: "td text-fg-muted", colspan: "2", {t!("entity-no-properties")} }
                                }
                            }
                        }
                    }
                }
            }

            // Edges
            if !data.edges.is_empty() {
                Card {
                    div { class: "p-5",
                        h3 { class: "h-section mb-2", {t!("entity-section-edges", count: data.edges.len())} }
                        table { class: "table",
                            thead { class: "thead",
                                tr {
                                    th { class: "th", {t!("entity-th-relation")} }
                                    th { class: "th", {t!("entity-th-target")} }
                                    th { class: "th", {t!("entity-th-weight")} }
                                }
                            }
                            tbody { class: "tbody",
                                for edge in &data.edges {
                                    tr {
                                        Td {
                                            Pill { variant: PillVariant::Muted, "{edge.relation}" }
                                        }
                                        Td {
                                            {
                                                let route = if let Some(hex) = edge.target.strip_prefix("entity:") {
                                                    Route::EntityDetail { id: hex.to_string() }
                                                } else if let Some(hex) = edge.target.strip_prefix("doc:") {
                                                    Route::NoteDetail { id: hex.to_string() }
                                                } else if let Some(hex) = edge.target.strip_prefix("file:").or_else(|| edge.target.strip_prefix("attachment:")) {
                                                    Route::FileDetail { cid: hex.to_string() }
                                                } else {
                                                    Route::EntityDetail { id: edge.target.clone() }
                                                };
                                                rsx! {
                                                    Link { to: route, class: "link",
                                                        if let Some(label) = &edge.target_label {
                                                            "{label}"
                                                        } else {
                                                            CidDisplay { cid: edge.target.clone(), len: Some(12) }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        TdMuted {
                                            if let Some(w) = edge.weight {
                                                "{w:.2}"
                                            } else {
                                                "—"
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
