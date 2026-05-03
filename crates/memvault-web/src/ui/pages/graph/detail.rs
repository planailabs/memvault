//! Entity detail page.

use dioxus::prelude::*;
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
async fn get_entity_detail(id: String) -> Result<EntityData, ServerFnError> {
    let client = crate::ui::state::client()?;
    let bytes = hex::decode(&id).map_err(|_| ServerFnError::new("Invalid entity ID"))?;
    if bytes.len() != 32 {
        return Err(ServerFnError::new("Entity ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let entity_id = memvault_core::EntityId(arr);

    let entity = client
        .get_entity(&entity_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("Entity not found"))?;

    let mut edges = Vec::new();
    for e in &entity.edges_out {
        // Try to get the target entity's label.
        let target_label = if let Ok(Some(target)) = client.get_entity(&e.target).await {
            target
                .props
                .get("name")
                .or_else(|| target.props.get("title"))
                .and_then(|v| v.as_str())
                .map(String::from)
        } else {
            None
        };
        edges.push(EdgeData {
            id: hex::encode(e.id.0),
            relation: e.relation.clone(),
            target: hex::encode(e.target.0),
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
pub fn EntityDetail(id: String) -> Element {
    use_topbar("Entity");
    let entity = use_server_future(move || {
        let id = id.clone();
        async move { get_entity_detail(id).await }
    })?;

    match &*entity.read() {
        Some(Ok(data)) => rsx! { EntityView { data: data.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", "Loading..." } },
    }
}

#[component]
fn EntityView(data: EntityData) -> Element {
    let label = data
        .props
        .get("name")
        .or_else(|| data.props.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed")
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
                        "History"
                    }
                    Link { to: Route::GraphExplorer {}, class: "btn btn-sm btn-secondary",
                        "View in Graph"
                    }
                }
            }

            // Properties
            Card {
                div { class: "p-5",
                    h3 { class: "h-section mb-2", "Properties" }
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
                                    td { class: "td text-fg-muted", colspan: "2", "No properties" }
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
                        h3 { class: "h-section mb-2", "Outgoing Edges ({data.edges.len()})" }
                        table { class: "table",
                            thead { class: "thead",
                                tr {
                                    th { class: "th", "Relation" }
                                    th { class: "th", "Target" }
                                    th { class: "th", "Weight" }
                                }
                            }
                            tbody { class: "tbody",
                                for edge in &data.edges {
                                    tr {
                                        Td {
                                            Pill { variant: PillVariant::Muted, "{edge.relation}" }
                                        }
                                        Td {
                                            Link { to: Route::EntityDetail { id: edge.target.clone() }, class: "link",
                                                if let Some(label) = &edge.target_label {
                                                    "{label}"
                                                } else {
                                                    CidDisplay { cid: edge.target.clone(), len: Some(12) }
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
