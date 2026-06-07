//! The right-hand detail panel: `DetailPanel` and its `NeighborEdgeRow`.
//!
//! Pure move out of `explorer.rs` — behavior is identical. The panel reads
//! the currently-selected node's lazily-loaded `NodeDetail` and renders its
//! properties, incoming/outgoing edges, and navigation links. Clicking a
//! neighbor row re-loads the panel for that neighbor (the graph stays put).

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Card, Dot, Pill, PillVariant};

use super::explorer::{
    display_kind_for, get_node_detail, kind_variant, EdgeDetail, NodeDetail,
};
use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;

#[component]
pub(crate) fn DetailPanel(
    detail: Signal<Option<NodeDetail>>,
    selected: Signal<Option<String>>,
    focus_node: Signal<Option<String>>,
) -> Element {
    let show_retracted = use_context::<crate::ui::topbar::ShowRetractedSignal>();

    let mut selected = selected;
    let mut detail = detail;
    let mut focus_node = focus_node;

    rsx! {
        if let Some(d) = &*detail.read() {
            {
                let display_kind = display_kind_for(&d.node_type, &d.kind).to_string();
                let variant = kind_variant(&display_kind);
                let incoming: Vec<&EdgeDetail> = d.edges.iter().filter(|e| e.direction == "incoming").collect();
                let outgoing: Vec<&EdgeDetail> = d.edges.iter().filter(|e| e.direction == "outgoing").collect();
                rsx! {
            div { class: "w-72 shrink-0 space-y-3",
                Card {
                    div { class: "p-4 space-y-3",
                        div { class: "flex items-center gap-2",
                            Pill { variant,
                                Dot { variant }
                                "{display_kind}"
                            }
                            Pill { variant: PillVariant::Muted, mono: true,
                                "{d.edges.len()} edges"
                            }
                        }
                        h3 { class: "h-card font-semibold break-words leading-snug", "{d.label}" }
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
                            div { class: "pt-3 border-t border-line",
                                div { class: "kicker mb-2", {t!("graph-section-properties")} }
                                for (key, val) in &d.props {
                                    {
                                        let full = val.as_str().map(String::from).unwrap_or_else(|| val.to_string());
                                        rsx! {
                                            div { class: "py-1",
                                                div { class: "text-xs text-fg-muted", "{key}" }
                                                div {
                                                    class: "font-mono text-sm text-fg-strong break-words whitespace-pre-wrap max-h-24 overflow-y-auto",
                                                    title: "{full}",
                                                    "{full}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Incoming edges
                        if !incoming.is_empty() {
                            div { class: "pt-3 border-t border-line",
                                div { class: "kicker mb-2",
                                    {t!("graph-section-incoming", count: incoming.len())}
                                }
                                for edge in &incoming {
                                    NeighborEdgeRow {
                                        key: "in-{edge.edge_id}",
                                        edge: (*edge).clone(),
                                        on_open: {
                                            let nid = edge.other_node.clone();
                                            move |_| {
                                                selected.set(Some(nid.clone()));
                                                let nid = nid.clone();
                                                spawn(async move {
                                                    if let Ok(d) = get_node_detail(nid, show_retracted().0).await {
                                                        detail.set(Some(d));
                                                    }
                                                });
                                            }
                                        },
                                    }
                                }
                            }
                        }

                        // Outgoing edges
                        if !outgoing.is_empty() {
                            div { class: "pt-3 border-t border-line",
                                div { class: "kicker mb-2",
                                    {t!("graph-section-outgoing", count: outgoing.len())}
                                }
                                for edge in &outgoing {
                                    NeighborEdgeRow {
                                        key: "out-{edge.edge_id}",
                                        edge: (*edge).clone(),
                                        on_open: {
                                            let nid = edge.other_node.clone();
                                            move |_| {
                                                selected.set(Some(nid.clone()));
                                                let nid = nid.clone();
                                                spawn(async move {
                                                    if let Ok(d) = get_node_detail(nid, show_retracted().0).await {
                                                        detail.set(Some(d));
                                                    }
                                                });
                                            }
                                        },
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

/// A single row in the right-panel's Incoming / Outgoing lists.
///
/// Shows `[relation pill]  [• human label]` and, on hover, floats a
/// small card to the left with the neighbor's kind, full label, and
/// truncated id. Clicking anywhere on the row asks the parent to
/// re-load the right panel with that neighbor — the graph stays in
/// place, but the inspector follows the edge.
#[component]
fn NeighborEdgeRow(edge: EdgeDetail, on_open: EventHandler<()>) -> Element {
    let display_kind = display_kind_for(&edge.other_node_type, &edge.other_kind).to_string();
    let variant = kind_variant(&display_kind);
    rsx! {
        div {
            class: "group relative",
            div {
                class: "flex items-center justify-between gap-2 py-1 px-1 -mx-1 rounded cursor-pointer hover:bg-surface-2 transition-colors",
                onclick: move |_| on_open.call(()),
                span { class: "font-mono text-xs text-fg-muted bg-surface-2 px-1.5 py-0.5 rounded border border-line shrink-0",
                    "{edge.relation}"
                }
                span { class: "flex items-center gap-1.5 min-w-0",
                    Dot { variant }
                    span { class: "text-xs text-fg truncate text-right", title: "{edge.other_label}",
                        "{edge.other_label}"
                    }
                }
            }
            // Hover card — anchored to the row's right edge, opens to
            // the left into the canvas area (the right panel is hugged
            // to the viewport edge, so a popover on that side would
            // clip). CSS-only: visibility flips on `group-hover`.
            div {
                class: "absolute right-full top-0 mr-2 w-56 z-20 \
                        opacity-0 invisible group-hover:opacity-100 group-hover:visible \
                        transition-opacity duration-100 pointer-events-none",
                div {
                    class: "rounded-md border border-line bg-surface shadow-lg p-3 space-y-2",
                    div { class: "flex items-center gap-2",
                        Pill { variant,
                            Dot { variant }
                            "{display_kind}"
                        }
                    }
                    div { class: "text-sm font-medium text-fg-strong break-words",
                        "{edge.other_label}"
                    }
                    div { class: "kicker", "id" }
                    div { class: "font-mono text-xs text-fg-muted break-all",
                        "{edge.other_node}"
                    }
                }
            }
        }
    }
}
