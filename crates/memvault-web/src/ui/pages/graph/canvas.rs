//! Renderer-agnostic graph helpers (the renderer "seam") and the SVG
//! renderer component (`GraphCanvas`).
//!
//! The pure decision functions (`fade_scale`, `should_show_label`,
//! `short_ref`, `display_label`) are shared by the SVG renderer today and
//! any future Canvas2D renderer. No Dioxus, no DOM — just math and
//! strings, so they are unit-testable on the host target.
//!
//! `GraphCanvas` owns the actual `svg { … }` block and all of its
//! pan/zoom/drag event handlers. It is the swappable renderer behind the
//! seam: everything above the prop boundary (data, settings, selection
//! signals) is renderer-agnostic.

use dioxus::prelude::*;

use super::controls::GraphSettings;
use super::explorer::{
    display_kind_for, expand_node, get_node_detail, kind_halo_color, kind_svg_palette, NodeDetail,
    Viewport,
};
use super::layout_engine::{ForceSimulation, GraphEdge, GraphNode};

/// Map the 0..1 "text fade threshold" slider to a world-space cutoff for
/// `zoom * radius`. 0.0 => every label shows; 1.0 => only large hubs,
/// and only when zoomed in.
pub fn fade_scale(threshold: f64) -> f64 {
    // Cutoff for `zoom * radius`. The 24.0 constant is tuned so that at the
    // default fade (0.5 -> cutoff 12) and a typical fit-view zoom (~0.4),
    // only well-connected nodes (radius >= 30, i.e. many edges) label, while
    // at 1× most connected nodes (radius >= 12) label. Re-tune in Task 7's
    // manual check against the real vault if too few / too many labels show.
    threshold.clamp(0.0, 1.0) * 24.0
}

/// Whether a node's label should render. `forced` is true when the node
/// is selected / hovered / focused / neighbor-highlighted.
pub fn should_show_label(zoom: f64, radius: f64, threshold: f64, forced: bool) -> bool {
    forced || zoom * radius >= fade_scale(threshold)
}

/// First 6 hex chars after the `<type>:` prefix of a node ref.
pub fn short_ref(node_ref: &str) -> String {
    node_ref
        .split(':')
        .nth(1)
        .map(|h| h.chars().take(6).collect())
        .unwrap_or_default()
}

/// Resolve a human label: name -> title -> "<kind> · <short-id>".
/// Never returns a raw `entity:<hex>` ref.
pub fn display_label(name: Option<&str>, title: Option<&str>, kind: &str, node_ref: &str) -> String {
    name.filter(|s| !s.trim().is_empty())
        .or_else(|| title.filter(|s| !s.trim().is_empty()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{kind} · {}", short_ref(node_ref)))
}

// ── SVG renderer component ─────────────────────────────────────────────

/// The SVG graph renderer. Owns the `svg { … }` element, its pan/zoom/drag
/// event handlers, and the per-node/edge drawing loops. Pure move out of
/// `explorer.rs` — behavior is identical.
///
/// Derived locals are recomputed here from the props rather than passed in:
/// `zoom` from `viewport.zoom`, `base_half` from `zoom`, and `highlight`
/// from `hovered` + `edges`.
#[component]
#[allow(clippy::too_many_arguments)]
pub(crate) fn GraphCanvas(
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
    settings: GraphSettings,
    view_box: String,
    selected: Signal<Option<String>>,
    hovered: Signal<Option<usize>>,
    dragging_node: Signal<Option<usize>>,
    detail: Signal<Option<NodeDetail>>,
    sim: Signal<ForceSimulation>,
    viewport: Signal<Viewport>,
    panning: Signal<bool>,
    pan_start: Signal<(f64, f64)>,
    did_drag: Signal<bool>,
) -> Element {
    let show_retracted = use_context::<crate::ui::topbar::ShowRetractedSignal>();

    let cfg = settings;
    let vb = view_box;
    let zoom = viewport.read().zoom;
    let base_half = 400.0 / zoom;

    // Mutable copies of the Copy signals for the event-handler closures.
    let mut selected = selected;
    let mut hovered = hovered;
    let mut dragging_node = dragging_node;
    let mut detail = detail;
    let mut sim = sim;
    let mut viewport = viewport;
    let mut panning = panning;
    let mut pan_start = pan_start;
    let mut did_drag = did_drag;

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

    let hover_idx = *hovered.read();
    let highlight: Option<std::collections::HashSet<usize>> = hover_idx.map(|h| {
        let mut set = std::collections::HashSet::new();
        set.insert(h);
        for e in &edges {
            if e.source == h {
                set.insert(e.target);
            }
            if e.target == h {
                set.insert(e.source);
            }
        }
        set
    });

    rsx! {
        svg {
            class: "w-full select-none",
            style: "min-height: 560px; cursor: grab",
            view_box: "{vb}",
            onwheel: on_wheel,
            onmousedown: on_svg_mousedown,
            onmousemove: on_svg_mousemove,
            onmouseup: on_svg_mouseup,
            onmouseleave: move |_| {
                dragging_node.set(None);
                panning.set(false);
            },

            // Arrow markers — neutral (`arrowhead`) for the
            // resting field, brand (`arrowhead-active`) for
            // edges incident to the current selection.
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
                        fill: "rgb(var(--c-line-soft))",
                        opacity: "0.7",
                    }
                }
                marker {
                    id: "arrowhead-active",
                    marker_width: "10",
                    marker_height: "7",
                    ref_x: "10",
                    ref_y: "3.5",
                    orient: "auto",
                    marker_units: "strokeWidth",
                    path {
                        d: "M0,0 L10,3.5 L0,7",
                        fill: "rgb(var(--c-brand))",
                    }
                }
            }

            // ── Kind halos (drawn first, behind edges) ──
            // Every node gets a kind-tinted halo at 10%
            // opacity. Together they read as a quiet
            // constellation; the selection halo (next
            // block) lifts the active node out.
            for (idx, node) in nodes.iter().enumerate() {
                {
                    let nt = if node.id.starts_with("doc:") { "doc" }
                        else if node.id.starts_with("file:") || node.id.starts_with("attachment:") { "file" }
                        else { "entity" };
                    let dk = display_kind_for(nt, &node.kind);
                    let halo = kind_halo_color(dk);
                    let r = node.radius * cfg.node_scale + 14.0;
                    let halo_opacity = if highlight.as_ref().map_or(false, |h| !h.contains(&idx)) { 0.02 } else { 0.10 };
                    rsx! {
                        circle {
                            cx: "{node.x}", cy: "{node.y}", r: "{r}",
                            fill: "{halo}",
                            opacity: "{halo_opacity}",
                            pointer_events: "none",
                        }
                    }
                }
            }

            // Selected halo — brighter brand glow, sits
            // over the kind halos so the active node
            // visibly emanates.
            for node in nodes.iter() {
                if selected.read().as_ref() == Some(&node.id) {
                    {
                        let r = node.radius * cfg.node_scale + 28.0;
                        rsx! {
                            circle {
                                cx: "{node.x}", cy: "{node.y}", r: "{r}",
                                fill: "rgb(var(--c-brand))",
                                opacity: "0.18",
                                pointer_events: "none",
                            }
                        }
                    }
                }
            }

            // Edges — incident-to-selection edges render in
            // brand, all others in the soft hairline line
            // color. Labels sit on a small surface chip so
            // they read against busy node fields.
            for edge in &edges {
                {
                    let sn = &nodes[edge.source];
                    let tn = &nodes[edge.target];
                    let dx = tn.x - sn.x;
                    let dy = tn.y - sn.y;
                    let dist = (dx * dx + dy * dy).sqrt().max(1.0);
                    let shorten = tn.radius * cfg.node_scale + 4.0;
                    let end_x = tn.x - dx / dist * shorten;
                    let end_y = tn.y - dy / dist * shorten;
                    let mid_x = (sn.x + tn.x) / 2.0;
                    let mid_y = (sn.y + tn.y) / 2.0;
                    let is_active = selected.read().as_ref().map_or(false, |sid| {
                        &nodes[edge.source].id == sid || &nodes[edge.target].id == sid
                    });
                    let edge_dimmed = highlight
                        .as_ref()
                        .map_or(false, |h| !(h.contains(&edge.source) && h.contains(&edge.target)));
                    let stroke = if is_active { "rgb(var(--c-brand))" } else { "rgb(var(--c-line-soft))" };
                    let stroke_opacity: &str = if edge_dimmed {
                        "0.06"
                    } else if is_active {
                        "0.85"
                    } else {
                        "0.55"
                    };
                    let chip_opacity: &str = if edge_dimmed { "0.06" } else { "1.0" };
                    let thickness = (if is_active { 1.5 } else { 1.0 + (edge.weight as f64 - 1.0).max(0.0) * 0.5 })
                        * cfg.link_thickness;
                    let marker = if !cfg.show_arrows {
                        "none".to_string()
                    } else if is_active {
                        "url(#arrowhead-active)".to_string()
                    } else {
                        "url(#arrowhead)".to_string()
                    };
                    let chip_w = (edge.relation.len() as f64) * 6.2 + 10.0;
                    rsx! {
                        line {
                            x1: "{sn.x}", y1: "{sn.y}",
                            x2: "{end_x}", y2: "{end_y}",
                            stroke: "{stroke}",
                            stroke_width: "{thickness}",
                            stroke_opacity: "{stroke_opacity}",
                            marker_end: "{marker}",
                        }
                        rect {
                            x: "{mid_x - chip_w / 2.0}",
                            y: "{mid_y - 8.0}",
                            width: "{chip_w}",
                            height: "14",
                            rx: "3", ry: "3",
                            fill: "rgb(var(--c-surface))",
                            stroke: "rgb(var(--c-line))",
                            stroke_width: "0.5",
                            opacity: "{chip_opacity}",
                            pointer_events: "none",
                        }
                        text {
                            x: "{mid_x}", y: "{mid_y + 2.5}",
                            text_anchor: "middle",
                            font_family: "var(--font-mono)",
                            font_size: "11",
                            fill: "rgb(var(--c-fg-muted))",
                            opacity: "{chip_opacity}",
                            pointer_events: "none",
                            "{edge.relation}"
                        }
                    }
                }
            }

            // Nodes — circle for entity, rounded rect for
            // doc, diamond for file. Fill/stroke come from
            // the kind palette; selection gets a slightly
            // heavier stroke (no opacity dip — translucent
            // node fills muddy the canvas in dark mode).
            for (idx, node) in nodes.iter().enumerate() {
                {
                    let nt = if node.id.starts_with("doc:") { "doc" }
                        else if node.id.starts_with("file:") || node.id.starts_with("attachment:") { "file" }
                        else { "entity" };
                    let dk = display_kind_for(nt, &node.kind);
                    let (fill, stroke_color) = kind_svg_palette(dk);
                    let is_selected = selected.read().as_ref() == Some(&node.id);
                    let dimmed = !is_selected && highlight.as_ref().map_or(false, |h| !h.contains(&idx));
                    let node_opacity = if dimmed { 0.15 } else { 1.0 };
                    let stroke_width = if is_selected { 2.5 } else { 1.5 };
                    let id = node.id.clone();
                    let expand_id = node.id.clone();
                    let r = node.radius * cfg.node_scale;
                    let forced = is_selected || highlight.as_ref().map_or(false, |h| h.contains(&idx));
                    let label_text = {
                        let max = 32usize;
                        if node.label.chars().count() > max {
                            let head: String = node.label.chars().take(max).collect();
                            format!("{head}…")
                        } else {
                            node.label.clone()
                        }
                    };
                    rsx! {
                        g {
                            style: "cursor: pointer",
                            opacity: "{node_opacity}",
                            onclick: {
                                let click_id = id.clone();
                                move |_| {
                                    selected.set(Some(click_id.clone()));
                                    let nid = click_id.clone();
                                    spawn(async move {
                                        if let Ok(d) = get_node_detail(nid, show_retracted().0).await {
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
                            onmouseenter: move |_| hovered.set(Some(idx)),
                            onmouseleave: move |_| hovered.set(None),
                            ondoubleclick: {
                                let eid = expand_id.clone();
                                move |_| {
                                    let eid = eid.clone();
                                    spawn(async move {
                                        if let Ok(neighbors) = expand_node(eid, show_retracted().0).await {
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

                            match nt {
                                "doc" => rsx! {
                                    rect {
                                        x: "{node.x - r}",
                                        y: "{node.y - r * 0.7}",
                                        width: "{r * 2.0}",
                                        height: "{r * 1.4}",
                                        rx: "4", ry: "4",
                                        fill: "{fill}",
                                        stroke: "{stroke_color}",
                                        stroke_width: "{stroke_width}",
                                    }
                                },
                                "file" | "attachment" => {
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
                                            fill: "{fill}",
                                            stroke: "{stroke_color}",
                                            stroke_width: "{stroke_width}",
                                        }
                                    }
                                },
                                _ => rsx! {
                                    circle {
                                        cx: "{node.x}", cy: "{node.y}", r: "{r}",
                                        fill: "{fill}",
                                        stroke: "{stroke_color}",
                                        stroke_width: "{stroke_width}",
                                    }
                                },
                            }

                            if should_show_label(zoom, r, cfg.label_fade, forced) {
                                text {
                                    x: "{node.x}",
                                    y: "{node.y + r + 18.0}",
                                    text_anchor: "middle",
                                    font_family: "var(--font-sans)",
                                    font_size: "13.5",
                                    font_weight: if is_selected { "600" } else { "500" },
                                    fill: if is_selected { "rgb(var(--c-brand))" } else { "rgb(var(--c-fg-strong))" },
                                    pointer_events: "none",
                                    "{label_text}"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fade_zero_always_shows() {
        assert_eq!(fade_scale(0.0), 0.0);
        assert!(should_show_label(0.1, 5.0, 0.0, false));
    }

    #[test]
    fn zoom_reveals_labels() {
        // Behavior, not magic numbers: a given node is hidden when zoomed
        // far out and shown when zoomed in (at the mid threshold).
        let r = 22.0; // a typical connected-node radius
        assert!(!should_show_label(0.1, r, 0.5, false));
        assert!(should_show_label(5.0, r, 0.5, false));
    }

    #[test]
    fn higher_threshold_hides_more() {
        // At fixed zoom+radius, raising the threshold can only remove labels.
        assert!(should_show_label(1.0, 22.0, 0.0, false)); // threshold 0 -> always
        assert!(!should_show_label(1.0, 22.0, 1.0, false)); // threshold 1 -> mid node hidden at 1×
    }

    #[test]
    fn forced_overrides_fade() {
        assert!(should_show_label(0.01, 1.0, 1.0, true));
    }

    #[test]
    fn short_ref_takes_six_hex() {
        assert_eq!(short_ref("entity:08a5c9986bd078"), "08a5c9");
        assert_eq!(short_ref("doc:deadbeefcafe"), "deadbe");
        assert_eq!(short_ref("nocolon"), "");
    }

    #[test]
    fn display_label_prefers_name_then_title() {
        assert_eq!(display_label(Some("Atlas"), Some("T"), "person", "entity:abc123"), "Atlas");
        assert_eq!(display_label(None, Some("The Title"), "paper", "entity:abc123"), "The Title");
        assert_eq!(display_label(Some("  "), None, "paper", "entity:abc123"), "paper · abc123");
    }

    #[test]
    fn display_label_falls_back_to_kind_and_short_id() {
        assert_eq!(display_label(None, None, "paper", "entity:08a5c9986bd0"), "paper · 08a5c9");
        assert_eq!(display_label(None, None, "entity", "entity:08a5c9986bd0"), "entity · 08a5c9");
    }
}
