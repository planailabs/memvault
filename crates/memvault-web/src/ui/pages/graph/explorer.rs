//! Graph explorer page — interactive force-directed knowledge graph.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Card, Dot, PageHeader, Pill, PillVariant};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::canvas::GraphCanvas;
// `display_label` is only referenced from the `#[server]` fns below, whose
// bodies are compiled out on the wasm/client target — gate the import so the
// client build stays warning-free.
#[cfg(feature = "server")]
use super::canvas::display_label;
use super::controls::{load_settings, save_settings, GraphSettings, SettingsPanel};
use super::layout_engine::{ForceSimulation, GraphEdge, GraphNode};
use super::panel::DetailPanel;
use crate::ui::topbar::use_topbar;

// ── Data types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NodeSummary {
    /// Unique ID in tag_label format: "entity:<hex>", "doc:<hex>", "file:<hex>"
    pub(crate) id: String,
    /// "entity", "doc", "file"
    pub(crate) node_type: String,
    /// Entity kind (e.g. "person") or "document"/"file" for docs/files
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) edges: Vec<EdgeSummary>,
    pub(crate) props: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct EdgeSummary {
    pub(crate) edge_id: String,
    pub(crate) relation: String,
    pub(crate) target_id: String,
    pub(crate) weight: f32,
}

/// Lazy-loaded detail for the sidebar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NodeDetail {
    pub(crate) id: String,
    pub(crate) node_type: String,
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) props: BTreeMap<String, serde_json::Value>,
    pub(crate) edges: Vec<EdgeDetail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct EdgeDetail {
    pub(crate) edge_id: String,
    pub(crate) relation: String,
    pub(crate) direction: String,
    /// Tag-label of the other end (`entity:<hex>`, `doc:<hex>`, `file:<hex>`).
    pub(crate) other_node: String,
    /// Human-readable name of the other end. Resolved server-side so the
    /// sidebar can show "Atlas" instead of "entity:4aa14e2…".
    pub(crate) other_label: String,
    /// Kind of the other end ("person", "library", "document", …). Used
    /// to pick a palette variant for the dot/pill in the row.
    pub(crate) other_kind: String,
    /// Node type discriminator ("entity" / "doc" / "file"), used so the
    /// hover popover can route to the right detail page.
    pub(crate) other_node_type: String,
}

// ── Server functions ───────────────────────────────────────────────────

#[server]
async fn list_graph_nodes(
    view: Option<String>,
    bucket_hex: Option<String>,
    show_retracted: bool,
) -> Result<Vec<NodeSummary>, ServerFnError> {
    let client = crate::ui::state::client()?;

    let bucket_id = bucket_hex.as_deref().and_then(|h| {
        let bytes = hex::decode(h).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(memvault_core::BucketId(arr))
    });

    // If a view is active, get all nodes matching the view.
    if let Some(ref view_name) = view {
        let items = client
            .list_scoped(
                &memvault_core::QueryScope::all()
                    .with_view(Some(view_name.to_string()))
                    .with_include_retracted(show_retracted),
                200,
            )
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let mut nodes = Vec::new();
        for item in &items {
            let id = &item.node_id;
            let node_type = &item.node_type;
            let label = &item.label;
            // Skip reserved/managed entities (vfs:dir, skill) from graph view.
            if node_type == "entity" {
                if let Some(memvault_core::NodeRef::Entity(eid)) =
                    memvault_core::NodeRef::from_tag_label(id)
                {
                    if let Ok(Some(e)) = client.get_entity_scoped(&eid, &memvault_core::QueryScope::all().with_include_retracted(show_retracted)).await {
                        if memvault_core::is_reserved_entity_kind(&e.kind) {
                            continue;
                        }
                    }
                }
            }
            let mut edges = Vec::new();
            if let Some(node_ref) = memvault_core::NodeRef::from_tag_label(id) {
                if let Ok(edge_list) = client.edges_of(&node_ref).await {
                    for (src, edge) in &edge_list {
                        if src != &node_ref || edge.relation == memvault_core::VFS_CHILD_REL {
                            continue;
                        }
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
                id: id.clone(),
                node_type: node_type.clone(),
                kind: node_type.clone(),
                label: label.clone(),
                edges,
                props: std::collections::BTreeMap::new(),
            });
        }
        return Ok(nodes);
    }

    // Load entities
    let entities = client
        .list_entities_ex(200, bucket_id.as_ref(), show_retracted)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let mut nodes: Vec<NodeSummary> = entities
        .into_iter()
        .filter(|entity| !memvault_core::is_reserved_entity_kind(&entity.kind))
        .map(|entity| {
            let id = format!("entity:{}", hex::encode(entity.id.0));
            let label = display_label(
                entity.props.get("name").and_then(|v| v.as_str()),
                entity.props.get("title").and_then(|v| v.as_str()),
                &entity.kind,
                &id,
            );
            NodeSummary {
                id,
                node_type: "entity".to_string(),
                kind: entity.kind,
                label,
                edges: entity
                    .edges_out
                    .iter()
                    .filter(|e| e.relation != memvault_core::VFS_CHILD_REL)
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
            if !edge.target_id.starts_with("entity:")
                && !nodes.iter().any(|n| n.id == edge.target_id)
            {
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
                let title = client
                    .get_doc_scoped(did, &memvault_core::QueryScope::all().with_include_retracted(show_retracted))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|d| {
                        d.frontmatter
                            .get("title")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "Untitled".to_string());
                ("doc".to_string(), "doc".to_string(), title)
            }
            memvault_core::NodeRef::Attachment(cid) => {
                let name = client
                    .get_file_manifest(cid)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .and_then(|v| {
                        v.get("filename")
                            .and_then(|f| f.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "Unnamed file".to_string());
                ("file".to_string(), "file".to_string(), name)
            }
            memvault_core::NodeRef::Entity(eid) => {
                // Skip vfs:dir entities that appear as edge targets.
                if let Ok(Some(e)) = client.get_entity_scoped(eid, &memvault_core::QueryScope::all().with_include_retracted(show_retracted)).await {
                    if e.kind == memvault_core::VFS_DIR_KIND {
                        continue;
                    }
                    let label = e
                        .props
                        .get("name")
                        .or_else(|| e.props.get("title"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&e.kind)
                        .to_string();
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
pub(crate) async fn get_node_detail(
    node_id: String,
    show_retracted: bool,
) -> Result<NodeDetail, ServerFnError> {
    let client = crate::ui::state::client()?;

    let node_ref = memvault_core::NodeRef::from_tag_label(&node_id)
        .ok_or_else(|| ServerFnError::new("Invalid node ID"))?;

    // Get properties + basic info
    let (kind, label, props) = match &node_ref {
        memvault_core::NodeRef::Entity(id) => {
            if let Ok(Some(entity)) = client.get_entity_scoped(id, &memvault_core::QueryScope::all().with_include_retracted(show_retracted)).await {
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
            let label = if let Ok(Some(doc)) = client.get_doc_scoped(id, &memvault_core::QueryScope::all().with_include_retracted(show_retracted)).await {
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

    // Get edges, resolving each "other end" so the sidebar can render
    // a human label + kind dot instead of a raw `entity:<hex>` string.
    let mut edges = Vec::new();
    if let Ok(edge_list) = client.edges_of(&node_ref).await {
        for (source, edge) in edge_list {
            let (direction, other_ref) = if source == node_ref {
                ("outgoing".to_string(), edge.target.clone())
            } else {
                ("incoming".to_string(), source.clone())
            };
            let other_node = other_ref.tag_label();
            let scope =
                memvault_core::QueryScope::all().with_include_retracted(show_retracted);
            let (other_node_type, other_kind, other_label) = match &other_ref {
                memvault_core::NodeRef::Entity(eid) => {
                    if let Ok(Some(e)) = client.get_entity_scoped(eid, &scope).await {
                        let label = display_label(
                            e.props.get("name").and_then(|v| v.as_str()),
                            e.props.get("title").and_then(|v| v.as_str()),
                            &e.kind,
                            &other_node,
                        );
                        ("entity".to_string(), e.kind.clone(), label)
                    } else {
                        // Couldn't fetch the target — still avoid a raw hash.
                        let label = display_label(None, None, "entity", &other_node);
                        ("entity".to_string(), "entity".to_string(), label)
                    }
                }
                memvault_core::NodeRef::Doc(did) => {
                    let title = client
                        .get_doc_scoped(did, &scope)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|d| d.frontmatter.get("title").and_then(|v| v.as_str()).map(String::from));
                    let label = display_label(title.as_deref(), None, "document", &other_node);
                    ("doc".to_string(), "document".to_string(), label)
                }
                memvault_core::NodeRef::Attachment(cid) => {
                    let name = client
                        .get_file_manifest(cid)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                        .and_then(|v| v.get("filename").and_then(|f| f.as_str()).map(String::from));
                    let label = display_label(name.as_deref(), None, "file", &other_node);
                    ("file".to_string(), "file".to_string(), label)
                }
            };
            edges.push(EdgeDetail {
                edge_id: hex::encode(edge.id.0),
                relation: edge.relation,
                direction,
                other_node,
                other_label,
                other_kind,
                other_node_type,
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
pub(crate) async fn expand_node(id: String, show_retracted: bool) -> Result<Vec<NodeSummary>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let node_ref = memvault_core::NodeRef::from_tag_label(&id)
        .ok_or_else(|| ServerFnError::new("Invalid node ID"))?;

    let mut neighbors = Vec::new();
    if let Ok(edge_list) = client.edges_of(&node_ref).await {
        for (source, edge) in edge_list {
            let other = if source == node_ref {
                &edge.target
            } else {
                &source
            };
            let other_id = other.tag_label();
            // Try to get entity details for entity nodes
            if let memvault_core::NodeRef::Entity(eid) = other {
                if let Ok(Some(entity)) = client.get_entity_scoped(eid, &memvault_core::QueryScope::all().with_include_retracted(show_retracted)).await {
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

// ── Kind palette ──────────────────────────────────────────────────────
//
// Every kind resolves to one of the six `PillVariant` slots in the
// planai-design palette so the graph reads as part of the rest of the
// app. Common kinds get hand-picked variants below; unknown kinds fall
// through to a deterministic hash → variant cycle (same kind always
// renders the same color, but two unfamiliar kinds may collide on the
// same variant — that's the cost of staying inside a 6-color system).

/// Display kind for a node: the entity kind for entities, the node_type
/// ("doc"/"file") otherwise.
pub(crate) fn display_kind_for<'a>(node_type: &'a str, kind: &'a str) -> &'a str {
    if node_type == "entity" {
        kind
    } else {
        node_type
    }
}

/// All six palette slots in a fixed order — used as the target set when
/// hashing unknown kinds. Keep `Muted` last so first-time hash collisions
/// land on the more vivid slots first.
const PALETTE_CYCLE: [PillVariant; 6] = [
    PillVariant::Info,
    PillVariant::Accent,
    PillVariant::Ok,
    PillVariant::Warn,
    PillVariant::Bad,
    PillVariant::Muted,
];

/// Hand-picked `PillVariant` for a display-kind. `None` means the kind
/// falls through to the hash-cycle.
fn kind_variant_opt(display_kind: &str) -> Option<PillVariant> {
    Some(match display_kind {
        // Entities — the most common kinds we see in real graphs.
        "person" | "team" => PillVariant::Info,
        "project" | "server" => PillVariant::Accent,
        "concept" | "library" => PillVariant::Ok,
        "doc" | "document" | "tool" => PillVariant::Warn,
        "database" => PillVariant::Bad,
        "file" | "attachment" | "standard" | "topic" => PillVariant::Muted,
        _ => return None,
    })
}

/// `PillVariant` for a display-kind. Falls back to a deterministic
/// hash → palette-cycle mapping so unfamiliar kinds still pick up a
/// stable, on-brand color.
pub(crate) fn kind_variant(display_kind: &str) -> PillVariant {
    if let Some(v) = kind_variant_opt(display_kind) {
        return v;
    }
    let mut h: u32 = 0;
    for b in display_kind.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    PALETTE_CYCLE[(h as usize) % PALETTE_CYCLE.len()]
}

/// Deterministic per-kind color: hashes the kind string to a stable hue, so
/// kinds outside the six semantic variants each get their own color (mkg's
/// colorful graph palette) rather than collapsing onto a shared variant.
fn hash_color(s: &str) -> String {
    let mut h: u32 = 0;
    for b in s.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    let hue = h % 360;
    format!("hsl({hue}, 55%, 55%)")
}

/// SVG `(fill, stroke)` pair for a display-kind. The six semantic kinds reuse
/// the design-token status palette; every other kind gets a deterministic
/// hashed hue so dense graphs stay colorful and kinds are distinguishable.
pub(crate) fn kind_svg_palette(display_kind: &str) -> (String, String) {
    match kind_variant_opt(display_kind) {
        Some(PillVariant::Info) => ("rgb(var(--c-info-soft))".into(), "rgb(var(--c-info))".into()),
        Some(PillVariant::Accent) => ("rgb(var(--c-brand-soft))".into(), "rgb(var(--c-brand))".into()),
        Some(PillVariant::Ok) => ("rgb(var(--c-success-soft))".into(), "rgb(var(--c-success))".into()),
        Some(PillVariant::Warn) => ("rgb(var(--c-warn-soft))".into(), "rgb(var(--c-warn-strong))".into()),
        Some(PillVariant::Bad) => ("rgb(var(--c-danger-soft))".into(), "rgb(var(--c-danger))".into()),
        Some(PillVariant::Muted) => ("rgb(var(--c-surface-2))".into(), "rgb(var(--c-fg-faint))".into()),
        None => {
            let c = hash_color(display_kind);
            (c.clone(), c)
        }
    }
}

/// Full-saturation halo color for a display-kind. Opacity is applied at
/// the use site so the same color drives both the field halo (low α) and
/// the brand "selected" emphasis (higher α via the brand variant).
pub(crate) fn kind_halo_color(display_kind: &str) -> String {
    match kind_variant_opt(display_kind) {
        Some(PillVariant::Info) => "rgb(var(--c-info))".into(),
        Some(PillVariant::Accent) => "rgb(var(--c-brand))".into(),
        Some(PillVariant::Ok) => "rgb(var(--c-success))".into(),
        Some(PillVariant::Warn) => "rgb(var(--c-warn))".into(),
        Some(PillVariant::Bad) => "rgb(var(--c-danger))".into(),
        Some(PillVariant::Muted) => "rgb(var(--c-fg-faint))".into(),
        None => hash_color(display_kind),
    }
}

// ── Viewport state ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Viewport {
    pub(crate) offset_x: f64,
    pub(crate) offset_y: f64,
    pub(crate) zoom: f64,
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
        let min_x = nodes
            .iter()
            .map(|n| n.x - n.radius)
            .fold(f64::INFINITY, f64::min);
        let max_x = nodes
            .iter()
            .map(|n| n.x + n.radius)
            .fold(f64::NEG_INFINITY, f64::max);
        let min_y = nodes
            .iter()
            .map(|n| n.y - n.radius)
            .fold(f64::INFINITY, f64::min);
        let max_y = nodes
            .iter()
            .map(|n| n.y + n.radius)
            .fold(f64::NEG_INFINITY, f64::max);

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

/// A stable key derived from the current node set, so `GraphView` re-mounts
/// (and rebuilds its physics sim) whenever the loaded nodes change — e.g. after
/// a bucket / view / retracted change.
fn node_set_key(nodes: &[NodeSummary]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    nodes.len().hash(&mut h);
    for n in nodes {
        n.id.hash(&mut h);
    }
    h.finish()
}

#[component]
pub fn GraphExplorer() -> Element {
    use_topbar(&t!("graph-title"));
    let filters = crate::ui::filters::use_filters();
    let nodes_res = use_server_future(move || {
        let f = filters.read();
        async move { list_graph_nodes(f.view, f.bucket, f.show_retracted).await }
    })?;
    // Re-fetch on in-place scope change (use_server_future only re-runs on
    // remount, not on signal change).
    use_effect(move || {
        let _ = filters.read();
        let mut r = nodes_res;
        r.restart();
    });

    match &*nodes_res.read() {
        Some(Ok(nodes)) => {
            // Re-mount GraphView when the node set changes (e.g. after a
            // bucket/view/retracted change) — otherwise its physics-sim signal,
            // seeded once at mount, keeps showing the previous data.
            let key = node_set_key(nodes);
            rsx! { GraphView { key: "{key}", initial_nodes: nodes.clone() } }
        }
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", {t!("graph-loading")} } },
    }
}

#[component]
fn GraphView(initial_nodes: Vec<NodeSummary>) -> Element {
    let show_retracted = use_context::<crate::ui::topbar::ShowRetractedSignal>();
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
    let dragging_node = use_signal(|| None::<usize>);
    let did_drag = use_signal(|| false);
    let panning = use_signal(|| false);
    let pan_start = use_signal(|| (0.0f64, 0.0f64));
    let mut sidebar_search = use_signal(String::new);
    let mut kind_filter = use_signal(|| None::<String>);
    let mut focus_node = use_signal(|| None::<String>);
    let mut detail = use_signal(|| None::<NodeDetail>);
    let mut settings = use_signal(GraphSettings::default);
    let mut settings_open = use_signal(|| false);
    let hovered = use_signal(|| None::<usize>);

    let mut settings_loaded = use_signal(|| false);
    // Load persisted settings once on mount (client-side only).
    use_effect(move || {
        settings.set(load_settings());
        settings_loaded.set(true);
    });
    // Persist settings whenever they change (client-side only). Skips until the
    // initial load has completed so it never clobbers stored settings with defaults.
    use_effect(move || {
        let s = *settings.read();
        if !*settings_loaded.peek() {
            return;
        }
        save_settings(&s);
    });

    // Push force-param changes into the simulation and reheat so the
    // canvas relaxes into the new layout instead of jumping. Gated on
    // `sim_ran` so the very first run (which already does its own warmup
    // below) doesn't double up.
    use_effect(move || {
        let p = settings.read().to_force_params();
        if !*sim_ran.peek() {
            return;
        }
        let mut s = sim.write();
        if s.params == p {
            return;
        }
        s.params = p;
        s.reheat();
        for _ in 0..120 {
            if s.is_settled() {
                break;
            }
            s.tick();
        }
    });

    // Run simulation client-side only (use_effect doesn't fire during SSR).
    use_effect(move || {
        if *sim_ran.read() {
            return;
        }
        sim_ran.set(true);
        let mut s = sim.write();
        for _ in 0..300 {
            if s.is_settled() {
                break;
            }
            s.tick();
        }
        viewport.set(Viewport::fit_to_nodes(&s.nodes));
    });

    // Re-seed the simulation when the incoming node set changes. The parent
    // keys this component to force a remount on scope change, but single-
    // component key remounts aren't reliable here, so the canvas (which reads
    // `sim`, seeded once via use_signal) would otherwise stay frozen while the
    // sidebar — which reads `initial_nodes` directly — already updated.
    let current_key = node_set_key(&initial_nodes);
    let mut last_key = use_signal(|| current_key);
    if *last_key.peek() != current_key {
        last_key.set(current_key);
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
        sim.set(s);
        // Re-run physics for the new node set (the physics effect is gated on
        // this flag).
        sim_ran.set(false);
    }

    let s = sim.read();
    let all_nodes: Vec<GraphNode> = s.nodes.clone();
    let all_edges: Vec<GraphEdge> = s.edges.clone();
    drop(s);

    // If focus mode is active, filter to just the focused node and its neighbors.
    let (nodes, edges) = if let Some(ref focus_id) = *focus_node.read() {
        let focus_idx = all_nodes.iter().position(|n| &n.id == focus_id);
        if let Some(fi) = focus_idx {
            let mut visible_indices: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
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
    let mut kinds: Vec<String> = initial_nodes
        .iter()
        .map(|e| {
            if e.node_type != "entity" {
                e.node_type.clone()
            } else {
                e.kind.clone()
            }
        })
        .collect();
    kinds.sort();
    kinds.dedup();

    // Filter sidebar list.
    let sidebar_q = sidebar_search.read().to_lowercase();
    let active_kind = kind_filter.read().clone();
    let filtered_list: Vec<&NodeSummary> = initial_nodes
        .iter()
        .filter(|e| {
            let display_kind = if e.node_type != "entity" {
                &e.node_type
            } else {
                &e.kind
            };
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

    let is_focus_active = focus_node.read().is_some();
    let cfg = *settings.read();

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
                // Toolbar — kicker-styled inline stats. Numbers use the
                // mono stack so they line up across the bar.
                div { class: "flex items-center gap-3 flex-wrap",
                    span { class: "kicker", {t!("graph-stat-nodes")} }
                    span { class: "font-mono text-sm font-semibold text-fg", "{nodes.len()}" }
                    span { class: "text-fg-faint", "·" }
                    span { class: "kicker", {t!("graph-stat-edges")} }
                    span { class: "font-mono text-sm font-semibold text-fg", "{edges.len()}" }
                    span { class: "text-fg-faint", "·" }
                    span { class: "kicker", {t!("graph-stat-kinds")} }
                    span { class: "font-mono text-sm font-semibold text-fg", "{kinds.len()}" }
                    span { class: "text-fg-faint", "·" }
                    span { class: "kicker", {t!("graph-stat-zoom")} }
                    span { class: "font-mono text-sm font-semibold text-fg", "{vp.zoom:.1}×" }
                    button {
                        class: "btn btn-xs btn-secondary ml-auto",
                        onclick: move |_| {
                            let open = !*settings_open.peek();
                            settings_open.set(open);
                        },
                        {t!("graph-settings")}
                        span { class: "ml-1 font-mono text-fg-faint",
                            if settings_open() { "▾" } else { "▸" }
                        }
                    }
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
                        // Kind filter pills — active picks up the kind's
                        // own variant, inactive stays muted.
                        div { class: "flex flex-wrap gap-1",
                            for kind in &kinds {
                                {
                                    let k = kind.clone();
                                    let is_active = active_kind.as_ref() == Some(kind);
                                    let variant = kind_variant(kind);
                                    rsx! {
                                        button {
                                            onclick: move |_| {
                                                if is_active {
                                                    kind_filter.set(None);
                                                } else {
                                                    kind_filter.set(Some(k.clone()));
                                                }
                                            },
                                            Pill {
                                                variant: if is_active { variant } else { PillVariant::Muted },
                                                Dot { variant }
                                                "{kind}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Node list — dot + label + edge count, single row.
                        div { class: "space-y-px overflow-y-auto max-h-[560px]",
                            for node in &filtered_list {
                                {
                                    let id = node.id.clone();
                                    let is_selected = selected.read().as_ref() == Some(&node.id);
                                    let display_kind = display_kind_for(&node.node_type, &node.kind).to_string();
                                    let variant = kind_variant(&display_kind);
                                    let edge_count = node.edges.len();
                                    rsx! {
                                        div {
                                            class: "flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer hover:bg-surface-2 transition-colors",
                                            class: if is_selected { "bg-brand-soft" } else { "" },
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
                                            Dot { variant }
                                            span {
                                                class: "text-sm truncate flex-1",
                                                class: if is_selected { "text-brand font-medium" } else { "text-fg" },
                                                "{node.label}"
                                            }
                                            span { class: "text-xs font-mono text-fg-faint shrink-0",
                                                "{edge_count}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ── Main canvas ─────────────────────────────────
                    Card { class: "flex-1 relative",
                        if settings_open() {
                            SettingsPanel { settings }
                        }
                        // Legend strip — kicker + a dot per kind currently
                        // present in the graph. Mirrors the filter row but
                        // anchors the palette as a visual key over the canvas.
                        div {
                            class: "flex items-center gap-3 flex-wrap px-4 py-2 bg-surface-2 border-b border-line text-xs text-fg-muted",
                            span { class: "kicker", {t!("graph-legend-kinds")} }
                            for (i, kind) in kinds.iter().enumerate() {
                                {
                                    let variant = kind_variant(kind);
                                    rsx! {
                                        if i > 0 {
                                            span { class: "text-fg-faint", "·" }
                                        }
                                        span { class: "inline-flex items-center gap-1.5",
                                            Dot { variant }
                                            "{kind}"
                                        }
                                    }
                                }
                            }
                            span { class: "ml-auto font-mono text-fg-faint", {t!("graph-hint")} }
                        }

                        GraphCanvas {
                            nodes: nodes.clone(),
                            edges: edges.clone(),
                            settings: cfg,
                            view_box: vb.clone(),
                            selected,
                            hovered,
                            dragging_node,
                            detail,
                            sim,
                            viewport,
                            panning,
                            pan_start,
                            did_drag,
                        }
                    }

                    // ── Right detail panel ──────────────────────────
                    DetailPanel { detail, selected, focus_node }
                }
            }
        }
    }
}
