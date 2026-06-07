# Knowledge Graph View Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the web UI knowledge graph usable for exploration — readable labels via level-of-detail, an Obsidian-style settings panel (arrows, fade, node size, link thickness, forces, link distance), hover-focus highlighting, resolved node names everywhere, and a readable detail panel.

**Architecture:** Enhance the existing SVG/Dioxus renderer (no Canvas migration). Pull all visual *decisions* into pure, unit-testable helpers in a new `canvas.rs` (the renderer seam), introduce a `GraphSettings` param struct + settings panel in a new `controls.rs` (browser-local via `localStorage`), and apply display/force params inline in the SVG. A shared `display_label` resolver kills raw `entity:<hex>` strings. Features land incrementally (tasks 1–9); the final task moves the SVG and detail panel into components to realize the seam and shrink `explorer.rs`.

**Tech Stack:** Rust + Dioxus 0.8 (fullstack/WASM), SVG rendering, `dioxus_i18n` (`t!`), `web-sys` for `localStorage`, `serde`/`serde_json`.

**Context reference:** Design spec at `docs/specs/2026-06-07-graph-view-redesign-design.md`. Branch: `viz`.

**Conventions for every task:**
- Test command for pure-fn unit tests: `cargo test -p memvault-web <test_name>` (default features include `webui`; first compile takes ~3–4 min).
- WASM/visual build check: `cd crates/memvault-web && dx build` (run from that dir).
- All paths below are relative to `crates/memvault-web/` unless absolute.

---

## File map

| File | Change |
|---|---|
| `src/ui/pages/graph/layout_engine.rs` | Add a `link_distance` behavioral unit test. (`link_distance` field already exists.) |
| `src/ui/pages/graph/canvas.rs` | **New.** Pure helpers: `fade_scale`, `should_show_label`, `short_ref`, `display_label`. Grows a `GraphCanvas` component in Task 10. |
| `src/ui/pages/graph/controls.rs` | **New.** `GraphSettings` struct (+`Default`, `clamp`, `to_force_params`), `load_settings`/`save_settings`, `SettingsPanel` component. |
| `src/ui/pages/graph/panel.rs` | **New** (Task 10). `DetailPanel` + `NeighborEdgeRow` moved out of `explorer.rs`. |
| `src/ui/pages/graph/explorer.rs` | Wire `display_label` into server fns; swap `force_params`→`settings`; apply display params + hover-focus + panel readability inline; Task 10 moves SVG/panel into components. |
| `src/ui/pages/graph/mod.rs` | Register `canvas`, `controls`, `panel` modules. |
| `src/ui/en-US.ftl`, `src/ui/de-DE.ftl` | New control labels. |
| `Cargo.toml` | Add `"Storage"` to `web-sys` features. |

---

## Task 1: link_distance behavioral test (layout engine)

The `link_distance` field and its spring term already exist in `layout_engine.rs`. Lock the behavior with a comparative test: a larger rest length must yield greater equilibrium separation.

**Files:**
- Test: `src/ui/pages/graph/layout_engine.rs` (append a `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Append to the end of `layout_engine.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Settle a 2-node, 1-edge graph at the given link rest length and
    /// return the final inter-node distance.
    fn settle_distance(link_distance: f64) -> f64 {
        let mut s = ForceSimulation::new();
        let a = s.add_node("a".into(), "k".into(), "A".into());
        let b = s.add_node("b".into(), "k".into(), "B".into());
        s.add_edge(a, b, "rel".into(), 1.0);
        s.params.link_distance = link_distance;
        s.alpha = 1.0;
        // Runs until alpha decays below alpha_min (tick early-returns after).
        for _ in 0..3000 {
            s.tick();
        }
        let dx = s.nodes[a].x - s.nodes[b].x;
        let dy = s.nodes[a].y - s.nodes[b].y;
        (dx * dx + dy * dy).sqrt()
    }

    #[test]
    fn link_distance_controls_separation() {
        let short = settle_distance(80.0);
        let long = settle_distance(320.0);
        assert!(
            long > short,
            "longer link_distance should separate nodes more: long={long} short={short}"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it passes (field already wired)**

Run: `cargo test -p memvault-web link_distance_controls_separation`
Expected: PASS. (If it fails, the spring term is not honoring `params.link_distance` — inspect `tick()` lines ~201–217.)

- [ ] **Step 3: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/layout_engine.rs
git commit -m "test(graph): lock link_distance separation behavior"
```

---

## Task 2: Pure canvas helpers (label fade + name resolution)

These are the renderer-agnostic *decisions* — the seam. All pure, all TDD'd.

**Files:**
- Create: `src/ui/pages/graph/canvas.rs`
- Modify: `src/ui/pages/graph/mod.rs`

- [ ] **Step 1: Register the module**

Add to `src/ui/pages/graph/mod.rs`:

```rust
pub mod canvas;
```

- [ ] **Step 2: Write the failing tests**

Create `src/ui/pages/graph/canvas.rs` with helpers stubbed to wrong values so tests fail first:

```rust
//! Renderer-agnostic graph helpers (the renderer "seam").
//!
//! Pure decision functions shared by the SVG renderer today and any
//! future Canvas2D renderer. No Dioxus, no DOM — just math and strings,
//! so they are unit-testable on the host target.

/// Map the 0..1 "text fade threshold" slider to a world-space cutoff for
/// `zoom * radius`. 0.0 => every label shows; 1.0 => only large hubs,
/// and only when zoomed in.
pub fn fade_scale(threshold: f64) -> f64 {
    let _ = threshold;
    -1.0 // STUB: make tests fail
}

/// Whether a node's label should render. `forced` is true when the node
/// is selected / hovered / focused / neighbor-highlighted.
pub fn should_show_label(zoom: f64, radius: f64, threshold: f64, forced: bool) -> bool {
    let _ = (zoom, radius, threshold, forced);
    false // STUB
}

/// First 6 hex chars after the `<type>:` prefix of a node ref.
pub fn short_ref(node_ref: &str) -> String {
    let _ = node_ref;
    String::new() // STUB
}

/// Resolve a human label: name -> title -> "<kind> · <short-id>".
/// Never returns a raw `entity:<hex>` ref.
pub fn display_label(name: Option<&str>, title: Option<&str>, kind: &str, node_ref: &str) -> String {
    let _ = (name, title, kind, node_ref);
    String::new() // STUB
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p memvault-web canvas::tests`
Expected: FAIL on all five (stub values).

- [ ] **Step 4: Implement the helpers**

Replace the four stub bodies with:

```rust
pub fn fade_scale(threshold: f64) -> f64 {
    // Cutoff for `zoom * radius`. The 24.0 constant is tuned so that at the
    // default fade (0.5 -> cutoff 12) and a typical fit-view zoom (~0.4),
    // only well-connected nodes (radius >= 30, i.e. many edges) label, while
    // at 1× most connected nodes (radius >= 12) label. Re-tune in Task 7's
    // manual check against the real vault if too few / too many labels show.
    threshold.clamp(0.0, 1.0) * 24.0
}

pub fn should_show_label(zoom: f64, radius: f64, threshold: f64, forced: bool) -> bool {
    forced || zoom * radius >= fade_scale(threshold)
}

pub fn short_ref(node_ref: &str) -> String {
    node_ref
        .split(':')
        .nth(1)
        .map(|h| h.chars().take(6).collect())
        .unwrap_or_default()
}

pub fn display_label(name: Option<&str>, title: Option<&str>, kind: &str, node_ref: &str) -> String {
    name.filter(|s| !s.trim().is_empty())
        .or_else(|| title.filter(|s| !s.trim().is_empty()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{kind} · {}", short_ref(node_ref)))
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p memvault-web canvas::tests`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/canvas.rs crates/memvault-web/src/ui/pages/graph/mod.rs
git commit -m "feat(graph): pure label-fade and name-resolution helpers"
```

---

## Task 3: GraphSettings + localStorage (controls module)

**Files:**
- Create: `src/ui/pages/graph/controls.rs`
- Modify: `src/ui/pages/graph/mod.rs`
- Modify: `Cargo.toml` (web-sys `Storage` feature)

- [ ] **Step 1: Add the `Storage` web-sys feature**

In `crates/memvault-web/Cargo.toml`, change the `web-sys` line (currently features `["EventSource", "MessageEvent", "Event", "KeyboardEvent", "Window", "Location"]`) to also include `"Storage"`:

```toml
web-sys = { version = "0.3", features = ["EventSource", "MessageEvent", "Event", "KeyboardEvent", "Window", "Location", "Storage"], optional = true }
```

- [ ] **Step 2: Register the module**

Add to `src/ui/pages/graph/mod.rs`:

```rust
pub mod controls;
```

- [ ] **Step 3: Write the failing tests**

Create `src/ui/pages/graph/controls.rs` with the struct + stubs:

```rust
//! Graph display/force settings: the `GraphSettings` param struct, its
//! localStorage persistence, and the floating settings panel UI.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::Card;
use serde::{Deserialize, Serialize};

use super::layout_engine::ForceParams;

pub const SETTINGS_KEY: &str = "memvault.graph.settings";

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GraphSettings {
    // Display
    pub show_arrows: bool,
    pub label_fade: f64,
    pub node_scale: f64,
    pub link_thickness: f64,
    // Forces
    pub center_strength: f64,
    pub repulsion: f64, // positive magnitude; negated for the engine
    pub link_strength: f64,
    pub link_distance: f64,
}

impl Default for GraphSettings {
    fn default() -> Self {
        Self {
            show_arrows: true,
            label_fade: 0.5,
            node_scale: 1.0,
            link_thickness: 1.0,
            center_strength: 0.01,
            repulsion: 2000.0,
            link_strength: 0.08,
            link_distance: 200.0,
        }
    }
}

impl GraphSettings {
    /// Clamp every field into its valid slider range (defends against
    /// corrupt/old localStorage payloads).
    pub fn clamp(&mut self) {
        // STUB: no-op so the clamp test fails first.
    }

    /// Project the force fields onto the engine's `ForceParams`.
    pub fn to_force_params(&self) -> ForceParams {
        ForceParams::default() // STUB
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_bounds_all_fields() {
        let mut s = GraphSettings {
            show_arrows: true,
            label_fade: 5.0,
            node_scale: 0.0,
            link_thickness: 99.0,
            center_strength: 1.0,
            repulsion: 10.0,
            link_strength: -1.0,
            link_distance: 9000.0,
        };
        s.clamp();
        assert_eq!(s.label_fade, 1.0);
        assert_eq!(s.node_scale, 0.25);
        assert_eq!(s.link_thickness, 4.0);
        assert_eq!(s.center_strength, 0.08);
        assert_eq!(s.repulsion, 200.0);
        assert_eq!(s.link_strength, 0.0);
        assert_eq!(s.link_distance, 400.0);
    }

    #[test]
    fn to_force_params_negates_repulsion() {
        let s = GraphSettings::default();
        let p = s.to_force_params();
        assert_eq!(p.repulsion_strength, -2000.0);
        assert_eq!(p.link_distance, 200.0);
        assert_eq!(p.link_strength, 0.08);
        assert_eq!(p.center_strength, 0.01);
    }

    #[test]
    fn serde_roundtrips() {
        let s = GraphSettings::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: GraphSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p memvault-web controls::tests`
Expected: FAIL on `clamp_bounds_all_fields` and `to_force_params_negates_repulsion`.

- [ ] **Step 5: Implement `clamp` and `to_force_params`**

Replace the two stub bodies:

```rust
    pub fn clamp(&mut self) {
        self.label_fade = self.label_fade.clamp(0.0, 1.0);
        self.node_scale = self.node_scale.clamp(0.25, 3.0);
        self.link_thickness = self.link_thickness.clamp(0.25, 4.0);
        self.center_strength = self.center_strength.clamp(0.0, 0.08);
        self.repulsion = self.repulsion.clamp(200.0, 6000.0);
        self.link_strength = self.link_strength.clamp(0.0, 0.4);
        self.link_distance = self.link_distance.clamp(30.0, 400.0);
    }

    pub fn to_force_params(&self) -> ForceParams {
        ForceParams {
            link_strength: self.link_strength,
            link_distance: self.link_distance,
            center_strength: self.center_strength,
            repulsion_strength: -self.repulsion,
        }
    }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p memvault-web controls::tests`
Expected: PASS (3 tests).

- [ ] **Step 7: Add the persistence helpers**

Append to `controls.rs` (these touch the browser; they are only ever called from client-side effects, and compile on the host target because `web-sys` bindings exist on all targets):

```rust
/// Load settings from localStorage, clamped. Returns defaults when absent,
/// unparseable, or outside a browser (SSR/host).
pub fn load_settings() -> GraphSettings {
    if let Some(win) = web_sys::window() {
        if let Ok(Some(store)) = win.local_storage() {
            if let Ok(Some(raw)) = store.get_item(SETTINGS_KEY) {
                if let Ok(mut parsed) = serde_json::from_str::<GraphSettings>(&raw) {
                    parsed.clamp();
                    return parsed;
                }
            }
        }
    }
    GraphSettings::default()
}

/// Persist settings to localStorage. No-op outside a browser.
pub fn save_settings(s: &GraphSettings) {
    if let Some(win) = web_sys::window() {
        if let Ok(Some(store)) = win.local_storage() {
            if let Ok(raw) = serde_json::to_string(s) {
                let _ = store.set_item(SETTINGS_KEY, &raw);
            }
        }
    }
}
```

- [ ] **Step 8: Verify it builds**

Run: `cargo test -p memvault-web controls:: --no-run`
Expected: compiles clean (confirms the `Storage` feature is wired and `web-sys` calls typecheck).

- [ ] **Step 9: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/controls.rs crates/memvault-web/src/ui/pages/graph/mod.rs crates/memvault-web/Cargo.toml
git commit -m "feat(graph): GraphSettings struct with localStorage persistence"
```

---

## Task 4: i18n keys for the new controls

**Files:**
- Modify: `src/ui/en-US.ftl`
- Modify: `src/ui/de-DE.ftl`

- [ ] **Step 1: Add English keys**

In `src/ui/en-US.ftl`, after the existing `graph-forces-reset = Reset` line (≈line 99), add:

```ftl
graph-settings = Settings
graph-group-display = Display
graph-group-forces = Forces
graph-display-arrows = Arrows
graph-display-fade = Text fade
graph-display-node-size = Node size
graph-display-link-thickness = Link thickness
graph-force-distance = Link distance
```

- [ ] **Step 2: Add German keys**

In `src/ui/de-DE.ftl`, after the existing `graph-forces-reset = Zurücksetzen` line (≈line 99), add:

```ftl
graph-settings = Einstellungen
graph-group-display = Anzeige
graph-group-forces = Kräfte
graph-display-arrows = Pfeile
graph-display-fade = Textausblendung
graph-display-node-size = Knotengröße
graph-display-link-thickness = Verbindungsstärke
graph-force-distance = Verbindungsabstand
```

- [ ] **Step 3: Verify the FTL still parses**

Run: `cd crates/memvault-web && cargo check -p memvault-web 2>&1 | tail -5`
Expected: no `dioxus_i18n`/FTL parse errors. (`t!` keys are validated at use; this just confirms the files are well-formed.)

- [ ] **Step 4: Commit**

```bash
git add crates/memvault-web/src/ui/en-US.ftl crates/memvault-web/src/ui/de-DE.ftl
git commit -m "i18n(graph): labels for display + force controls"
```

---

## Task 5: Resolve neighbor + node names server-side (kill raw hashes)

Route both server resolvers through `display_label` so unnamed nodes read `<kind> · <short-id>` instead of a bare kind or a raw `entity:<hex>`.

**Files:**
- Modify: `src/ui/pages/graph/explorer.rs` — `list_graph_nodes` (≈lines 150–158) and `get_node_detail` (≈lines 319–377)

- [ ] **Step 1: Import the helper**

Near the top of `explorer.rs`, alongside `use super::layout_engine::...`, add:

```rust
use super::canvas::display_label;
```

- [ ] **Step 2: Use it in `list_graph_nodes`**

Find the label resolution in `list_graph_nodes` (currently):

```rust
let label = entity
    .props
    .get("name")
    .or_else(|| entity.props.get("title"))
    .and_then(|v| v.as_str())
    .unwrap_or(&entity.kind)
    .to_string();
```

Note: this is inside a `.map(|entity| { ... })` closure whose only input is `entity`; the node `id` (`format!("entity:{}", hex::encode(entity.id.0))`) is built on the line *after* the label, so neither `id` nor a `node_ref` is in scope at the label site. Build the ref inline for the 4th arg:

```rust
let label = display_label(
    entity.props.get("name").and_then(|v| v.as_str()),
    entity.props.get("title").and_then(|v| v.as_str()),
    &entity.kind,
    &format!("entity:{}", hex::encode(entity.id.0)),
);
```

(Or hoist the existing `let id = format!(...)` line above the label and pass `&id`. The 4th arg must be the node's `entity:<hex>` ref so the `<kind> · <short-id>` fallback can derive the short id.)

- [ ] **Step 3: Use it in `get_node_detail` (entity branch)**

In the `NodeRef::Entity(eid)` arm of the edge loop (≈lines 320–343), replace the success-path label resolution and the fetch-fail fallback so **both** go through `display_label`:

```rust
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
```

(`other_node` is `other_ref.tag_label()`, already bound above this match.)

- [ ] **Step 4: Use it for docs and files (consistency)**

In the `NodeRef::Doc(did)` arm, replace the `.unwrap_or_else(|| "Untitled".to_string())` so a title-less doc reads `document · <short>`:

```rust
let title = client
    .get_doc_scoped(did, &scope)
    .await
    .ok()
    .flatten()
    .and_then(|d| d.frontmatter.get("title").and_then(|v| v.as_str()).map(String::from));
let label = display_label(title.as_deref(), None, "document", &other_node);
("doc".to_string(), "document".to_string(), label)
```

In the `NodeRef::Attachment(cid)` arm, similarly replace `.unwrap_or_else(|| "Unnamed file".to_string())`:

```rust
let name = client
    .get_file_manifest(cid)
    .await
    .ok()
    .flatten()
    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    .and_then(|v| v.get("filename").and_then(|f| f.as_str()).map(String::from));
let label = display_label(name.as_deref(), None, "file", &other_node);
("file".to_string(), "file".to_string(), label)
```

- [ ] **Step 5: Verify it builds (server feature)**

Run: `cargo check -p memvault-web --features server`
Expected: compiles clean. Fix any borrow/scope issue with the 4th `display_label` arg per the note in Step 2.

- [ ] **Step 6: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/explorer.rs
git commit -m "fix(graph): resolve all node/neighbor names, never show raw refs"
```

---

## Task 6: Swap force sliders for the settings panel

Replace the `force_params` signal + the horizontal forces bar with a `settings: Signal<GraphSettings>`, persisted, driving a floating `SettingsPanel`.

**Files:**
- Modify: `src/ui/pages/graph/controls.rs` — add `SettingsPanel`
- Modify: `src/ui/pages/graph/explorer.rs` — signal swap + panel mount

- [ ] **Step 1: Add the `SettingsPanel` component to `controls.rs`**

Append to `controls.rs`. Each control writes through to the signal and calls `save_settings`; `on_reset` restores defaults.

`Signal<GraphSettings>` is `Copy`, so each handler captures `settings` directly and writes through it — do **not** share one `update` closure across handlers (it would be moved into the first handler and fail to compile). Each slider's `on_input` mutates one field and clamps; **persistence is centralized** in a single `use_effect` in `GraphView` (Task 6 Step 2), so handlers don't call `save_settings` themselves:

```rust
/// Floating, grouped settings panel (Display + Forces). Toggled by the
/// gear button in the toolbar. Mirrors Obsidian's graph controls.
#[component]
pub fn SettingsPanel(settings: Signal<GraphSettings>) -> Element {
    let s = *settings.read();
    rsx! {
        Card { class: "absolute top-2 right-2 z-10 w-64 p-3 space-y-3 shadow-lg",
            // ── Display ──────────────────────────────────────────────
            div { class: "kicker", {t!("graph-group-display")} }
            label { class: "flex items-center justify-between text-xs",
                span { {t!("graph-display-arrows")} }
                input {
                    r#type: "checkbox",
                    checked: s.show_arrows,
                    onchange: move |e: Event<FormData>| {
                        let v = e.checked();
                        settings.write().show_arrows = v;
                    },
                }
            }
            Slider {
                label: t!("graph-display-fade"), min: 0.0, max: 1.0, step: 0.02,
                value: s.label_fade, fmt: format!("{:.2}", s.label_fade),
                on_input: move |v| { { let mut w = settings.write(); w.label_fade = v; w.clamp(); } },
            }
            Slider {
                label: t!("graph-display-node-size"), min: 0.25, max: 3.0, step: 0.05,
                value: s.node_scale, fmt: format!("{:.2}×", s.node_scale),
                on_input: move |v| { { let mut w = settings.write(); w.node_scale = v; w.clamp(); } },
            }
            Slider {
                label: t!("graph-display-link-thickness"), min: 0.25, max: 4.0, step: 0.05,
                value: s.link_thickness, fmt: format!("{:.2}×", s.link_thickness),
                on_input: move |v| { { let mut w = settings.write(); w.link_thickness = v; w.clamp(); } },
            }
            // ── Forces ───────────────────────────────────────────────
            div { class: "kicker pt-1 border-t border-line", {t!("graph-group-forces")} }
            Slider {
                label: t!("graph-force-center"), min: 0.0, max: 0.08, step: 0.001,
                value: s.center_strength, fmt: format!("{:.3}", s.center_strength),
                on_input: move |v| { { let mut w = settings.write(); w.center_strength = v; w.clamp(); } },
            }
            Slider {
                label: t!("graph-force-repel"), min: 200.0, max: 6000.0, step: 50.0,
                value: s.repulsion, fmt: format!("{:.0}", s.repulsion),
                on_input: move |v| { { let mut w = settings.write(); w.repulsion = v; w.clamp(); } },
            }
            Slider {
                label: t!("graph-force-link"), min: 0.0, max: 0.4, step: 0.005,
                value: s.link_strength, fmt: format!("{:.3}", s.link_strength),
                on_input: move |v| { { let mut w = settings.write(); w.link_strength = v; w.clamp(); } },
            }
            Slider {
                label: t!("graph-force-distance"), min: 30.0, max: 400.0, step: 5.0,
                value: s.link_distance, fmt: format!("{:.0}", s.link_distance),
                on_input: move |v| { { let mut w = settings.write(); w.link_distance = v; w.clamp(); } },
            }
            button {
                class: "btn btn-xs btn-ghost w-full",
                onclick: move |_| settings.set(GraphSettings::default()),
                {t!("graph-forces-reset")}
            }
        }
    }
}
```

(`e.checked()` is the right call here — it's already used on `Event<FormData>` elsewhere in this codebase, e.g. `src/ui/topbar.rs` and `src/ui/pages/buckets/detail.rs`.)

/// One labeled range row: caption, slider, live value.
#[component]
fn Slider(
    label: String,
    min: f64,
    max: f64,
    step: f64,
    value: f64,
    fmt: String,
    on_input: EventHandler<f64>,
) -> Element {
    rsx! {
        div { class: "space-y-0.5",
            div { class: "flex items-center justify-between text-xs",
                span { class: "text-fg-muted", "{label}" }
                span { class: "font-mono text-fg-faint", "{fmt}" }
            }
            input {
                r#type: "range",
                min: "{min}", max: "{max}", step: "{step}",
                value: "{value}",
                class: "w-full",
                oninput: move |e: Event<FormData>| {
                    if let Ok(v) = e.value().parse::<f64>() {
                        on_input.call(v);
                    }
                },
            }
        }
    }
}
```

- [ ] **Step 2: Swap the signal in `explorer.rs`**

Add import near the other graph `use` lines:

```rust
use super::controls::{load_settings, save_settings, GraphSettings, SettingsPanel};
```

Replace the declaration (≈line 693):

```rust
let mut force_params = use_signal(ForceParams::default);
```

with:

```rust
let mut settings = use_signal(GraphSettings::default);
```

Then add two effects (place them after `sim_ran` is declared, near the other `use_effect`s). The first loads persisted settings on mount; the second persists on every change. `use_effect` only runs client-side, so it never touches `localStorage` during SSR:

```rust
// Load persisted settings once on mount (client-side only).
use_effect(move || {
    settings.set(load_settings());
});
// Persist settings whenever they change. Reads `settings` reactively, so it
// re-runs on each edit; writes are tiny synchronous localStorage sets.
use_effect(move || {
    let s = *settings.read();
    save_settings(&s);
});
```

(If per-pixel slider writes ever matter, debounce this with `gloo-timers` — a dep already in the crate. Not needed at this scale.)

Rename the `forces_open` signal to `settings_open` (≈line 694):

```rust
let mut settings_open = use_signal(|| false);
```

- [ ] **Step 3: Point the reheat effect at `settings`**

Replace the body of the force-param effect (≈lines 700–717) so it derives `ForceParams` from `settings`:

```rust
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
```

- [ ] **Step 4: Toolbar — gear button toggles the panel**

Replace the `Forces` toolbar button (≈lines 966–976) with a gear toggle:

```rust
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
```

- [ ] **Step 5: Delete the old forces bar; mount the panel over the canvas**

Remove the entire `if forces_open() { ... }` block (≈lines 997–1067).

Make the canvas `Card` a positioning context and mount `SettingsPanel` inside it. Change the canvas `Card { class: "flex-1", ...` (≈line 1148) to `Card { class: "flex-1 relative", ...`, and immediately inside it (before the legend strip) add:

```rust
if settings_open() {
    SettingsPanel { settings }
}
```

- [ ] **Step 6: Verify it builds (WASM)**

Run: `cd crates/memvault-web && dx build`
Expected: build succeeds. Fix any leftover references to `force_params` / `forces_open` (search the file for both and ensure none remain). `ForceParams` is no longer named directly in `explorer.rs` (it's produced via `to_force_params()`), so drop it from the `use super::layout_engine::{...}` line to avoid an unused-import warning.

- [ ] **Step 7: Manual check**

Run the app (`overmind start` from `crates/memvault-web/`, or the project's run command), open `/graph`. Confirm: gear button opens a floating panel with Display + Forces groups; dragging the force sliders relaxes the layout; reload preserves the slider values.

- [ ] **Step 8: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/controls.rs crates/memvault-web/src/ui/pages/graph/explorer.rs
git commit -m "feat(graph): floating settings panel, persisted, replaces forces bar"
```

---

## Task 7: Apply display params in the SVG (fade, node size, link thickness, arrows)

**Files:**
- Modify: `src/ui/pages/graph/explorer.rs` — SVG render block (≈lines 1172–1438)

- [ ] **Step 1: Import the fade helper**

**Replace** the `use super::canvas::display_label;` line added in Task 5 (do not add a second line — that would duplicate-import `display_label`) with:

```rust
use super::canvas::{display_label, should_show_label};
```

- [ ] **Step 2: Read settings once before the SVG block**

Just before `rsx! {` builds the SVG (near line 940, alongside `let is_focus_active = ...`), add:

```rust
let cfg = *settings.read();
```

- [ ] **Step 3: Node size — scale radius at render time**

In both the kind-halo loop (≈line 1230) and the node loop (≈lines 1323+), compute a scaled radius and use it everywhere the code reads `node.radius`. At the top of each loop body add:

```rust
let r = node.radius * cfg.node_scale;
```

Then replace `node.radius` usages **inside rendering** with the scaled value `r` everywhere geometry is drawn so nothing visually mismatches:
- Kind-halo loop (≈1230): `let r = node.radius + 14.0;` → `let r = node.radius * cfg.node_scale + 14.0;`
- Selection-halo loop (≈1248): `let r = node.radius + 28.0;` → `let r = node.radius * cfg.node_scale + 28.0;`
- Circle: `r: "{node.radius}"` → `r: "{r}"`
- Doc rect: `node.radius` → `r` in the four geometry expressions.
- File polygon: `let r = node.radius;` → `let r = node.radius * cfg.node_scale;`
- Label y-offset: `y: "{node.y + node.radius + 18.0}"` → `y: "{node.y + r + 18.0}"`.
- Edge endpoint shorten (edge loop, ≈1272): `let shorten = tn.radius + 4.0;` → `let shorten = tn.radius * cfg.node_scale + 4.0;` (so arrowheads land on the scaled node edge, not inside/short of it).

(Do **not** scale the collision/physics radius in `layout_engine.rs` — only the rendered geometry here. `cfg` is bound in Step 2.)

- [ ] **Step 4: Link thickness + arrows toggle**

In the edge loop (≈lines 1282–1292), scale thickness by `cfg.link_thickness` and gate the marker on `cfg.show_arrows`:

```rust
let thickness = (if is_active { 1.5 } else { 1.0 + (edge.weight as f64 - 1.0).max(0.0) * 0.5 })
    * cfg.link_thickness;
let marker = if !cfg.show_arrows {
    "none".to_string()
} else if is_active {
    "url(#arrowhead-active)".to_string()
} else {
    "url(#arrowhead)".to_string()
};
```

The `line` already uses `marker_end: "{marker}"` — keep it (SVG treats `marker_end="none"` as no arrow).

- [ ] **Step 5: Label fade + truncation (the text-soup fix)**

First, in the node loop's **leading block** (where `nt`, `dk`, `fill`, `is_selected` are computed — before the `rsx! {`), add `forced` and a width-capped label so a single long title can't sprawl across the canvas:

```rust
let forced = is_selected;
let label_text = {
    let max = 32usize;
    if node.label.chars().count() > max {
        let head: String = node.label.chars().take(max).collect();
        format!("{head}…")
    } else {
        node.label.clone()
    }
};
```

Then replace the label `text { ... }` (≈lines 1424–1434) with a conditional, bare-element form. Dioxus rsx supports `if cond { element { } }` directly as a child (same idiom as the legend's `if i > 0 { span { } }` at ≈line 1159), so do **not** wrap it in `rsx! { }`:

```rust
if should_show_label(vp.zoom, r, cfg.label_fade, forced) {
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
```

(`vp` is the `*viewport.read()` value already bound near line 848. `r` is the scaled radius from Step 3.)

- [ ] **Step 6: Verify it builds**

Run: `cd crates/memvault-web && dx build`
Expected: success. If `marker` type mismatches (String vs &str), ensure all three branches return `String` as shown.

- [ ] **Step 7: Manual check + fade tuning**

On `/graph` against the reference vault: at the default view a *readable subset* of labels shows (well-connected nodes), not a wall of text and not a blank canvas; sliding Text-fade left reveals more, right hides more; Node-size and Link-thickness sliders visibly rescale; toggling Arrows removes/restores arrowheads. The selected node always keeps its label.

**Tune the fade constant here.** If the default view shows *no* labels (too aggressive) or *all* of them (too weak), adjust the `* 24.0` multiplier in `canvas::fade_scale` (lower = more labels). Re-run `cargo test -p memvault-web canvas::tests` after — the tests assert behavior (zoom reveals, higher threshold hides), not the exact constant, so they should still pass. Note: label truncation is by character count (~32 chars), a pragmatic approximation of the spec's "max width with ellipsis" — true SVG text-width measurement isn't available without a DOM round-trip, and char-count is sufficient to stop sprawl.

- [ ] **Step 8: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/explorer.rs
git commit -m "feat(graph): apply fade/node-size/link-thickness/arrows in render"
```

---

## Task 8: Hover-focus highlighting

Hovering a node emphasizes it + its neighbors/links and dims the rest, and force-shows neighbor labels.

**Files:**
- Modify: `src/ui/pages/graph/explorer.rs`

- [ ] **Step 1: Add a `hovered` signal**

Near the other signals (≈line 685), add:

```rust
let mut hovered = use_signal(|| None::<usize>);
```

- [ ] **Step 2: Compute the highlight set before the SVG block**

After `let cfg = *settings.read();` (Task 7 Step 2), derive the set of node indices to emphasize:

```rust
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
```

- [ ] **Step 3: Wire hover events on each node group**

In the node loop's `g { ... }` (≈line 1335), add hover handlers (alongside `onclick`/`onmousedown`):

```rust
onmouseenter: move |_| hovered.set(Some(idx)),
onmouseleave: move |_| hovered.set(None),
```

- [ ] **Step 4: Dim non-highlighted nodes**

In the node `g`, add a computed opacity. After `let is_selected = ...` add:

```rust
let dimmed = highlight.as_ref().map_or(false, |h| !h.contains(&idx));
let node_opacity = if dimmed { 0.15 } else { 1.0 };
```

Add `opacity: "{node_opacity}",` as an attribute on the `g { ... }` element.

Also dim the **kind-halos**, which are drawn in a separate earlier loop (≈1223) and would otherwise stay bright under dimmed nodes. Change that loop's header `for node in nodes.iter()` to `for (idx, node) in nodes.iter().enumerate()`, and change its `opacity: "0.10",` to a computed value:

```rust
let halo_opacity = if highlight.as_ref().map_or(false, |h| !h.contains(&idx)) { 0.02 } else { 0.10 };
```

then `opacity: "{halo_opacity}",`. (The selection halo only renders for the selected node and can stay as-is.)

- [ ] **Step 5: Dim non-incident edges**

In the edge loop, after `let is_active = ...` (≈line 1277), compute edge emphasis from the hover set and fold it into the stroke opacity:

```rust
let edge_dimmed = highlight
    .as_ref()
    .map_or(false, |h| !(h.contains(&edge.source) && h.contains(&edge.target)));
```

Then change the `stroke_opacity` binding so dimmed edges drop out:

```rust
let stroke_opacity = if edge_dimmed {
    "0.06".to_string()
} else if is_active {
    "0.85".to_string()
} else {
    "0.55".to_string()
};
```

(Update the `stroke_opacity: "{stroke_opacity}"` attribute is already present.)

- [ ] **Step 6: Force-show labels for the hover set**

In the label gate from Task 7 Step 5, fold hover into `forced`:

```rust
let forced = is_selected || highlight.as_ref().map_or(false, |h| h.contains(&idx));
```

- [ ] **Step 7: Verify it builds**

Run: `cd crates/memvault-web && dx build`
Expected: success.

- [ ] **Step 8: Manual check**

Hovering a node fades everything except it and its direct neighbors + connecting edges, and those neighbors' labels appear. Moving off restores the full graph.

- [ ] **Step 9: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/explorer.rs
git commit -m "feat(graph): hover highlights neighbors and dims the rest"
```

---

## Task 9: Detail panel readability

Make the right panel readable: wrapping header, property values that clamp with a tooltip + scroll instead of clipping.

**Files:**
- Modify: `src/ui/pages/graph/explorer.rs` — detail panel (≈lines 1450–1485)

- [ ] **Step 1: Let the header wrap**

The header `h3 { class: "h-card font-semibold", "{d.label}" }` (≈line 1462) clips long titles. Replace with a wrapping variant:

```rust
h3 { class: "h-card font-semibold break-words leading-snug", "{d.label}" }
```

- [ ] **Step 2: Make property values readable**

Replace the property loop (≈lines 1479–1484):

```rust
for (key, val) in &d.props {
    div { class: "flex justify-between text-sm py-0.5",
        span { class: "text-fg-muted truncate mr-2", "{key}" }
        span { class: "font-mono text-fg-strong truncate text-right", "{val}" }
    }
}
```

with a stacked key-over-value layout where the value clamps to a scrollable box and carries a full-text tooltip:

```rust
for (key, val) in &d.props {
    {
        let full = val.as_str().map(String::from).unwrap_or_else(|| val.to_string());
        rsx! {
            div { class: "py-1",
                div { class: "text-xs text-fg-muted", "{key}" }
                div {
                    class: "font-mono text-sm text-fg-strong break-words whitespace-pre-wrap \
                            max-h-24 overflow-y-auto",
                    title: "{full}",
                    "{full}"
                }
            }
        }
    }
}
```

(`max-h-24 overflow-y-auto` gives a scrollbar for long values; `break-words whitespace-pre-wrap` wraps instead of clipping; `title` is the hover tooltip with the complete value. The previous version rendered the raw `serde_json::Value` debug form for strings, leaving quotes — `as_str()` strips them when the value is a string.)

- [ ] **Step 3: Verify it builds**

Run: `cd crates/memvault-web && dx build`
Expected: success.

- [ ] **Step 4: Manual check**

Open a node with long properties (e.g. the `authors`/`doi`/`url` fields in the screenshots). Long values now wrap and scroll within the panel, hovering shows the full text, and the title no longer clips at the panel edge. Neighbor rows already show resolved names from Task 5 (no `entity:<hex>`).

- [ ] **Step 5: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/explorer.rs
git commit -m "feat(graph): readable detail panel (wrap header, scroll/tooltip values)"
```

---

## Task 10: Realize the seam — extract `canvas.rs` + `panel.rs` components

Move the SVG block and the detail panel out of `explorer.rs` into components so the renderer is swappable and `explorer.rs` shrinks. **Pure move-refactor — no behavior change.** Features already work after Task 9; this is the architectural finish.

**Files:**
- Modify: `src/ui/pages/graph/canvas.rs` — add `GraphCanvas` component
- Create: `src/ui/pages/graph/panel.rs` — `DetailPanel` + `NeighborEdgeRow`
- Modify: `src/ui/pages/graph/explorer.rs` — replace inlined blocks with the components
- Modify: `src/ui/pages/graph/mod.rs` — register `panel`

- [ ] **Step 1: Register the panel module**

Add to `src/ui/pages/graph/mod.rs`:

```rust
pub mod panel;
```

- [ ] **Step 2: Create `GraphCanvas` in `canvas.rs`**

Add a `#[component] pub fn GraphCanvas(...)` that owns the `svg { ... }` block. Give it the props the SVG block reads today (all `Signal<T>` are `Copy`):

```rust
use dioxus::prelude::*;
use super::controls::GraphSettings;
use super::layout_engine::{GraphEdge, GraphNode};

#[component]
pub fn GraphCanvas(
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
    settings: GraphSettings,
    zoom: f64,
    view_box: String,
    selected: Signal<Option<String>>,
    hovered: Signal<Option<usize>>,
    dragging_node: Signal<Option<usize>>,
    detail: Signal<Option<super::explorer::NodeDetail>>,
    sim: Signal<super::layout_engine::ForceSimulation>,
    viewport: Signal<super::explorer::Viewport>,
    panning: Signal<bool>,
    pan_start: Signal<(f64, f64)>,
    did_drag: Signal<bool>,
) -> Element {
    // MOVE the current `svg { ... }` block (explorer.rs ≈lines 1172–1439)
    // here verbatim, plus the event-handler closures it uses
    // (on_wheel, on_svg_mousedown, on_svg_mousemove, on_svg_mouseup) and
    // the `base_half`/`vb`/`cfg`/`highlight` locals it depends on,
    // rebuilt from the props above. `show_retracted` and `get_node_detail`
    // /`expand_node` are reached via `use super::explorer::...` and
    // `use_context` exactly as before.
    todo!("moved SVG block")
}
```

To make this compile, the items the SVG block references must be visible from `canvas.rs`:
- In `layout_engine.rs`, add `PartialEq` to the `derive(...)` on both `GraphNode` and `GraphEdge` (Dioxus component props require `PartialEq`; their `f64` fields support it). Confirm with `cargo test -p memvault-web --no-run`.
- In `explorer.rs`, change `struct NodeDetail`, `struct Viewport`, and the server fns `get_node_detail` / `expand_node` from private to `pub(crate)` (or `pub(super)`). `Viewport`'s fields (`zoom`, `offset_x`, `offset_y`) are currently private and are read inside the moved block — widen them (and any `Viewport` methods used, e.g. `fit_to_nodes`) to `pub(crate)` too. Same for any `NodeDetail` fields the panel reads.
- Note on cost: passing `nodes`/`edges` as `Vec<_>` by value clones them once per render. The current inline code already clones at the same point (`let all_nodes = s.nodes.clone();`, `explorer.rs:763-764`), so this is not a new clone per frame — it's the same one, now at the prop boundary. Acceptable at a few-hundred nodes; revisit if profiling shows it hot.
- Move the free helper fns the SVG uses — `display_kind_for`, `kind_variant`, `kind_svg_palette`, `kind_halo_color` — to `pub(crate)` (keep them in `explorer.rs` and `use super::explorer::...`, or relocate into `canvas.rs`; pick one and be consistent).

- [ ] **Step 3: Replace the inlined SVG in `explorer.rs`**

Delete the `svg { ... }` block from `explorer.rs` and render the component instead, inside the canvas `Card`:

```rust
GraphCanvas {
    nodes: nodes.clone(),
    edges: edges.clone(),
    settings: cfg,
    zoom: vp.zoom,
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
```

- [ ] **Step 4: Create `panel.rs` and move the detail panel**

Move the `if let Some(d) = &*detail.read() { ... }` block (the right-hand `div { class: "w-72 ..." }`) and the existing `NeighborEdgeRow` component out of `explorer.rs` into a `#[component] pub fn DetailPanel(...)` in `panel.rs`:

```rust
use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Card, Dot, Pill, PillVariant};
use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use super::explorer::{EdgeDetail, NodeDetail, get_node_detail};

#[component]
pub fn DetailPanel(
    detail: Signal<Option<NodeDetail>>,
    selected: Signal<Option<String>>,
    focus_node: Signal<Option<String>>,
) -> Element {
    // MOVE the right-panel block (explorer.rs ≈lines 1443–1572, including
    // the Task 9 readability changes) here verbatim. The `show_retracted`
    // context is fetched via `use_context` as in explorer.rs.
    todo!("moved detail panel")
}
```

Make `EdgeDetail`, `NodeDetail`, and `get_node_detail` `pub(crate)` in `explorer.rs`, and move `NeighborEdgeRow` into `panel.rs`.

- [ ] **Step 5: Replace the inlined panel in `explorer.rs`**

Delete the inlined panel block and render:

```rust
DetailPanel { detail, selected, focus_node }
```

- [ ] **Step 6: Verify it builds and tests pass**

Run: `cd crates/memvault-web && dx build`
Then: `cargo test -p memvault-web canvas:: controls::`
Expected: build succeeds; pure-fn tests still pass. Resolve visibility errors by widening `pub(crate)` on the moved items until it compiles.

- [ ] **Step 7: Manual regression check**

Re-verify every feature from Tasks 6–9 still works (settings panel, fade, hover-focus, readable detail panel, resolved names). Behavior must be identical — this task only relocates code.

- [ ] **Step 8: Commit**

```bash
git add crates/memvault-web/src/ui/pages/graph/
git commit -m "refactor(graph): extract GraphCanvas + DetailPanel (renderer seam)"
```

---

## Final verification

- [ ] `cargo test -p memvault-web` — all pure-fn tests pass (layout_engine, canvas, controls).
- [ ] `cd crates/memvault-web && dx build` — clean WASM build.
- [ ] Manual sweep on `/graph` against the reference vault:
  - Labels readable at 1.0× (no text wall); Text-fade slider behaves.
  - Node-size, Link-thickness, Arrows toggle all visibly work.
  - Center/Repel/Link/Link-distance sliders reshape the layout.
  - Hovering dims everything but the node + neighbors.
  - No raw `entity:<hex>` anywhere (canvas labels, sidebar, neighbor rows).
  - Detail panel: header wraps, long values scroll + tooltip.
  - Settings survive a page reload.
- [ ] Update the spec status if desired and open the PR from `viz`.
