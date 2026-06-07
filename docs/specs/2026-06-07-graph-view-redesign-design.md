# Knowledge Graph View Redesign — Design

- **Date:** 2026-06-07
- **Branch:** `viz`
- **Status:** Approved
- **Area:** `crates/memvault-web/src/ui/pages/graph/`

## Problem

The web UI knowledge graph (`/graph`) is unusable at real data volumes (261 nodes /
580 edges in the reference vault):

1. **Text soup.** Every node's label renders as live SVG at all times, so hundreds of
   overlapping titles cover the canvas and nothing is readable.
2. **No exploration controls.** Only three force sliders (link / center / repel) are
   exposed in a cramped horizontal bar. There is no way to toggle arrows, fade labels,
   scale nodes/links, or set link distance — the parameters needed to navigate dense
   graphs (cf. Obsidian's graph view).
3. **Raw refs leak into the UI.** Nodes and neighbor rows that lack a `name`/`title`
   prop fall through to a long `entity:<hex>` ref that overflows the screen.
4. **Detail panel overflow.** Property values and neighbor labels are single-line
   `truncate`d; long values are clipped with no way to read the full text.

## Goals

Make the graph a usable knowledge-exploration surface: readable at any zoom, navigable
clusters and connections, resolvable node names everywhere, and a readable detail panel.

## Non-goals

- Migrating the renderer to Canvas2D/WebGL. We enhance the existing SVG renderer now and
  leave a clean seam to evaluate a Canvas renderer later if perf still falls short.
- Persisting graph parameters server-side or per named View. Settings are browser-local
  (localStorage) for this iteration.

## Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Renderer | Enhance SVG now; isolate drawing behind one seam for a possible later swap. |
| Controls location | Collapsible, grouped settings panel floating over the canvas (gear toggle). |
| Persistence | Browser-local `localStorage`. No server/View-model changes. |
| Unnamed-node label | `<kind> · <short-id>` (e.g. `paper · 08a5c9`). Full ref stays on hover. |
| Hover behavior | Hovering a node highlights it + direct neighbors/links and dims the rest. |

## Architecture

### Module split

`explorer.rs` (currently 1633 lines) does data loading, state, rendering, controls, and
the detail panel in one file. Split so the renderer is swappable and each file has one
job:

| File | Responsibility |
|---|---|
| `explorer.rs` | Page shell, server data loading, top-level state/signals, event wiring. |
| `controls.rs` *(new)* | `GraphSettings` param struct, the settings panel UI, localStorage load/save. |
| `canvas.rs` *(new)* | All SVG drawing — nodes, edges, labels, hover-focus. Consumes a single `GraphParams` input. **The renderer seam.** |
| `panel.rs` *(new)* | The graph's inline node-detail panel, extracted from `explorer.rs` and overhauled. (The standalone entity page `detail.rs` is unrelated and untouched.) |
| `layout_engine.rs` *(existing)* | Force simulation. `link_distance` already present in the working tree; gains a unit test. |

The seam: `canvas.rs` exposes one component that takes the node/edge slices plus a
`GraphParams` value (display settings + current zoom + hover/selection state) and emits
the SVG. Nothing outside `canvas.rs` knows it is SVG. A future Canvas2D renderer
implements the same input contract.

### Parameter model

A single serde struct, persisted to `localStorage["memvault.graph.settings"]`:

```rust
struct GraphSettings {
    // Display
    show_arrows: bool,        // default true
    label_fade: f64,          // 0.0 (always show) .. 1.0 (only when zoomed in); default 0.5
    node_scale: f64,          // 0.25 .. 3.0; default 1.0  (multiplies node radius)
    link_thickness: f64,      // 0.25 .. 4.0; default 1.0  (multiplies edge stroke width)
    // Forces (live-applied; reheats sim on change)
    center_strength: f64,     // 0.0 .. 0.08; default 0.01
    repulsion: f64,           // 200 .. 6000; default 2000 (negated internally)
    link_strength: f64,       // 0.0 .. 0.4;  default 0.08
    link_distance: f64,       // 30 .. 400;   default 200
}
```

The Forces fields map onto the existing `ForceParams` (extended with `link_distance`).
The Display fields are renderer-only. A **Reset** action restores `Default::default()`.

### Settings panel UI (`controls.rs`)

A gear icon on the canvas toggles a compact panel floating over a canvas corner,
replacing the current horizontal forces bar (`forces_open`). Two collapsible sections:

- **Display** — Show arrows (toggle), Text fade threshold, Node size, Link thickness.
- **Forces** — Center force, Repel force, Link force, Link distance.

Each control is a labeled slider/toggle with its live value shown. Force changes reheat
the simulation (existing `force_params` effect path); display changes are immediate and
require no reheat.

## Feature: Label level-of-detail

The central readability fix. Replace "always render every label" with a pure predicate
decided per node each render:

```rust
fn should_show_label(
    zoom: f64,
    radius: f64,
    fade_threshold: f64,
    forced: bool, // selected || hovered || focused || neighbor-highlighted
) -> bool {
    forced || (zoom * radius) >= fade_scale(fade_threshold)
}
```

`fade_scale` maps the `0.0..1.0` slider to a world-space cutoff: at `0.0` every label
shows; at `1.0` only the largest hubs show, and only when zoomed in. Because node radius
already scales with edge count, hubs label first — which is the useful default.

Labels also get a **max width with ellipsis** so a single long title cannot sprawl across
the canvas (the full title remains available via the detail panel and hover).

`should_show_label` and `fade_scale` are pure functions in `canvas.rs`, unit-tested.

## Feature: Hover-focus highlighting

Hovering a node sets a transient `hovered: Option<usize>` signal. While set:

- The hovered node, its directly connected edges, and its neighbor nodes render at full
  opacity; their labels are force-shown (`forced = true`).
- All other nodes/edges/labels drop to a low opacity (e.g. ~0.15).

Leaving the node clears the signal and restores normal rendering. This is pure visual
state — no data reload, no layout change, no server call. Neighbor adjacency is derived
once per render from the visible edge list.

## Feature: Node name resolution

A single shared resolver used by the canvas labels, the sidebar list, and the
detail-panel neighbor rows:

```
name → title → kind-derived → "<kind> · <short-id>"
```

- When an entity/doc/file resolves a `name` or `title`, use it (current behavior).
- When it does not, fall back to `"<kind> · <short-id>"` (e.g. `paper · 08a5c9`) instead
  of the raw `entity:<hex>` ref. `short-id` is the first 6 hex chars of the ref.
- The full ref stays available on hover and in the detail panel's id field.

This closes the resolution-fallback gap in `get_node_detail` (the `entity:{short}…`
branch) and the equivalent server-side label resolution in `list_graph_nodes`, and is
applied consistently so no long hash reaches the canvas, sidebar, or edge rows.

The fallback formatting is a pure function, unit-tested.

## Feature: Detail panel readability (`panel.rs`)

- **Header** — node name wraps (no truncation) instead of clipping at the panel edge.
- **Properties** — each value clamps to ~2 lines (CSS line-clamp) with the full text in a
  hover `title` tooltip; values longer than that render in a scrollable max-height box.
  Nothing overflows the panel; everything is reachable by scroll or tooltip.
- **Incoming / Outgoing** — already resolve names (now via the shared resolver); ensure
  rows clamp cleanly and keep the existing hover card showing kind + full id.
- **Focus on this node** — unchanged (works well). "Show All" / clear-focus stays visible
  while a focus is active.

## Persistence

- On mount, load `GraphSettings` from `localStorage["memvault.graph.settings"]`; fall
  back to `Default` on absence or parse error.
- On any setting change, save (debounced) back to localStorage.
- **Reset** restores defaults in state and storage.
- No server, API, or View-model changes.

## Testing

- **Unit tests (pure functions):**
  - `should_show_label` / `fade_scale` — label visibility across zoom × radius × threshold,
    including `forced` override.
  - Name resolver fallback — `name`/`title` present vs. absent → `<kind> · <short-id>`.
  - `link_distance` term in `layout_engine.rs` — springs relax toward the configured
    distance (extend existing layout-engine tests).
- **Manual verification:** `cd crates/memvault-web && dx build`, then run the app and
  confirm against the reference vault: labels readable at 1.0×, fade slider behaves,
  hover dims correctly, no raw hashes anywhere, detail panel values reachable, settings
  survive reload.

## Risks / open questions

- **SVG perf ceiling.** LOD + culling should make a few hundred nodes smooth in SVG. If a
  vault pushes into thousands of nodes and it janks, the `canvas.rs` seam lets us swap in
  a Canvas2D renderer without touching the rest. Out of scope now; the seam de-risks it.
- **Fade-threshold tuning.** The `fade_scale` mapping needs hand-tuning against the
  reference vault so the mid default is sensible; cheap to iterate.

## Files touched

- `crates/memvault-web/src/ui/pages/graph/explorer.rs` — slim down to shell + state.
- `crates/memvault-web/src/ui/pages/graph/controls.rs` — **new**.
- `crates/memvault-web/src/ui/pages/graph/canvas.rs` — **new**.
- `crates/memvault-web/src/ui/pages/graph/panel.rs` — **new** (inline detail panel, extracted + overhauled).
- `crates/memvault-web/src/ui/pages/graph/layout_engine.rs` — `link_distance` unit test.
- `crates/memvault-web/src/ui/pages/graph/mod.rs` — module wiring.
- `crates/memvault-web/src/ui/en-US.ftl`, `de-DE.ftl` — new control labels.
