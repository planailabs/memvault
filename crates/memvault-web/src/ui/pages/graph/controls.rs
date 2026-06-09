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
    pub repulsion: f64, // positive magnitude; engine uses positive = repulsive
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
        self.label_fade = self.label_fade.clamp(0.0, 1.0);
        self.node_scale = self.node_scale.clamp(0.25, 3.0);
        self.link_thickness = self.link_thickness.clamp(0.25, 4.0);
        self.center_strength = self.center_strength.clamp(0.0, 0.08);
        self.repulsion = self.repulsion.clamp(200.0, 6000.0);
        self.link_strength = self.link_strength.clamp(0.0, 0.4);
        self.link_distance = self.link_distance.clamp(30.0, 400.0);
    }

    /// Project the force fields onto the engine's `ForceParams`.
    pub fn to_force_params(&self) -> ForceParams {
        ForceParams {
            link_strength: self.link_strength,
            link_distance: self.link_distance,
            center_strength: self.center_strength,
            repulsion_strength: self.repulsion,
        }
    }
}

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

/// Floating, grouped settings panel (Display + Forces). Toggled by the
/// gear button in the toolbar. Mirrors Obsidian's graph controls.
#[component]
pub fn SettingsPanel(settings: Signal<GraphSettings>) -> Element {
    let s = *settings.read();
    rsx! {
        Card { class: "absolute top-2 right-2 z-10 w-64 p-3 space-y-3 shadow-lg max-h-[90%] overflow-y-auto",
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
    fn to_force_params_maps_repulsion() {
        let s = GraphSettings::default();
        let p = s.to_force_params();
        // Positive repulsion_strength repels (see ForceSimulation::tick); the
        // UI magnitude maps straight through, no negation.
        assert_eq!(p.repulsion_strength, 2000.0);
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
