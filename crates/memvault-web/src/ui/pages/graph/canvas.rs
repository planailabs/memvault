//! Renderer-agnostic graph helpers (the renderer "seam").
//!
//! Pure decision functions shared by the SVG renderer today and any
//! future Canvas2D renderer. No Dioxus, no DOM — just math and strings,
//! so they are unit-testable on the host target.

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
