//! Topbar component.

use dioxus::prelude::*;

use super::cmd_k::PaletteOpen;

/// Metadata for the current page shown in the topbar.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TopbarMeta {
    pub title: String,
}

/// Set the topbar title for the current page.
pub fn use_topbar(title: &str) {
    let mut meta = use_context::<Signal<TopbarMeta>>();
    let title = title.to_string();
    use_effect(move || {
        meta.set(TopbarMeta {
            title: title.clone(),
        });
    });
}

#[component]
pub fn Topbar() -> Element {
    let meta = use_context::<Signal<TopbarMeta>>();
    let title = meta.read().title.clone();
    let mut palette_open = use_context::<PaletteOpen>();

    rsx! {
        header { class: "topbar",
            div { class: "flex items-center gap-3 px-5 py-3",
                h1 { class: "text-lg font-semibold text-fg-strong truncate flex-1", "{title}" }
                button {
                    class: "flex items-center gap-2 px-3 py-1.5 text-sm text-fg-muted bg-surface-2 border border-line rounded-md hover:border-brand transition-colors",
                    onclick: move |_| palette_open.set(true),
                    // Search icon (magnifying glass)
                    svg {
                        class: "w-4 h-4",
                        fill: "none",
                        stroke: "currentColor",
                        stroke_width: "2",
                        view_box: "0 0 24 24",
                        circle { cx: "11", cy: "11", r: "8" }
                        line { x1: "21", y1: "21", x2: "16.65", y2: "16.65" }
                    }
                    span { "Search" }
                    kbd { class: "hidden sm:inline text-[10px] text-fg-faint bg-surface px-1.5 py-0.5 rounded border border-line ml-1",
                        "\u{2318}K"
                    }
                }
            }
        }
    }
}
