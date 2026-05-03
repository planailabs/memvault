//! Topbar component.

use dioxus::prelude::*;

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

    rsx! {
        header { class: "topbar",
            div { class: "flex items-center gap-3 px-5 py-3",
                h1 { class: "text-lg font-semibold text-fg-strong truncate", "{title}" }
            }
        }
    }
}
