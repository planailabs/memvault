use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn SearchPage() -> Element {
    use_topbar("Search");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Search" }
            p { class: "text-fg-muted", "Search page coming soon." }
        }
    }
}
