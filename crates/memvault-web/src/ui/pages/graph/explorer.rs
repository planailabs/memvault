use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn GraphExplorer() -> Element {
    use_topbar("Graph");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Knowledge Graph" }
            p { class: "text-fg-muted", "Graph explorer coming soon." }
        }
    }
}
