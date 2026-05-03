use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn FileExplorer() -> Element {
    use_topbar("Files");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Files" }
            p { class: "text-fg-muted", "File explorer coming soon." }
        }
    }
}
