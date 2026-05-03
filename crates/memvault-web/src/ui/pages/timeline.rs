use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn Timeline() -> Element {
    use_topbar("Timeline");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Timeline" }
            p { class: "text-fg-muted", "Timeline coming soon." }
        }
    }
}
