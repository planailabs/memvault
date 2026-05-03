use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn TokenManagement() -> Element {
    use_topbar("Tokens");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "API Tokens" }
            p { class: "text-fg-muted", "Token management coming soon." }
        }
    }
}
