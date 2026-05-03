use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn EntityDetail(id: String) -> Element {
    use_topbar("Entity");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Entity {id}" }
            p { class: "text-fg-muted", "Entity detail coming soon." }
        }
    }
}
