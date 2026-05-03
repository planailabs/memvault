use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn NoteHistory(id: String) -> Element {
    use_topbar("Note History");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "History — {id}" }
            p { class: "text-fg-muted", "Note history coming soon." }
        }
    }
}
