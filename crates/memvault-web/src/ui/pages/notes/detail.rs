use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn NoteDetail(id: String) -> Element {
    use_topbar("Note");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Note {id}" }
            p { class: "text-fg-muted", "Note detail coming soon." }
        }
    }
}
