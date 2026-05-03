use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn NoteList() -> Element {
    use_topbar("Notes");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Notes" }
            p { class: "text-fg-muted", "Note explorer coming soon." }
        }
    }
}
