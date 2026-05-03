use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn NoteForm() -> Element {
    use_topbar("New Note");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "New Note" }
            p { class: "text-fg-muted", "Note form coming soon." }
        }
    }
}
