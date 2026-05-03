use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn FileDetail(cid: String) -> Element {
    use_topbar("File");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "File {cid}" }
            p { class: "text-fg-muted", "File detail coming soon." }
        }
    }
}
