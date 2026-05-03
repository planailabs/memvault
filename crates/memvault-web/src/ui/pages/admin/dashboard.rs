use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn AdminDashboard() -> Element {
    use_topbar("Admin");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Administration" }
            p { class: "text-fg-muted", "Admin dashboard coming soon." }
        }
    }
}
