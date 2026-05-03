use dioxus::prelude::*;
use crate::ui::topbar::use_topbar;

#[component]
pub fn AuditLog() -> Element {
    use_topbar("Audit");
    rsx! {
        div { class: "space-y-4",
            h2 { class: "h-page", "Audit Trail" }
            p { class: "text-fg-muted", "Audit log coming soon." }
        }
    }
}
