//! Sidebar navigation.

use dioxus::prelude::*;
use dioxus_i18n::t;

use super::app::Route;

#[component]
pub fn Sidebar() -> Element {
    rsx! {
        nav { class: "nav-side hidden xl:flex flex-col w-56 shrink-0 border-r border-line bg-surface-2 h-screen overflow-y-auto",
            // Logo area
            div { class: "px-4 py-4 border-b border-line",
                span { class: "text-lg font-bold text-fg-strong", {t!("nav-brand")} }
            }

            // Memory section
            div { class: "px-3 pt-4 pb-1",
                span { class: "kicker", {t!("nav-section-memory")} }
            }
            NavLink { to: Route::NoteList {}, label: t!("nav-notes") }
            NavLink { to: Route::GraphExplorer {}, label: t!("nav-graph") }
            NavLink { to: Route::FileExplorer {}, label: t!("nav-files") }
            NavLink { to: Route::VfsExplorer {}, label: t!("nav-vfs") }

            // Operations section
            div { class: "px-3 pt-6 pb-1",
                span { class: "kicker", {t!("nav-section-operations")} }
            }
            NavLink { to: Route::AuditLog {}, label: t!("nav-audit") }
            NavLink { to: Route::ViewManager {}, label: t!("nav-views") }
            NavLink { to: Route::AdminDashboard {}, label: t!("nav-admin") }
        }
    }
}

#[component]
fn NavLink(to: Route, label: String) -> Element {
    rsx! {
        Link { class: "nav-link", to,
            "{label}"
        }
    }
}
