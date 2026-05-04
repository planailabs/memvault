//! Sidebar navigation.

use dioxus::prelude::*;

use super::app::Route;

#[component]
pub fn Sidebar() -> Element {
    rsx! {
        nav { class: "nav-side hidden xl:flex flex-col w-56 shrink-0 border-r border-line bg-surface-2 h-screen overflow-y-auto",
            // Logo area
            div { class: "px-4 py-4 border-b border-line",
                span { class: "text-lg font-bold text-fg-strong", "memvault" }
            }

            // Memory section
            div { class: "px-3 pt-4 pb-1",
                span { class: "kicker", "Memory" }
            }
            NavLink { to: Route::NoteList {}, label: "Notes" }
            NavLink { to: Route::GraphExplorer {}, label: "Graph" }
            NavLink { to: Route::FileExplorer {}, label: "Files" }
            NavLink { to: Route::VfsExplorer {}, label: "VFS" }

            // Operations section
            div { class: "px-3 pt-6 pb-1",
                span { class: "kicker", "Operations" }
            }
            NavLink { to: Route::AuditLog {}, label: "Audit" }
            NavLink { to: Route::ViewManager {}, label: "Views" }
            NavLink { to: Route::AdminDashboard {}, label: "Admin" }
        }
    }
}

#[component]
fn NavLink(to: Route, label: &'static str) -> Element {
    rsx! {
        Link { class: "nav-link", to,
            "{label}"
        }
    }
}
