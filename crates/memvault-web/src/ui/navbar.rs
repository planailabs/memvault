//! Sidebar navigation + the mobile drawer that mirrors it.
//!
//! The desktop sidebar is `hidden xl:flex`; below that breakpoint the
//! `MobileDrawer` (opened by the topbar hamburger via the shared
//! [`DrawerOpen`] signal) is the only navigation.

use dioxus::prelude::*;
use dioxus_i18n::t;

use super::app::Route;

/// Mobile drawer open state. A distinct newtype (not a bare
/// `Signal<bool>`) so it doesn't collide with other `Signal<bool>`
/// contexts — Dioxus keys context by type.
#[derive(Clone, Copy)]
pub struct DrawerOpen(pub Signal<bool>);

#[component]
pub fn Sidebar() -> Element {
    rsx! {
        nav { class: "nav-side hidden xl:flex flex-col w-56 shrink-0 border-r border-line bg-surface-2 h-screen overflow-y-auto",
            // Logo area
            div { class: "px-4 py-4 border-b border-line",
                span { class: "text-lg font-bold text-fg-strong", {t!("nav-brand")} }
            }
            NavLinks { on_navigate: |_| {} }
        }
    }
}

/// The nav sections + links, shared between the desktop sidebar and the
/// mobile drawer (which passes `on_navigate` to close itself).
#[component]
fn NavLinks(on_navigate: EventHandler<()>) -> Element {
    rsx! {
        // Memory section
        div { class: "px-3 pt-4 pb-1",
            span { class: "kicker", {t!("nav-section-memory")} }
        }
        NavLink { to: Route::NoteList {}, label: t!("nav-notes"), on_navigate }
        NavLink { to: Route::GraphExplorer {}, label: t!("nav-graph"), on_navigate }
        NavLink { to: Route::FileExplorer {}, label: t!("nav-files"), on_navigate }
        NavLink { to: Route::VfsExplorer {}, label: t!("nav-vfs"), on_navigate }
        NavLink { to: Route::BucketList {}, label: "Buckets".to_string(), on_navigate }
        NavLink { to: Route::SkillList {}, label: "Skills".to_string(), on_navigate }

        // Operations section
        div { class: "px-3 pt-6 pb-1",
            span { class: "kicker", {t!("nav-section-operations")} }
        }
        NavLink { to: Route::AuditLog {}, label: t!("nav-audit"), on_navigate }
        NavLink { to: Route::ViewManager {}, label: t!("nav-views"), on_navigate }
        NavLink { to: Route::AdminDashboard {}, label: t!("nav-admin"), on_navigate }
    }
}

#[component]
fn NavLink(to: Route, label: String, on_navigate: EventHandler<()>) -> Element {
    rsx! {
        Link { class: "nav-link", to,
            onclick: move |_| on_navigate.call(()),
            "{label}"
        }
    }
}

#[component]
pub fn MobileDrawer(is_open: Signal<bool>) -> Element {
    let open = *is_open.read();

    // Backdrop tints the canvas (matches the page theme rather than
    // contrasting it) so dark mode gets a dark scrim and light mode a
    // light one.
    let backdrop_cls = if open {
        "fixed inset-0 bg-bg/80 backdrop-blur-sm transition-opacity duration-300 z-40 opacity-100 pointer-events-auto"
    } else {
        "fixed inset-0 bg-bg/80 backdrop-blur-sm transition-opacity duration-300 z-40 opacity-0 pointer-events-none"
    };

    let drawer_cls = if open {
        "fixed inset-y-0 right-0 max-w-xs w-full bg-surface shadow-xl overflow-y-auto flex flex-col z-50 transform transition-transform duration-300 ease-in-out border-l border-line translate-x-0 pointer-events-auto"
    } else {
        "fixed inset-y-0 right-0 max-w-xs w-full bg-surface shadow-xl overflow-y-auto flex flex-col z-50 transform transition-transform duration-300 ease-in-out border-l border-line translate-x-full pointer-events-none"
    };

    rsx! {
        div { class: "xl:hidden relative z-50",
            // Backdrop — taps close the drawer.
            div {
                class: backdrop_cls,
                "aria-hidden": "true",
                onclick: move |_| is_open.set(false),
            }

            div { class: drawer_cls, id: "mobile-drawer",
                div { class: "px-4 py-3 border-b border-line flex items-center justify-between shrink-0",
                    span { class: "text-lg font-bold text-fg-strong", {t!("nav-brand")} }
                    button {
                        class: "nav-icon-btn",
                        "aria-label": t!("nav-close-menu"),
                        onclick: move |_| is_open.set(false),
                        svg {
                            class: "h-5 w-5",
                            fill: "none",
                            stroke: "currentColor",
                            view_box: "0 0 24 24",
                            path {
                                stroke_linecap: "round",
                                stroke_linejoin: "round",
                                stroke_width: "2",
                                d: "M6 18L18 6M6 6l12 12",
                            }
                        }
                    }
                }
                nav { class: "flex-1 overflow-y-auto pb-4",
                    NavLinks { on_navigate: move |_| is_open.set(false) }
                }
            }
        }
    }
}
