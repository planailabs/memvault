//! Application shell: sidebar + topbar + main content.

use dioxus::prelude::*;
use dioxus_i18n::t;

use super::cmd_k::{CommandPalette, PaletteOpen};
use super::events::use_event_bus_provider;
use super::navbar::Sidebar;
use super::session::use_session_provider;
use super::topbar::{
    ActiveBucket, ActiveBucketSignal, ActiveView, ActiveViewSignal, ShowRetracted,
    ShowRetractedSignal, Topbar, TopbarMeta,
};

#[component]
pub fn Layout() -> Element {
    use_context_provider::<Signal<TopbarMeta>>(|| Signal::new(TopbarMeta::default()));
    use_context_provider::<PaletteOpen>(|| Signal::new(false));
    use_context_provider::<ActiveViewSignal>(|| Signal::new(ActiveView::default()));
    use_context_provider::<ActiveBucketSignal>(|| Signal::new(ActiveBucket::default()));
    use_context_provider::<ShowRetractedSignal>(|| Signal::new(ShowRetracted::default()));
    use_context_provider::<super::filters::FilterEpochSignal>(|| {
        Signal::new(super::filters::FilterEpoch::default())
    });
    let _event_bus = use_event_bus_provider();
    let _session = use_session_provider();

    rsx! {
        CommandPalette {}
        div { class: "flex h-screen bg-bg text-fg",
            Sidebar {}
            div { class: "flex-1 flex flex-col min-w-0",
                // Topbar has its own boundary: toggling a filter (e.g. Retracted)
                // restarts its bucket/view fetches, and without this the suspense
                // would bubble past the page boundary and blank the whole layout.
                // While re-fetching it shows a fixed-height placeholder bar.
                SuspenseBoundary {
                    fallback: |_| rsx! {
                        header { class: "topbar",
                            div { class: "flex items-center gap-3 px-5 py-3 h-[49px]" }
                        }
                    },
                    Topbar {}
                }
                main { class: "flex-1 overflow-y-auto p-5",
                    SuspenseBoundary {
                        fallback: |_| rsx! {
                            div { class: "flex items-center justify-center py-20",
                                div { class: "flex flex-col items-center gap-3",
                                    svg {
                                        class: "animate-spin h-8 w-8 text-brand",
                                        fill: "none",
                                        view_box: "0 0 24 24",
                                        circle {
                                            class: "opacity-25",
                                            cx: "12", cy: "12", r: "10",
                                            stroke: "currentColor", stroke_width: "4",
                                        }
                                        path {
                                            class: "opacity-75",
                                            fill: "currentColor",
                                            d: "M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z",
                                        }
                                    }
                                    span { class: "text-sm text-fg-muted", {t!("loading")} }
                                }
                            }
                        },
                        Outlet::<super::app::Route> {}
                    }
                }
            }
        }
    }
}
