//! Topbar component with view selector, theme toggle, and language picker.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{LanguagePicker, ThemeToggle};
use serde::{Deserialize, Serialize};

use super::cmd_k::PaletteOpen;

/// Metadata for the current page shown in the topbar.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TopbarMeta {
    pub title: String,
}

/// The active view filter — None means "All" (no filter).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActiveView {
    pub name: Option<String>,
    pub tags: Vec<(String, String)>,
}

/// Shared signal for the active view.
pub type ActiveViewSignal = Signal<ActiveView>;

/// The active bucket filter — None means "All buckets" (no filter).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActiveBucket {
    pub id: Option<String>,   // hex-encoded bucket_id
    pub name: Option<String>, // display name
}

/// Shared signal for the active bucket.
pub type ActiveBucketSignal = Signal<ActiveBucket>;

/// Global "show retracted" toggle (top bar). When true, every UI read passes
/// `include_retracted` so retracted entries are shown. Pages read this signal
/// in their data-fetch closures so flipping it re-fetches.
///
/// A distinct newtype (not a bare `Signal<bool>`) so it doesn't collide with
/// other `Signal<bool>` contexts (e.g. the command-palette open state) — Dioxus
/// keys context by type.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ShowRetracted(pub bool);
pub type ShowRetractedSignal = Signal<ShowRetracted>;

/// Set the topbar title for the current page.
pub fn use_topbar(title: &str) {
    let mut meta = use_context::<Signal<TopbarMeta>>();
    let title = title.to_string();
    use_effect(move || {
        meta.set(TopbarMeta {
            title: title.clone(),
        });
    });
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ViewOption {
    name: String,
    tag_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BucketOption {
    id_hex: String,
    name: String,
    /// True when this is a merged source (only surfaced while the "Retracted"
    /// toggle is on). Rendered with a "(merged)" suffix in the selector.
    merged: bool,
}

#[server]
async fn fetch_buckets(include_merged: bool) -> Result<Vec<BucketOption>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let buckets = client
        .bucket_list_filtered(include_merged)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(buckets
        .iter()
        .map(|b| BucketOption {
            id_hex: hex::encode(b.id.0),
            name: b.name.clone(),
            merged: b.merged_into.is_some(),
        })
        .collect())
}

#[server]
async fn fetch_views() -> Result<Vec<ViewOption>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let views = client
        .list_views()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(views
        .iter()
        .map(|v| ViewOption {
            name: v.name.clone(),
            tag_count: v.tags.len(),
        })
        .collect())
}

#[component]
pub fn Topbar() -> Element {
    let meta = use_context::<Signal<TopbarMeta>>();
    let title = meta.read().title.clone();
    let mut palette_open = use_context::<PaletteOpen>();
    let mut active_view = use_context::<ActiveViewSignal>();
    let mut active_bucket = use_context::<ActiveBucketSignal>();
    let mut show_retracted = use_context::<ShowRetractedSignal>();
    let views_res = use_server_future(fetch_views)?;
    // Surface merged buckets in the selector together with retracted entries —
    // both ride the "Retracted" toggle. Re-fetch when it flips.
    let mut buckets_res = use_server_future(move || {
        let include_merged = show_retracted().0;
        async move { fetch_buckets(include_merged).await }
    })?;
    use_effect(move || {
        let _ = show_retracted();
        buckets_res.restart();
    });

    let current_name = active_view
        .read()
        .name
        .clone()
        .unwrap_or_else(|| "All".to_string());
    let current_bucket = active_bucket
        .read()
        .name
        .clone()
        .unwrap_or_else(|| "All".to_string());

    let on_view_change = move |e: Event<FormData>| {
        let name = e.value();
        if name == "All" || name.is_empty() {
            active_view.set(ActiveView::default());
        } else {
            let view_name = name.clone();
            spawn(async move {
                if let Ok(Some(view)) = get_view_tags(view_name.clone()).await {
                    active_view.set(ActiveView {
                        name: Some(view_name),
                        tags: view,
                    });
                }
            });
        }
    };

    rsx! {
        header { class: "topbar",
            div { class: "flex items-center gap-3 px-5 py-3",
                h1 { class: "text-lg font-semibold text-fg-strong truncate", "{title}" }

                div { class: "flex items-center gap-1 ml-auto",
                    // Global "show retracted" toggle — applies to every UI read.
                    label {
                        class: "flex items-center gap-1.5 text-sm text-fg-muted cursor-pointer mr-1 whitespace-nowrap",
                        title: "Include retracted entries in all lists, search, and detail views",
                        input {
                            r#type: "checkbox",
                            checked: show_retracted().0,
                            onchange: move |e| show_retracted.set(ShowRetracted(e.checked())),
                        }
                        "Retracted"
                    }
                    // Bucket selector
                    select {
                        class: "input input-sm text-sm w-auto",
                        value: "{current_bucket}",
                        onchange: move |e: Event<FormData>| {
                            let val = e.value();
                            if val == "All" || val.is_empty() {
                                active_bucket.set(ActiveBucket::default());
                            } else {
                                // val is "id_hex:name"
                                let (id_hex, name) = val.split_once(':').unwrap_or((&val, &val));
                                active_bucket.set(ActiveBucket {
                                    id: Some(id_hex.to_string()),
                                    name: Some(name.to_string()),
                                });
                            }
                        },
                        option { value: "All", selected: active_bucket.read().id.is_none(), "All buckets" }
                        if let Some(Ok(buckets)) = &*buckets_res.read() {
                            for b in buckets {
                                {
                                    let val = format!("{}:{}", b.id_hex, b.name);
                                    let selected = active_bucket.read().id.as_deref() == Some(b.id_hex.as_str());
                                    let label = if b.merged { format!("{} (merged)", b.name) } else { b.name.clone() };
                                    rsx! { option { value: "{val}", selected: selected, "{label}" } }
                                }
                            }
                        }
                    }
                    // View selector
                    select {
                        class: "input input-sm text-sm w-auto",
                        value: "{current_name}",
                        onchange: on_view_change,
                        option { value: "All", selected: active_view.read().name.is_none(), {t!("all")} }
                        if let Some(Ok(views)) = &*views_res.read() {
                            for v in views {
                                option { value: "{v.name}", selected: active_view.read().name.as_deref() == Some(v.name.as_str()), "{v.name} ({v.tag_count})" }
                            }
                        }
                    }
                }

                SessionBadge {}
                LanguagePicker {}
                ThemeToggle {}

                button {
                    class: "flex items-center gap-2 px-3 py-1.5 text-sm text-fg-muted bg-surface-2 border border-line rounded-md hover:border-brand transition-colors",
                    onclick: move |_| palette_open.set(true),
                    svg {
                        class: "w-4 h-4",
                        fill: "none",
                        stroke: "currentColor",
                        stroke_width: "2",
                        view_box: "0 0 24 24",
                        circle { cx: "11", cy: "11", r: "8" }
                        line { x1: "21", y1: "21", x2: "16.65", y2: "16.65" }
                    }
                    span { {t!("topbar-search")} }
                    kbd { class: "hidden sm:inline text-[10px] text-fg-faint bg-surface px-1.5 py-0.5 rounded border border-line ml-1",
                        {t!("topbar-shortcut")}
                    }
                }

                MobileMenuButton {}
            }
        }
    }
}

/// Hamburger for the mobile drawer — visible below `xl` only, where the
/// desktop sidebar is hidden.
#[component]
fn MobileMenuButton() -> Element {
    let mut drawer = use_context::<super::navbar::DrawerOpen>();
    let open = *drawer.0.read();
    rsx! {
        button {
            class: "xl:hidden nav-icon-btn",
            "aria-expanded": "{open}",
            "aria-controls": "mobile-drawer",
            "aria-label": t!("nav-open-menu"),
            onclick: move |_| drawer.0.set(!open),
            svg {
                class: "h-5 w-5",
                fill: "none",
                stroke: "currentColor",
                view_box: "0 0 24 24",
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5",
                }
            }
        }
    }
}

#[server]
async fn get_view_tags(name: String) -> Result<Option<Vec<(String, String)>>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let view = client
        .get_view(&name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(view.map(|v| v.tags))
}

/// "Logged in as <agent_id>" chip. Reads from the SessionSignal that
/// Layout installs via use_session_provider().
#[component]
fn SessionBadge() -> Element {
    use super::session::{SessionState, use_session};
    let session = use_session();
    let state = session.read().clone();

    let (label, tone): (String, &'static str) = match state {
        SessionState::Loading => ("…".to_string(), "text-fg-faint"),
        SessionState::Active(info) => (info.agent_id, "text-fg-muted"),
        SessionState::Failed(_) => ("session unavailable".to_string(), "text-warn"),
    };

    rsx! {
        span {
            class: "text-xs whitespace-nowrap px-2 py-1 rounded-md bg-surface-2 border border-line {tone}",
            title: "Active session identity",
            "{label}"
        }
    }
}
