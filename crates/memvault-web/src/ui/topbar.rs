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
}

#[server]
async fn fetch_buckets() -> Result<Vec<BucketOption>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let buckets = client
        .bucket_list()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(buckets
        .iter()
        .map(|b| BucketOption {
            id_hex: hex::encode(b.id.0),
            name: b.name.clone(),
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
    let views_res = use_server_future(fetch_views)?;
    let buckets_res = use_server_future(fetch_buckets)?;

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
                                    rsx! { option { value: "{val}", selected: selected, "{b.name}" } }
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
