//! Topbar component with theme toggle and language picker.

use dioxus::prelude::*;
use dioxus_i18n::{prelude::*, t, unic_langid::langid};
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

const LOCALES: &[(&str, &str)] = &[("en-US", "English"), ("de-DE", "Deutsch")];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ViewOption {
    name: String,
    tag_count: usize,
}

#[server]
async fn fetch_views() -> Result<Vec<ViewOption>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let views = client.list_views().await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(views.iter().map(|v| ViewOption {
        name: v.name.clone(),
        tag_count: v.tags.len(),
    }).collect())
}

#[component]
pub fn Topbar() -> Element {
    let meta = use_context::<Signal<TopbarMeta>>();
    let title = meta.read().title.clone();
    let mut palette_open = use_context::<PaletteOpen>();
    let mut active_view = use_context::<ActiveViewSignal>();
    let views_res = use_server_future(fetch_views)?;

    let current_name = active_view.read().name.clone().unwrap_or_else(|| t!("all"));

    let on_view_change = move |e: Event<FormData>| {
        let name = e.value();
        let all_label = t!("all");
        if name == all_label || name.is_empty() {
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

                // View selector
                div { class: "flex items-center gap-1 ml-auto",
                    select {
                        class: "input input-sm text-sm w-auto",
                        value: "{current_name}",
                        onchange: on_view_change,
                        option { value: "{t!(\"all\")}", {t!("all")} }
                        if let Some(Ok(views)) = &*views_res.read() {
                            for v in views {
                                option { value: "{v.name}", "{v.name} ({v.tag_count})" }
                            }
                        }
                    }
                }

                // Language picker
                LanguagePicker {}

                // Theme toggle
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

// ── Language Picker ─────────────────────────────────────────────────

#[component]
fn LanguagePicker() -> Element {
    let mut i18n = i18n();
    let current = i18n.language();
    let current_tag = current.to_string();

    let on_change = move |evt: Event<FormData>| {
        let val = evt.value();
        if val == "de-DE" {
            let _ = i18n.set_language(langid!("de-DE"));
        } else {
            let _ = i18n.set_language(langid!("en-US"));
        }
        document::eval(&format!(
            "try {{ localStorage.setItem('lang', '{}'); }} catch(e) {{}}",
            val
        ));
    };

    rsx! {
        div { class: "relative",
            label { class: "sr-only", r#for: "lang-picker", {t!("language-picker-label")} }
            select {
                id: "lang-picker",
                class: "appearance-none bg-transparent text-fg-muted hover:text-fg-strong text-sm rounded-md px-2 py-1.5 pr-6 cursor-pointer focus:outline-none focus:ring-2 focus:ring-info transition-colors",
                value: "{current_tag}",
                onchange: on_change,
                for &(tag, label) in LOCALES.iter() {
                    option {
                        key: "{tag}",
                        value: "{tag}",
                        selected: tag == current_tag,
                        "{label}"
                    }
                }
            }
            svg {
                class: "pointer-events-none absolute right-1 top-1/2 -translate-y-1/2 h-3 w-3 text-fg-faint",
                fill: "none",
                stroke: "currentColor",
                stroke_width: "2",
                view_box: "0 0 24 24",
                path { stroke_linecap: "round", stroke_linejoin: "round", d: "M19 9l-7 7-7-7" }
            }
        }
    }
}

// ── Theme Toggle ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum ThemeMode {
    System,
    Light,
    Dark,
}

impl ThemeMode {
    fn next(self) -> Self {
        match self {
            Self::System => Self::Light,
            Self::Light => Self::Dark,
            Self::Dark => Self::System,
        }
    }
}

#[component]
fn ThemeToggle() -> Element {
    let mut theme = use_signal(|| ThemeMode::System);

    use_effect(move || {
        spawn(async move {
            let result = document::eval(
                r#"
                try {
                    var t = localStorage.getItem('theme');
                    if (t === 'dark') return 'dark';
                    if (t === 'light') return 'light';
                    return 'system';
                } catch(e) { return 'system'; }
                "#,
            )
            .await;
            if let Ok(val) = result {
                if let Some(s) = val.as_str() {
                    theme.set(match s {
                        "dark" => ThemeMode::Dark,
                        "light" => ThemeMode::Light,
                        _ => ThemeMode::System,
                    });
                }
            }
        });
    });

    let toggle = move |_| {
        let next = theme().next();
        theme.set(next);
        let store = match next {
            ThemeMode::System => "localStorage.removeItem('theme');",
            ThemeMode::Light => "localStorage.setItem('theme', 'light');",
            ThemeMode::Dark => "localStorage.setItem('theme', 'dark');",
        };
        document::eval(&format!(
            r#"
            {store}
            var d = document.documentElement;
            var t = localStorage.getItem('theme');
            var dark = t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches);
            d.classList.toggle('dark', dark);
            d.style.colorScheme = dark ? 'dark' : 'light';
            "#
        ));
    };

    let aria = match theme() {
        ThemeMode::System => t!("theme-system"),
        ThemeMode::Light => t!("theme-light"),
        ThemeMode::Dark => t!("theme-dark"),
    };

    rsx! {
        button {
            class: "nav-icon-btn",
            onclick: toggle,
            "aria-label": aria.clone(),
            title: aria,
            ThemeIcon { mode: theme() }
        }
    }
}

#[component]
fn ThemeIcon(mode: ThemeMode) -> Element {
    match mode {
        ThemeMode::System => rsx! {
            svg {
                class: "h-5 w-5",
                fill: "none",
                stroke: "currentColor",
                stroke_width: "1.5",
                view_box: "0 0 24 24",
                rect { x: "2", y: "3", width: "20", height: "14", rx: "2", ry: "2" }
                line { x1: "8", y1: "21", x2: "16", y2: "21" }
                line { x1: "12", y1: "17", x2: "12", y2: "21" }
            }
        },
        ThemeMode::Light => rsx! {
            svg {
                class: "h-5 w-5",
                fill: "none",
                stroke: "currentColor",
                stroke_width: "2",
                view_box: "0 0 24 24",
                circle { cx: "12", cy: "12", r: "5" }
                line { x1: "12", y1: "1", x2: "12", y2: "3" }
                line { x1: "12", y1: "21", x2: "12", y2: "23" }
                line { x1: "4.22", y1: "4.22", x2: "5.64", y2: "5.64" }
                line { x1: "18.36", y1: "18.36", x2: "19.78", y2: "19.78" }
                line { x1: "1", y1: "12", x2: "3", y2: "12" }
                line { x1: "21", y1: "12", x2: "23", y2: "12" }
                line { x1: "4.22", y1: "19.78", x2: "5.64", y2: "18.36" }
                line { x1: "18.36", y1: "5.64", x2: "19.78", y2: "4.22" }
            }
        },
        ThemeMode::Dark => rsx! {
            svg {
                class: "h-5 w-5",
                fill: "none",
                stroke: "currentColor",
                stroke_width: "2",
                view_box: "0 0 24 24",
                path { d: "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" }
            }
        },
    }
}

#[server]
async fn get_view_tags(name: String) -> Result<Option<Vec<(String, String)>>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let view = client.get_view(&name).await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(view.map(|v| v.tags))
}
