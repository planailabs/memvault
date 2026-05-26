//! View management page — create, edit, and delete saved tag filter sets.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Button, ButtonVariant, Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};

use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ViewData {
    name: String,
    tags: Vec<(String, String)>,
}

#[server]
async fn list_all_views() -> Result<Vec<ViewData>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let views = client
        .list_views()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(views
        .into_iter()
        .map(|v| ViewData {
            name: v.name,
            tags: v.tags,
        })
        .collect())
}

#[server]
async fn save_view(name: String, tags: Vec<(String, String)>) -> Result<(), ServerFnError> {
    let client = crate::ui::state::client()?;
    let view = memvault_api::View {
        name,
        tags,
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    // Use update_view which does delete + create.
    client
        .update_view(view)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server]
async fn remove_view(name: String) -> Result<(), ServerFnError> {
    let client = crate::ui::state::client()?;
    client
        .delete_view(&name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[component]
pub fn ViewManager() -> Element {
    use_topbar(&t!("views-title"));
    let views = use_server_future(list_all_views)?;
    let mut editing = use_signal(|| None::<String>); // view name being edited
    let mut show_create = use_signal(|| false);

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center justify-between",
                PageHeader { class: "mb-0", {t!("views-title")} }
                Button {
                    variant: ButtonVariant::Primary,
                    onclick: move |_| show_create.set(true),
                    {t!("views-new")}
                }
            }

            p { class: "text-sm text-fg-muted",
                {t!("views-description")}
            }

            // Create form
            if *show_create.read() {
                Card {
                    div { class: "p-5",
                        ViewForm {
                            initial_name: String::new(),
                            initial_tags: vec![],
                            on_save: move |_| show_create.set(false),
                            on_cancel: move |_| show_create.set(false),
                        }
                    }
                }
            }

            // View list
            match &*views.read() {
                Some(Ok(list)) if !list.is_empty() => rsx! {
                    div { class: "space-y-3",
                        for view in list {
                            Card {
                                div { class: "p-5",
                                    if editing.read().as_ref() == Some(&view.name) {
                                        ViewForm {
                                            initial_name: view.name.clone(),
                                            initial_tags: view.tags.clone(),
                                            on_save: move |_| editing.set(None),
                                            on_cancel: move |_| editing.set(None),
                                        }
                                    } else {
                                        div { class: "flex items-center justify-between",
                                            div {
                                                h3 { class: "font-semibold text-fg-strong", "{view.name}" }
                                                div { class: "flex flex-wrap gap-1 mt-1",
                                                    for (scope, label) in &view.tags {
                                                        Pill { variant: PillVariant::Muted, "{scope}:{label}" }
                                                    }
                                                    if view.tags.is_empty() {
                                                        span { class: "text-sm text-fg-faint", {t!("views-no-tags")} }
                                                    }
                                                }
                                            }
                                            div { class: "flex gap-2 shrink-0",
                                                {
                                                    let name = view.name.clone();
                                                    rsx! {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            onclick: move |_| editing.set(Some(name.clone())),
                                                            {t!("edit")}
                                                        }
                                                    }
                                                }
                                                {
                                                    let name = view.name.clone();
                                                    rsx! {
                                                        Button {
                                                            variant: ButtonVariant::Danger,
                                                            onclick: move |_| {
                                                                let name = name.clone();
                                                                spawn(async move {
                                                                    let _ = remove_view(name).await;
                                                                });
                                                            },
                                                            {t!("delete")}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                Some(Ok(_)) => rsx! {
                    Card {
                        div { class: "p-8 text-center text-fg-muted",
                            {t!("views-empty")}
                        }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
            }
        }
    }
}

#[component]
fn ViewForm(
    initial_name: String,
    initial_tags: Vec<(String, String)>,
    on_save: EventHandler<()>,
    on_cancel: EventHandler<()>,
) -> Element {
    let is_edit = !initial_name.is_empty();
    let mut name_input = use_signal(|| initial_name.clone());
    let mut tag_input = use_signal(|| {
        initial_tags
            .iter()
            .map(|(s, l)| format!("{s}:{l}"))
            .collect::<Vec<_>>()
            .join(", ")
    });
    let mut status = use_signal(|| None::<String>);

    let do_save = move |_| {
        let name = name_input.read().trim().to_string();
        if name.is_empty() {
            status.set(Some(t!("views-name-required")));
            return;
        }
        let tags: Vec<(String, String)> = tag_input
            .read()
            .split(',')
            .filter_map(|t| {
                let t = t.trim();
                let (s, l) = t.split_once(':')?;
                Some((s.trim().to_string(), l.trim().to_string()))
            })
            .collect();

        spawn(async move {
            match save_view(name, tags).await {
                Ok(()) => on_save.call(()),
                Err(e) => status.set(Some(format!("Error: {e}"))),
            }
        });
    };

    rsx! {
        div { class: "space-y-3",
            SectionHeading { if is_edit { {t!("views-edit")} } else { {t!("views-new")} } }
            div {
                label { class: "text-xs text-fg-muted", {t!("files-th-name")} }
                input {
                    class: "input input-sm w-full mt-1",
                    r#type: "text",
                    placeholder: t!("views-placeholder-name"),
                    value: "{name_input}",
                    disabled: is_edit,
                    oninput: move |e: Event<FormData>| name_input.set(e.value()),
                }
            }
            div {
                label { class: "text-xs text-fg-muted", {t!("views-tags-label")} }
                input {
                    class: "input input-sm w-full mt-1",
                    r#type: "text",
                    placeholder: t!("views-placeholder-tags"),
                    value: "{tag_input}",
                    oninput: move |e: Event<FormData>| tag_input.set(e.value()),
                }
            }
            div { class: "flex gap-2",
                Button { variant: ButtonVariant::Primary, onclick: do_save,
                    if is_edit { {t!("save")} } else { {t!("views-create")} }
                }
                Button { variant: ButtonVariant::Secondary, onclick: move |_| on_cancel.call(()),
                    {t!("cancel")}
                }
            }
            if let Some(msg) = &*status.read() {
                p { class: "text-xs text-danger", "{msg}" }
            }
        }
    }
}
