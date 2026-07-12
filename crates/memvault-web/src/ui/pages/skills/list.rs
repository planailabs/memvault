//! Skill list page — shows all skills with a create form.

use dioxus::prelude::*;
use plan_ai_design::{
    Button, ButtonVariant, Card, DataTable, PageHeader, SortState, SortableTh, Td, TdMuted,
    page_window,
};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SkillRow {
    id_hex: String,
    name: String,
    description: String,
    trigger: String,
}

impl SkillRow {
    fn matches_search(&self, query: &str) -> bool {
        self.name.to_lowercase().contains(query)
            || self.description.to_lowercase().contains(query)
            || self.trigger.to_lowercase().contains(query)
            || self.id_hex.contains(query)
    }
}

#[server]
async fn list_skills() -> Result<Vec<SkillRow>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let skills = client
        .skill_list(500, None)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(skills
        .into_iter()
        .map(|s| SkillRow {
            id_hex: hex::encode(s.id.0),
            name: s.name,
            description: s.description.unwrap_or_default(),
            trigger: s.trigger.unwrap_or_default(),
        })
        .collect())
}

#[server]
async fn create_skill(
    name: String,
    description: String,
    trigger: String,
    body: String,
    bucket_hex: String,
) -> Result<String, ServerFnError> {
    let client = crate::ui::state::client()?;
    // Skills are entities, so a write needs a target bucket (the daemon refuses
    // unbucketed writes once any bucket exists). The UI passes the topbar's
    // active bucket.
    let bucket = memvault_core::BucketId::from_hex(&bucket_hex)
        .map_err(|_| ServerFnError::new("select a bucket to create a skill in".to_string()))?;
    let spec = memvault_api::SkillSpec {
        name,
        description: (!description.trim().is_empty()).then(|| description.trim().to_string()),
        trigger: (!trigger.trim().is_empty()).then(|| trigger.trim().to_string()),
        instruction_body: (!body.trim().is_empty()).then(|| body.clone()),
    };
    let id = client
        .skill_publish(spec, memvault_core::Visibility::Internal, Some(&bucket))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(hex::encode(id.0))
}

#[component]
pub fn SkillList() -> Element {
    use_topbar("Skills");
    let mut skills = use_server_future(list_skills)?;
    let active_bucket = use_context::<crate::ui::topbar::ActiveBucketSignal>();
    let mut show_create = use_signal(|| false);
    let mut new_name = use_signal(String::new);
    let mut new_desc = use_signal(String::new);
    let mut new_trigger = use_signal(String::new);
    let mut new_body = use_signal(String::new);
    let mut create_err = use_signal(String::new);

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center justify-between",
                PageHeader { class: "mb-0", "Skills" }
                Button {
                    variant: ButtonVariant::Primary,
                    onclick: move |_| show_create.toggle(),
                    if *show_create.read() { "Cancel" } else { "New Skill" }
                }
            }

            if *show_create.read() {
                Card {
                    div { class: "p-5 space-y-3",
                        div {
                            label { class: "text-xs text-fg-muted", "Name" }
                            input {
                                class: "input input-sm w-full mt-1",
                                r#type: "text",
                                placeholder: "e.g. Code Review",
                                value: "{new_name}",
                                oninput: move |e: Event<FormData>| new_name.set(e.value()),
                            }
                        }
                        div {
                            label { class: "text-xs text-fg-muted", "Description" }
                            input {
                                class: "input input-sm w-full mt-1",
                                r#type: "text",
                                placeholder: "One line — used for discovery",
                                value: "{new_desc}",
                                oninput: move |e: Event<FormData>| new_desc.set(e.value()),
                            }
                        }
                        div {
                            label { class: "text-xs text-fg-muted", "Trigger" }
                            input {
                                class: "input input-sm w-full mt-1",
                                r#type: "text",
                                placeholder: "When to use this skill",
                                value: "{new_trigger}",
                                oninput: move |e: Event<FormData>| new_trigger.set(e.value()),
                            }
                        }
                        div {
                            label { class: "text-xs text-fg-muted", "Instructions (SKILL.md body)" }
                            textarea {
                                class: "input input-sm w-full mt-1 font-mono",
                                rows: "6",
                                placeholder: "# Code Review\nRun the linter, then read the diff...",
                                value: "{new_body}",
                                oninput: move |e: Event<FormData>| new_body.set(e.value()),
                            }
                        }
                        if !create_err.read().is_empty() {
                            p { class: "text-danger text-sm", "{create_err}" }
                        }
                        div { class: "flex gap-2",
                            Button {
                                variant: ButtonVariant::Primary,
                                onclick: move |_| {
                                    let name = new_name.read().trim().to_string();
                                    if name.is_empty() { return; }
                                    let bucket_hex = active_bucket.read().id.clone().unwrap_or_default();
                                    if bucket_hex.is_empty() {
                                        create_err.set("Select a bucket (top bar) to create a skill in.".to_string());
                                        return;
                                    }
                                    let desc = new_desc.read().clone();
                                    let trig = new_trigger.read().clone();
                                    let body = new_body.read().clone();
                                    spawn(async move {
                                        match create_skill(name, desc, trig, body, bucket_hex).await {
                                            Ok(_) => {
                                                show_create.set(false);
                                                create_err.set(String::new());
                                                new_name.set(String::new());
                                                new_desc.set(String::new());
                                                new_trigger.set(String::new());
                                                new_body.set(String::new());
                                                skills.restart();
                                            }
                                            Err(e) => create_err.set(e.to_string()),
                                        }
                                    });
                                },
                                "Create"
                            }
                        }
                    }
                }
            }

            match &*skills.read() {
                Some(Ok(list)) if !list.is_empty() => rsx! {
                    SkillTable { list: list.clone() }
                },
                Some(Ok(_)) => rsx! {
                    Card {
                        div { class: "p-8 text-center text-fg-muted",
                            "No skills yet. Create one to get started."
                        }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", "Loading..." } },
            }
        }
    }
}

#[component]
fn SkillTable(list: ReadSignal<Vec<SkillRow>>) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 20usize);
    let page = use_signal(|| 0usize);
    let sort = use_signal::<SortState>(|| ("name".to_string(), true));

    let filtered = use_memo(move || {
        // Read `list` reactively so the table refreshes when the parent re-fetches.
        let list = list.read();
        let q = search.read().to_lowercase();
        let mut items: Vec<SkillRow> = if q.is_empty() {
            list.clone()
        } else {
            list.iter()
                .filter(|s| s.matches_search(&q))
                .cloned()
                .collect()
        };
        let (key, asc) = sort.read().clone();
        items.sort_by(|a, b| {
            let ord = match key.as_str() {
                "description" => a
                    .description
                    .to_lowercase()
                    .cmp(&b.description.to_lowercase()),
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            };
            if asc { ord } else { ord.reverse() }
        });
        items
    });

    let total = list.read().len();
    let filtered_count = filtered.read().len();
    let limit_val = *limit.read();
    let (start, shown) = page_window(*page.read(), limit_val, filtered_count);

    rsx! {
        DataTable {
            search, limit, page, total, filtered: filtered_count, shown,
            headers: rsx! {
                SortableTh { label: "Name".to_string(), sort_key: "name".to_string(), sort }
                SortableTh { label: "Description".to_string(), sort_key: "description".to_string(), sort }
                th { class: "th", "Trigger" }
            },
            body: rsx! {
                for s in filtered.read().iter().skip(start).take(limit_val) {
                    tr {
                        key: "{s.id_hex}",
                        class: "cursor-pointer hover:bg-surface-3",
                        onclick: {
                            let id = s.id_hex.clone();
                            move |_| {
                                navigator().push(Route::SkillDetail { id: id.clone() });
                            }
                        },
                        Td {
                            span { class: "font-medium text-fg-strong", "{s.name}" }
                        }
                        TdMuted { "{s.description}" }
                        TdMuted { "{s.trigger}" }
                    }
                }
            },
        }
    }
}
