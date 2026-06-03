//! Skill detail page — manifest, rename/delete actions, and resource management.

use dioxus::prelude::*;
use plan_ai_design::{Button, ButtonVariant, Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ResourceRow {
    edge_hex: String,
    node: String,
    relation: String,
    path: String,
    executable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SkillDetailData {
    id_hex: String,
    name: String,
    description: String,
    trigger: String,
    instructions: Vec<ResourceRow>,
    resources: Vec<ResourceRow>,
    requires: Vec<ResourceRow>,
}

#[server]
async fn get_skill(id: String) -> Result<Option<SkillDetailData>, ServerFnError> {
    let entity_id = memvault_core::EntityId::from_hex(&id)
        .map_err(|e| ServerFnError::new(format!("bad id: {e}")))?;
    let client = crate::ui::state::client()?;
    let bundle = client
        .skill_get(&entity_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let map = |r: memvault_api::SkillResource| ResourceRow {
        edge_hex: hex::encode(r.edge_id.0),
        node: r.node,
        relation: r.relation,
        path: r.path.unwrap_or_default(),
        executable: r.executable,
    };
    Ok(bundle.map(|b| SkillDetailData {
        id_hex: hex::encode(b.info.id.0),
        name: b.info.name,
        description: b.info.description.unwrap_or_default(),
        trigger: b.info.trigger.unwrap_or_default(),
        instructions: b.instructions.into_iter().map(map).collect(),
        resources: b.resources.into_iter().map(map).collect(),
        requires: b.requires.into_iter().map(map).collect(),
    }))
}

#[server]
async fn rename_skill(id: String, new_name: String) -> Result<(), ServerFnError> {
    let entity_id = memvault_core::EntityId::from_hex(&id)
        .map_err(|e| ServerFnError::new(format!("bad id: {e}")))?;
    let client = crate::ui::state::client()?;
    client
        .skill_rename(&entity_id, &new_name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server]
async fn delete_skill(id: String) -> Result<(), ServerFnError> {
    let entity_id = memvault_core::EntityId::from_hex(&id)
        .map_err(|e| ServerFnError::new(format!("bad id: {e}")))?;
    let client = crate::ui::state::client()?;
    client
        .skill_delete(&entity_id, "deleted via web UI")
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server]
async fn link_resource(
    id: String,
    node: String,
    relation: String,
    path: String,
    executable: bool,
) -> Result<(), ServerFnError> {
    let entity_id = memvault_core::EntityId::from_hex(&id)
        .map_err(|e| ServerFnError::new(format!("bad id: {e}")))?;
    let target = memvault_core::NodeRef::from_tag_label(&node)
        .ok_or_else(|| ServerFnError::new("node must be 'type:hex'".to_string()))?;
    let client = crate::ui::state::client()?;
    client
        .skill_link_resource(
            &entity_id,
            &target,
            &relation,
            (!path.trim().is_empty()).then(|| path.trim()),
            executable,
            memvault_core::Visibility::Internal,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
}

#[server]
async fn unlink_resource(id: String, edge_hex: String) -> Result<(), ServerFnError> {
    let entity_id = memvault_core::EntityId::from_hex(&id)
        .map_err(|e| ServerFnError::new(format!("bad id: {e}")))?;
    let bytes = hex::decode(&edge_hex).map_err(|e| ServerFnError::new(format!("bad edge: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ServerFnError::new("edge id must be 32 bytes".to_string()))?;
    let client = crate::ui::state::client()?;
    client
        .skill_unlink_resource(&entity_id, &memvault_core::EdgeId(arr))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[component]
pub fn SkillDetail(id: String) -> Element {
    use_topbar("Skill");
    let fetch_id = id.clone();
    let mut skill = use_server_future(move || {
        let id = fetch_id.clone();
        async move { get_skill(id).await }
    })?;

    let data = match &*skill.read() {
        Some(Ok(Some(d))) => d.clone(),
        Some(Ok(None)) => {
            return rsx! { p { class: "text-fg-muted", "Skill not found." } };
        }
        Some(Err(e)) => {
            return rsx! { p { class: "text-danger", "Error: {e}" } };
        }
        None => {
            return rsx! { p { class: "text-fg-muted", "Loading..." } };
        }
    };

    let mut rename_value = use_signal(|| data.name.clone());

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center gap-3",
                PageHeader { class: "mb-0", "{data.name}" }
                Pill { variant: PillVariant::Info, "skill" }
            }

            // Metadata card
            Card {
                div { class: "p-5 space-y-2",
                    SectionHeading { "Manifest" }
                    div { class: "grid grid-cols-2 gap-2 text-sm",
                        span { class: "text-fg-muted", "ID" }
                        span { class: "font-mono text-xs", "{data.id_hex}" }
                        span { class: "text-fg-muted", "Description" }
                        span { {if data.description.is_empty() { "—".to_string() } else { data.description.clone() }} }
                        span { class: "text-fg-muted", "Trigger" }
                        span { {if data.trigger.is_empty() { "—".to_string() } else { data.trigger.clone() }} }
                    }
                }
            }

            // Actions card (rename / delete)
            Card {
                div { class: "p-5 space-y-3",
                    SectionHeading { "Actions" }
                    div { class: "flex items-end gap-2",
                        div { class: "flex-1",
                            label { class: "text-xs text-fg-muted", "Rename" }
                            input {
                                class: "input input-sm w-full mt-1",
                                r#type: "text",
                                value: "{rename_value}",
                                oninput: move |e: Event<FormData>| rename_value.set(e.value()),
                            }
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            onclick: {
                                let sid = data.id_hex.clone();
                                move |_| {
                                    let sid = sid.clone();
                                    let name = rename_value.read().trim().to_string();
                                    if name.is_empty() { return; }
                                    spawn(async move {
                                        if rename_skill(sid, name).await.is_ok() {
                                            skill.restart();
                                        }
                                    });
                                }
                            },
                            "Save"
                        }
                        Button {
                            variant: ButtonVariant::Danger,
                            onclick: {
                                let sid = data.id_hex.clone();
                                move |_| {
                                    let sid = sid.clone();
                                    spawn(async move {
                                        if delete_skill(sid).await.is_ok() {
                                            navigator().push(Route::SkillList {});
                                        }
                                    });
                                }
                            },
                            "Delete"
                        }
                    }
                }
            }

            // Components (instructions + resources + requires)
            SkillResources { skill_id: data.id_hex.clone(), data: data.clone() }
        }
    }
}

#[component]
fn SkillResources(skill_id: String, data: SkillDetailData) -> Element {
    let mut show_form = use_signal(|| false);
    let mut node = use_signal(String::new);
    let mut relation = use_signal(|| "skill:resource".to_string());
    let mut path = use_signal(String::new);
    let mut executable = use_signal(|| false);

    let parent_id = skill_id.clone();

    rsx! {
        Card {
            div { class: "p-5 space-y-3",
                div { class: "flex items-center justify-between",
                    SectionHeading { "Components" }
                    Button {
                        variant: ButtonVariant::Secondary,
                        onclick: move |_| show_form.toggle(),
                        if *show_form.read() { "Cancel" } else { "Link Resource" }
                    }
                }

                if *show_form.read() {
                    div { class: "space-y-2 border border-line rounded p-3",
                        div {
                            label { class: "text-xs text-fg-muted", "Node (type:hex)" }
                            input {
                                class: "input input-sm w-full mt-1 font-mono",
                                placeholder: "doc:<hex> / file:<hex> / entity:<hex>",
                                value: "{node}",
                                oninput: move |e: Event<FormData>| node.set(e.value()),
                            }
                        }
                        div { class: "flex gap-2",
                            div { class: "flex-1",
                                label { class: "text-xs text-fg-muted", "Relation" }
                                select {
                                    class: "input input-sm w-full mt-1",
                                    value: "{relation}",
                                    onchange: move |e: Event<FormData>| relation.set(e.value()),
                                    option { value: "skill:resource", "skill:resource" }
                                    option { value: "skill:instruction", "skill:instruction" }
                                    option { value: "skill:requires", "skill:requires" }
                                }
                            }
                            div { class: "flex-1",
                                label { class: "text-xs text-fg-muted", "Bundle path" }
                                input {
                                    class: "input input-sm w-full mt-1 font-mono",
                                    placeholder: "scripts/run.sh",
                                    value: "{path}",
                                    oninput: move |e: Event<FormData>| path.set(e.value()),
                                }
                            }
                        }
                        label { class: "flex items-center gap-2 text-sm",
                            input {
                                r#type: "checkbox",
                                checked: "{executable}",
                                onchange: move |e: Event<FormData>| executable.set(e.value() == "true"),
                            }
                            "Executable on hydrate"
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            onclick: {
                                let sid = parent_id.clone();
                                move |_| {
                                    let sid = sid.clone();
                                    let nav_id = sid.clone();
                                    let n = node.read().trim().to_string();
                                    if n.is_empty() { return; }
                                    let rel = relation.read().clone();
                                    let p = path.read().clone();
                                    let exec = *executable.read();
                                    spawn(async move {
                                        if link_resource(sid, n, rel, p, exec).await.is_ok() {
                                            show_form.set(false);
                                            node.set(String::new());
                                            path.set(String::new());
                                            navigator().push(Route::SkillDetail { id: nav_id });
                                        }
                                    });
                                }
                            },
                            "Link"
                        }
                    }
                }

                ResourceGroup { title: "Instructions".to_string(), skill_id: skill_id.clone(), rows: data.instructions.clone() }
                ResourceGroup { title: "Resources".to_string(), skill_id: skill_id.clone(), rows: data.resources.clone() }
                ResourceGroup { title: "Requires".to_string(), skill_id: skill_id.clone(), rows: data.requires.clone() }
            }
        }
    }
}

#[component]
fn ResourceGroup(title: String, skill_id: String, rows: Vec<ResourceRow>) -> Element {
    if rows.is_empty() {
        return rsx! {};
    }
    rsx! {
        div { class: "space-y-1",
            span { class: "kicker", "{title}" }
            for r in rows.iter() {
                div {
                    key: "{r.edge_hex}",
                    class: "flex items-center justify-between text-sm border-b border-line py-1",
                    div { class: "flex flex-col",
                        span { class: "font-mono text-xs", "{r.node}" }
                        if !r.path.is_empty() {
                            span { class: "text-fg-muted text-xs",
                                "{r.path}"
                                if r.executable { " (exec)" }
                            }
                        }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        onclick: {
                            let sid = skill_id.clone();
                            let edge = r.edge_hex.clone();
                            move |_| {
                                let sid = sid.clone();
                                let edge = edge.clone();
                                spawn(async move {
                                    if unlink_resource(sid.clone(), edge).await.is_ok() {
                                        navigator().push(Route::SkillDetail { id: sid });
                                    }
                                });
                            }
                        },
                        "Unlink"
                    }
                }
            }
        }
    }
}
