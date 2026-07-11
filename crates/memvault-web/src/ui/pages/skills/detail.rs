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
    let edge_id = parse_edge(&edge_hex)?;
    let client = crate::ui::state::client()?;
    client
        .skill_unlink_resource(&entity_id, &edge_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

fn parse_edge(edge_hex: &str) -> Result<memvault_core::EdgeId, ServerFnError> {
    let bytes = hex::decode(edge_hex).map_err(|e| ServerFnError::new(format!("bad edge: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ServerFnError::new("edge id must be 32 bytes".to_string()))?;
    Ok(memvault_core::EdgeId(arr))
}

/// Upload a file and attach it to the skill as a `skill:resource` in one step.
/// The file always lands in the skill's own bucket (resolved server-side).
#[server]
async fn upload_skill_file(
    id: String,
    filename: String,
    data: Vec<u8>,
    path: String,
    executable: bool,
) -> Result<(), ServerFnError> {
    let entity_id = memvault_core::EntityId::from_hex(&id)
        .map_err(|e| ServerFnError::new(format!("bad id: {e}")))?;
    if data.is_empty() {
        return Err(ServerFnError::new("no file selected".to_string()));
    }
    let client = crate::ui::state::client()?;
    let bucket = client
        .node_bucket(&memvault_core::NodeRef::Entity(entity_id.clone()))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("could not resolve the skill's bucket".to_string()))?;
    let mime = memvault_api::files::detect_mime(std::path::Path::new(&filename));
    let cid = client
        .upload_file(
            &data,
            Some(&filename),
            mime,
            vec![],
            "internal",
            Some(&bucket),
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let bundle_path = if path.trim().is_empty() {
        filename.clone()
    } else {
        path.trim().to_string()
    };
    client
        .skill_link_resource(
            &entity_id,
            &memvault_core::NodeRef::Attachment(cid),
            memvault_core::SKILL_RESOURCE_REL,
            Some(&bundle_path),
            executable,
            memvault_core::Visibility::Internal,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
}

/// Rename a resource's bundle path (and update its executable bit). The
/// underlying node is unchanged — only the linking edge is re-created with the
/// new path (skills have no in-place edge-prop update primitive).
#[server]
async fn rename_resource(
    id: String,
    edge_hex: String,
    node: String,
    relation: String,
    new_path: String,
    executable: bool,
) -> Result<(), ServerFnError> {
    let entity_id = memvault_core::EntityId::from_hex(&id)
        .map_err(|e| ServerFnError::new(format!("bad id: {e}")))?;
    let edge_id = parse_edge(&edge_hex)?;
    let target = memvault_core::NodeRef::from_tag_label(&node)
        .ok_or_else(|| ServerFnError::new("node must be 'type:hex'".to_string()))?;
    let client = crate::ui::state::client()?;
    client
        .skill_unlink_resource(&entity_id, &edge_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    client
        .skill_link_resource(
            &entity_id,
            &target,
            &relation,
            (!new_path.trim().is_empty()).then(|| new_path.trim()),
            executable,
            memvault_core::Visibility::Internal,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
}

/// Delete a file/doc resource: unlink it from the skill AND retract the
/// underlying node. (Reserved kinds — e.g. a required skill — are refused by
/// the validated retract, so only file/doc resources expose this in the UI.)
#[server]
async fn delete_resource(id: String, edge_hex: String, node: String) -> Result<(), ServerFnError> {
    let entity_id = memvault_core::EntityId::from_hex(&id)
        .map_err(|e| ServerFnError::new(format!("bad id: {e}")))?;
    let edge_id = parse_edge(&edge_hex)?;
    let client = crate::ui::state::client()?;
    client
        .skill_unlink_resource(&entity_id, &edge_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    client
        .retract_node(&node, "deleted via skill UI")
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
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
    let mut show_upload = use_signal(|| false);
    let mut show_link = use_signal(|| false);
    let mut err = use_signal(String::new);

    // Upload-file form state.
    let mut up_file = use_signal(|| None::<(String, Vec<u8>)>);
    let mut up_path = use_signal(String::new);
    let mut up_exec = use_signal(|| false);

    // Link-existing-node form state.
    let mut node = use_signal(String::new);
    let mut relation = use_signal(|| "skill:resource".to_string());
    let mut link_path = use_signal(String::new);
    let mut link_exec = use_signal(|| false);

    rsx! {
        Card {
            div { class: "p-5 space-y-3",
                div { class: "flex items-center justify-between",
                    SectionHeading { "Components" }
                    div { class: "flex gap-2",
                        Button {
                            variant: ButtonVariant::Secondary,
                            onclick: move |_| { show_upload.toggle(); show_link.set(false); err.set(String::new()); },
                            if *show_upload.read() { "Cancel" } else { "Upload File" }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            onclick: move |_| { show_link.toggle(); show_upload.set(false); err.set(String::new()); },
                            if *show_link.read() { "Cancel" } else { "Link Node" }
                        }
                    }
                }

                if !err.read().is_empty() {
                    p { class: "text-danger text-sm", "{err}" }
                }

                if *show_upload.read() {
                    div { class: "space-y-2 border border-line rounded p-3",
                        div {
                            label { class: "text-xs text-fg-muted", "File" }
                            input {
                                class: "input input-sm w-full mt-1",
                                r#type: "file",
                                onchange: move |evt: Event<FormData>| {
                                    if let Some(file) = evt.files().into_iter().next() {
                                        spawn(async move {
                                            let name = file.name();
                                            if let Ok(bytes) = file.read_bytes().await {
                                                up_file.set(Some((name, bytes.to_vec())));
                                            }
                                        });
                                    }
                                },
                            }
                            if let Some((n, b)) = up_file.read().as_ref() {
                                span { class: "text-fg-muted text-xs", "{n} — {b.len()} bytes" }
                            }
                        }
                        input {
                            class: "input input-sm w-full font-mono",
                            placeholder: "bundle path — defaults to filename (e.g. scripts/run.sh)",
                            value: "{up_path}",
                            oninput: move |e: Event<FormData>| up_path.set(e.value()),
                        }
                        label { class: "flex items-center gap-2 text-sm",
                            input {
                                r#type: "checkbox",
                                checked: "{up_exec}",
                                onchange: move |e: Event<FormData>| up_exec.set(e.value() == "true"),
                            }
                            "Executable on hydrate"
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            onclick: {
                                let sid = skill_id.clone();
                                move |_| {
                                    let Some((fname, bytes)) = up_file.read().clone() else {
                                        err.set("Choose a file first.".to_string());
                                        return;
                                    };
                                    let p = up_path.read().clone();
                                    let exec = *up_exec.read();
                                    let sid = sid.clone();
                                    spawn(async move {
                                        match upload_skill_file(sid.clone(), fname, bytes, p, exec).await {
                                            Ok(_) => {
                                                show_upload.set(false);
                                                up_file.set(None);
                                                up_path.set(String::new());
                                                navigator().push(Route::SkillDetail { id: sid });
                                            }
                                            Err(e) => err.set(e.to_string()),
                                        }
                                    });
                                }
                            },
                            "Upload"
                        }
                    }
                }

                if *show_link.read() {
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
                                    value: "{link_path}",
                                    oninput: move |e: Event<FormData>| link_path.set(e.value()),
                                }
                            }
                        }
                        label { class: "flex items-center gap-2 text-sm",
                            input {
                                r#type: "checkbox",
                                checked: "{link_exec}",
                                onchange: move |e: Event<FormData>| link_exec.set(e.value() == "true"),
                            }
                            "Executable on hydrate"
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            onclick: {
                                let sid = skill_id.clone();
                                move |_| {
                                    let n = node.read().trim().to_string();
                                    if n.is_empty() {
                                        err.set("Enter a node id (type:hex).".to_string());
                                        return;
                                    }
                                    let rel = relation.read().clone();
                                    let p = link_path.read().clone();
                                    let exec = *link_exec.read();
                                    let sid = sid.clone();
                                    spawn(async move {
                                        match link_resource(sid.clone(), n, rel, p, exec).await {
                                            Ok(_) => {
                                                show_link.set(false);
                                                node.set(String::new());
                                                link_path.set(String::new());
                                                navigator().push(Route::SkillDetail { id: sid });
                                            }
                                            Err(e) => err.set(e.to_string()),
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
                ResourceRowItem { key: "{r.edge_hex}", skill_id: skill_id.clone(), row: r.clone() }
            }
        }
    }
}

#[component]
fn ResourceRowItem(skill_id: String, row: ResourceRow) -> Element {
    let mut editing = use_signal(|| false);
    let mut path_edit = use_signal(|| row.path.clone());
    let mut err = use_signal(String::new);
    // Only file/doc resources can be deleted (retracting a required skill is
    // refused by the validated retract — those are unlink-only here).
    let deletable = row.node.starts_with("file:") || row.node.starts_with("doc:");

    rsx! {
        div {
            class: "flex items-center justify-between gap-2 text-sm border-b border-line py-1",
            div { class: "flex flex-col min-w-0",
                span { class: "font-mono text-xs truncate", "{row.node}" }
                if *editing.read() {
                    input {
                        class: "input input-sm mt-1 font-mono",
                        value: "{path_edit}",
                        oninput: move |e: Event<FormData>| path_edit.set(e.value()),
                    }
                } else if !row.path.is_empty() {
                    span { class: "text-fg-muted text-xs",
                        "{row.path}"
                        if row.executable { " (exec)" }
                    }
                }
                if !err.read().is_empty() {
                    span { class: "text-danger text-xs", "{err}" }
                }
            }
            div { class: "flex gap-1 shrink-0",
                if *editing.read() {
                    Button {
                        variant: ButtonVariant::Primary,
                        onclick: {
                            let sid = skill_id.clone();
                            let edge = row.edge_hex.clone();
                            let node = row.node.clone();
                            let rel = row.relation.clone();
                            let exec = row.executable;
                            move |_| {
                                let sid = sid.clone();
                                let edge = edge.clone();
                                let node = node.clone();
                                let rel = rel.clone();
                                let np = path_edit.read().clone();
                                spawn(async move {
                                    match rename_resource(sid.clone(), edge, node, rel, np, exec).await {
                                        Ok(_) => { navigator().push(Route::SkillDetail { id: sid }); }
                                        Err(e) => err.set(e.to_string()),
                                    }
                                });
                            }
                        },
                        "Save"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        onclick: move |_| editing.set(false),
                        "Cancel"
                    }
                } else {
                    Button {
                        variant: ButtonVariant::Secondary,
                        onclick: move |_| editing.set(true),
                        "Rename"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        onclick: {
                            let sid = skill_id.clone();
                            let edge = row.edge_hex.clone();
                            move |_| {
                                let sid = sid.clone();
                                let edge = edge.clone();
                                spawn(async move {
                                    match unlink_resource(sid.clone(), edge).await {
                                        Ok(_) => { navigator().push(Route::SkillDetail { id: sid }); }
                                        Err(e) => err.set(e.to_string()),
                                    }
                                });
                            }
                        },
                        "Unlink"
                    }
                    if deletable {
                        Button {
                            variant: ButtonVariant::Danger,
                            onclick: {
                                let sid = skill_id.clone();
                                let edge = row.edge_hex.clone();
                                let node = row.node.clone();
                                move |_| {
                                    let sid = sid.clone();
                                    let edge = edge.clone();
                                    let node = node.clone();
                                    spawn(async move {
                                        match delete_resource(sid.clone(), edge, node).await {
                                            Ok(_) => { navigator().push(Route::SkillDetail { id: sid }); }
                                            Err(e) => err.set(e.to_string()),
                                        }
                                    });
                                }
                            },
                            "Delete"
                        }
                    }
                }
            }
        }
    }
}
