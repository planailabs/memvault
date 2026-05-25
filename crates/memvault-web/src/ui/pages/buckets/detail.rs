//! Bucket detail page — shows metadata, actions, and contents.

use dioxus::prelude::*;
use plan_ai_design::{Button, ButtonVariant, Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};

use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BucketData {
    id_hex: String,
    name: String,
    description: String,
    owner: String,
    status: String,
    cluster_hex: String,
    is_default: bool,
    is_attached: bool,
    visibility: String,
    classification: String,
    created_ns: u64,
    envelope_count: u64,
}

#[server]
async fn get_bucket(id: String) -> Result<Option<BucketData>, ServerFnError> {
    let bucket_bytes = hex::decode(&id).map_err(|e| ServerFnError::new(format!("bad hex: {e}")))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ServerFnError::new("bucket id must be 32 bytes".to_string()))?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    let client = crate::ui::state::client()?;
    let info = client
        .bucket_get(&bucket_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(info.map(|b| {
        let status = if b.name.contains("[ARCHIVED]") {
            "archived"
        } else if !b.is_attached {
            "private"
        } else if b.cluster_id.is_none() {
            "unbound"
        } else {
            "attached"
        };
        BucketData {
            id_hex: hex::encode(b.id.0),
            name: b.name,
            description: b.description.unwrap_or_default(),
            owner: b.owner_agent.map(|a| a.0).unwrap_or_else(|| "cluster".to_string()),
            status: status.to_string(),
            cluster_hex: b.cluster_id.map(|c| hex::encode(c.0)).unwrap_or_default(),
            is_default: b.is_default,
            is_attached: b.is_attached,
            visibility: format!("{:?}", b.default_visibility),
            classification: format!("{:?}", b.default_classification),
            created_ns: b.created_ns,
            envelope_count: b.envelope_count,
        }
    }))
}

#[server]
async fn rename_bucket(id: String, new_name: String) -> Result<(), ServerFnError> {
    let bucket_bytes = hex::decode(&id).map_err(|e| ServerFnError::new(format!("bad hex: {e}")))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ServerFnError::new("bucket id must be 32 bytes".to_string()))?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    let client = crate::ui::state::client()?;
    client
        .bucket_rename(&bucket_id, &new_name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server]
async fn attach_bucket(id: String) -> Result<(), ServerFnError> {
    let bucket_bytes = hex::decode(&id).map_err(|e| ServerFnError::new(format!("bad hex: {e}")))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ServerFnError::new("bucket id must be 32 bytes".to_string()))?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    let client = crate::ui::state::client()?;
    client
        .bucket_attach(&bucket_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server]
async fn archive_bucket(id: String, reason: String) -> Result<(), ServerFnError> {
    let bucket_bytes = hex::decode(&id).map_err(|e| ServerFnError::new(format!("bad hex: {e}")))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ServerFnError::new("bucket id must be 32 bytes".to_string()))?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    let client = crate::ui::state::client()?;
    client
        .bucket_archive(&bucket_id, &reason)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[component]
pub fn BucketDetail(id: String) -> Element {
    use_topbar("Bucket Detail");
    let bucket_id = id.clone();
    let bucket = use_server_future(move || {
        let id = bucket_id.clone();
        async move { get_bucket(id).await }
    })?;
    let mut editing_name = use_signal(|| false);
    let mut name_input = use_signal(String::new);
    let mut archive_reason = use_signal(String::new);
    let mut show_archive = use_signal(|| false);

    match &*bucket.read() {
        Some(Ok(Some(b))) => {
            let status_variant = match b.status.as_str() {
                "unbound" => PillVariant::Muted,
                "private" => PillVariant::Warn,
                "attached" => PillVariant::Ok,
                "archived" => PillVariant::Bad,
                _ => PillVariant::Muted,
            };

            rsx! {
                div { class: "space-y-4",
                    div { class: "flex items-center gap-3",
                        PageHeader { class: "mb-0",
                            if *editing_name.read() {
                                input {
                                    class: "input input-sm",
                                    r#type: "text",
                                    value: "{name_input}",
                                    oninput: move |e: Event<FormData>| name_input.set(e.value()),
                                    onkeypress: {
                                        let bid = id.clone();
                                        move |e: Event<KeyboardData>| {
                                            if e.key() == Key::Enter {
                                                let new_name = name_input.read().trim().to_string();
                                                let bid = bid.clone();
                                                spawn(async move {
                                                    let _ = rename_bucket(bid, new_name).await;
                                                    editing_name.set(false);
                                                });
                                            }
                                        }
                                    },
                                }
                            } else {
                                span {
                                    class: "cursor-pointer",
                                    onclick: move |_| {
                                        name_input.set(b.name.clone());
                                        editing_name.set(true);
                                    },
                                    "{b.name}"
                                }
                            }
                        }
                        Pill { variant: status_variant, "{b.status}" }
                        if b.is_default {
                            Pill { variant: PillVariant::Info, "default" }
                        }
                    }

                    // Metadata card
                    Card {
                        div { class: "p-5 space-y-2",
                            SectionHeading { "Metadata" }
                            div { class: "grid grid-cols-2 gap-2 text-sm",
                                span { class: "text-fg-muted", "ID" }
                                span { class: "font-mono text-xs", "{b.id_hex}" }
                                span { class: "text-fg-muted", "Owner" }
                                span { "{b.owner}" }
                                span { class: "text-fg-muted", "Visibility" }
                                span { "{b.visibility}" }
                                span { class: "text-fg-muted", "Classification" }
                                span { "{b.classification}" }
                                span { class: "text-fg-muted", "Cluster" }
                                span { class: "font-mono text-xs",
                                    if b.cluster_hex.is_empty() { "unbound" } else { &b.cluster_hex }
                                }
                                span { class: "text-fg-muted", "Envelopes" }
                                span { class: "tabular-nums", "{b.envelope_count}" }
                            }
                            if !b.description.is_empty() {
                                p { class: "text-sm text-fg-muted mt-2", "{b.description}" }
                            }
                        }
                    }

                    // Actions card
                    Card {
                        div { class: "p-5 space-y-3",
                            SectionHeading { "Actions" }
                            div { class: "flex flex-wrap gap-2",
                                if !b.is_attached && b.status != "archived" {
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        onclick: {
                                            let bid = id.clone();
                                            move |_| {
                                                let bid = bid.clone();
                                                spawn(async move {
                                                    let _ = attach_bucket(bid).await;
                                                });
                                            }
                                        },
                                        "Attach to Cluster"
                                    }
                                }
                                if b.status != "archived" {
                                    Button {
                                        variant: ButtonVariant::Danger,
                                        onclick: move |_| show_archive.set(true),
                                        "Archive"
                                    }
                                }
                            }
                            if *show_archive.read() {
                                div { class: "flex gap-2 mt-2",
                                    input {
                                        class: "input input-sm flex-1",
                                        r#type: "text",
                                        placeholder: "Reason for archiving...",
                                        value: "{archive_reason}",
                                        oninput: move |e: Event<FormData>| archive_reason.set(e.value()),
                                    }
                                    Button {
                                        variant: ButtonVariant::Danger,
                                        onclick: {
                                            let bid = id.clone();
                                            move |_| {
                                                let reason = archive_reason.read().clone();
                                                let bid = bid.clone();
                                                spawn(async move {
                                                    let _ = archive_bucket(bid, reason).await;
                                                    show_archive.set(false);
                                                });
                                            }
                                        },
                                        "Confirm Archive"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Some(Ok(None)) => rsx! {
            PageHeader { "Bucket not found" }
            p { class: "text-fg-muted", "The bucket with ID {id} does not exist." }
        },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", "Loading..." } },
    }
}
