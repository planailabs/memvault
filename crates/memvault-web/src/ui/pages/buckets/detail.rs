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
    client.bucket_rename(&bucket_id, &new_name).await
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
    client.bucket_attach(&bucket_id).await
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
    client.bucket_archive(&bucket_id, &reason).await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[component]
pub fn BucketDetail(id: String) -> Element {
    use_topbar("Bucket Detail");
    let fetch_id = id.clone();
    let bucket = use_server_future(move || {
        let id = fetch_id.clone();
        async move { get_bucket(id).await }
    })?;

    let data = match &*bucket.read() {
        Some(Ok(Some(b))) => b.clone(),
        Some(Ok(None)) => {
            return rsx! {
                PageHeader { "Bucket not found" }
                p { class: "text-fg-muted", "The bucket with ID {id} does not exist." }
            };
        }
        Some(Err(e)) => {
            return rsx! { p { class: "text-danger", "Error: {e}" } };
        }
        None => {
            return rsx! { p { class: "text-fg-muted", "Loading..." } };
        }
    };

    let status_variant = match data.status.as_str() {
        "unbound" => PillVariant::Muted,
        "private" => PillVariant::Warn,
        "attached" => PillVariant::Ok,
        "archived" => PillVariant::Bad,
        _ => PillVariant::Muted,
    };

    let cluster_display = if data.cluster_hex.is_empty() {
        "unbound".to_string()
    } else {
        data.cluster_hex.clone()
    };

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center gap-3",
                PageHeader { class: "mb-0", "{data.name}" }
                Pill { variant: status_variant, "{data.status}" }
                if data.is_default {
                    Pill { variant: PillVariant::Info, "default" }
                }
            }

            // Metadata card
            Card {
                div { class: "p-5 space-y-2",
                    SectionHeading { "Metadata" }
                    div { class: "grid grid-cols-2 gap-2 text-sm",
                        span { class: "text-fg-muted", "ID" }
                        span { class: "font-mono text-xs", "{data.id_hex}" }
                        span { class: "text-fg-muted", "Owner" }
                        span { "{data.owner}" }
                        span { class: "text-fg-muted", "Visibility" }
                        span { "{data.visibility}" }
                        span { class: "text-fg-muted", "Classification" }
                        span { "{data.classification}" }
                        span { class: "text-fg-muted", "Cluster" }
                        span { class: "font-mono text-xs", "{cluster_display}" }
                        span { class: "text-fg-muted", "Envelopes" }
                        span { class: "tabular-nums", "{data.envelope_count}" }
                    }
                    if !data.description.is_empty() {
                        p { class: "text-sm text-fg-muted mt-2", "{data.description}" }
                    }
                }
            }

            // Actions card
            Card {
                div { class: "p-5 space-y-3",
                    SectionHeading { "Actions" }
                    div { class: "flex flex-wrap gap-2",
                        if !data.is_attached && data.status != "archived" {
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
                        if data.status != "archived" {
                            Button {
                                variant: ButtonVariant::Danger,
                                onclick: {
                                    let bid = id.clone();
                                    move |_| {
                                        let bid = bid.clone();
                                        spawn(async move {
                                            let _ = archive_bucket(bid, "archived via web UI".to_string()).await;
                                        });
                                    }
                                },
                                "Archive"
                            }
                        }
                    }
                }
            }
        }
    }
}
