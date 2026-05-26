//! Bucket detail page — shows metadata, actions, and contents.

use dioxus::prelude::*;
use plan_ai_design::{
    Button, ButtonVariant, Card, PageHeader, Pill, PillVariant, SectionHeading,
};
use serde::{Deserialize, Serialize};

use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct GrantRow {
    cid_hex: String,
    audience: String,
    actions: String,
    expires: String,
}

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
            owner: b
                .owner_agent
                .map(|a| a.0)
                .unwrap_or_else(|| "cluster".to_string()),
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

#[server]
async fn list_grants(id: String) -> Result<Vec<GrantRow>, ServerFnError> {
    let bucket_bytes =
        hex::decode(&id).map_err(|e| ServerFnError::new(format!("bad hex: {e}")))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ServerFnError::new("bucket id must be 32 bytes".to_string()))?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    let local = crate::ui::state::local_client()?;

    let grants = local
        .list_bucket_grants(&bucket_id)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(grants
        .into_iter()
        .map(|(cid, g)| {
            let audience = match &g.audience {
                memvault_auth::GrantAudience::Cluster(c) => {
                    format!("cluster:{}", &hex::encode(c.0)[..8])
                }
                memvault_auth::GrantAudience::Peer(p) => {
                    format!("peer:{}", &hex::encode(&p.0)[..8])
                }
                memvault_auth::GrantAudience::Agent(a) => format!("agent:{}", a.0),
                memvault_auth::GrantAudience::Role(r) => format!("role:{r:?}"),
            };
            let actions: Vec<String> = g.actions.iter().map(|a| format!("{a:?}")).collect();
            let expires_secs = g.not_after_ns / 1_000_000_000;
            let now_secs = memvault_core::wall_ns() / 1_000_000_000;
            let remaining = if expires_secs > now_secs {
                let rem = expires_secs - now_secs;
                if rem > 86400 {
                    format!("{}d", rem / 86400)
                } else if rem > 3600 {
                    format!("{}h", rem / 3600)
                } else {
                    format!("{}m", rem / 60)
                }
            } else {
                "expired".to_string()
            };
            GrantRow {
                cid_hex: hex::encode(&cid),
                audience,
                actions: actions.join(", "),
                expires: remaining,
            }
        })
        .collect())
}

#[server]
async fn create_grant(
    bucket_id_hex: String,
    audience_type: String,
    audience_value: String,
    read: bool,
    write: bool,
    admin: bool,
    ttl_hours: u64,
) -> Result<(), ServerFnError> {
    let bucket_bytes = hex::decode(&bucket_id_hex)
        .map_err(|e| ServerFnError::new(format!("bad hex: {e}")))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ServerFnError::new("bucket id must be 32 bytes".to_string()))?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    let audience = match audience_type.as_str() {
        "role" => {
            let role = match audience_value.as_str() {
                "admin" => memvault_auth::Role::Admin,
                "agent_host" => memvault_auth::Role::AgentHost,
                "auditor" => memvault_auth::Role::Auditor,
                "service" => memvault_auth::Role::Service,
                _ => return Err(ServerFnError::new(format!("unknown role: {audience_value}"))),
            };
            memvault_auth::GrantAudience::Role(role)
        }
        "agent" => {
            memvault_auth::GrantAudience::Agent(memvault_core::AgentId(audience_value))
        }
        _ => return Err(ServerFnError::new(format!("unsupported audience type: {audience_type}"))),
    };

    let mut actions = Vec::new();
    if read {
        actions.push(memvault_auth::Action::Read);
    }
    if write {
        actions.push(memvault_auth::Action::Write);
    }
    if admin {
        actions.push(memvault_auth::Action::Admin);
    }
    if actions.is_empty() {
        return Err(ServerFnError::new("at least one action required".to_string()));
    }

    let local = crate::ui::state::local_client()?;

    local
        .issue_bucket_grant(&bucket_id, audience, actions, ttl_hours * 3600)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(())
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

            // Access Control (Grants) card
            BucketAcls { bucket_id: id.clone() }
        }
    }
}

#[component]
fn BucketAcls(bucket_id: String) -> Element {
    let fetch_id = bucket_id.clone();
    let grants = use_server_future(move || {
        let id = fetch_id.clone();
        async move { list_grants(id).await }
    })?;

    let mut show_form = use_signal(|| false);
    let mut audience_type = use_signal(|| "role".to_string());
    let mut audience_value = use_signal(|| "agent_host".to_string());
    let mut act_read = use_signal(|| true);
    let mut act_write = use_signal(|| false);
    let mut act_admin = use_signal(|| false);
    let mut ttl = use_signal(|| "720".to_string()); // 30 days default

    rsx! {
        Card {
            div { class: "p-5 space-y-3",
                div { class: "flex items-center justify-between",
                    SectionHeading { "Access Control" }
                    Button {
                        variant: ButtonVariant::Secondary,
                        onclick: move |_| show_form.toggle(),
                        if *show_form.read() { "Cancel" } else { "Add Grant" }
                    }
                }

                if *show_form.read() {
                    div { class: "border border-border rounded-lg p-4 space-y-3 bg-bg-muted",
                        div { class: "grid grid-cols-2 gap-3",
                            div {
                                label { class: "block text-xs text-fg-muted mb-1", "Audience Type" }
                                select {
                                    class: "w-full rounded border border-border bg-bg px-2 py-1 text-sm",
                                    value: "{audience_type}",
                                    onchange: move |e| audience_type.set(e.value()),
                                    option { value: "role", "Role" }
                                    option { value: "agent", "Agent" }
                                }
                            }
                            div {
                                label { class: "block text-xs text-fg-muted mb-1", "Value" }
                                if audience_type.read().as_str() == "role" {
                                    select {
                                        class: "w-full rounded border border-border bg-bg px-2 py-1 text-sm",
                                        value: "{audience_value}",
                                        onchange: move |e| audience_value.set(e.value()),
                                        option { value: "admin", "Admin" }
                                        option { value: "agent_host", "AgentHost" }
                                        option { value: "auditor", "Auditor" }
                                        option { value: "service", "Service" }
                                    }
                                } else {
                                    input {
                                        class: "w-full rounded border border-border bg-bg px-2 py-1 text-sm",
                                        placeholder: "agent-id",
                                        value: "{audience_value}",
                                        oninput: move |e| audience_value.set(e.value()),
                                    }
                                }
                            }
                        }
                        div { class: "flex items-center gap-4",
                            label { class: "flex items-center gap-1 text-sm",
                                input {
                                    r#type: "checkbox",
                                    checked: *act_read.read(),
                                    onchange: move |e| act_read.set(e.checked()),
                                }
                                "Read"
                            }
                            label { class: "flex items-center gap-1 text-sm",
                                input {
                                    r#type: "checkbox",
                                    checked: *act_write.read(),
                                    onchange: move |e| act_write.set(e.checked()),
                                }
                                "Write"
                            }
                            label { class: "flex items-center gap-1 text-sm",
                                input {
                                    r#type: "checkbox",
                                    checked: *act_admin.read(),
                                    onchange: move |e| act_admin.set(e.checked()),
                                }
                                "Admin"
                            }
                        }
                        div {
                            label { class: "block text-xs text-fg-muted mb-1", "TTL (hours)" }
                            input {
                                class: "w-24 rounded border border-border bg-bg px-2 py-1 text-sm",
                                r#type: "number",
                                value: "{ttl}",
                                oninput: move |e| ttl.set(e.value()),
                            }
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            onclick: {
                                let bid = bucket_id.clone();
                                move |_| {
                                    let bid = bid.clone();
                                    let at = audience_type.read().clone();
                                    let av = audience_value.read().clone();
                                    let r = *act_read.read();
                                    let w = *act_write.read();
                                    let a = *act_admin.read();
                                    let t: u64 = ttl.read().parse().unwrap_or(720);
                                    spawn(async move {
                                        let _ = create_grant(bid, at, av, r, w, a, t).await;
                                    });
                                }
                            },
                            "Issue Grant"
                        }
                    }
                }

                // Grants table
                match &*grants.read() {
                    Some(Ok(rows)) if !rows.is_empty() => rsx! {
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm",
                                thead {
                                    tr { class: "text-left text-fg-muted border-b border-border",
                                        th { class: "pb-2 pr-4", "Audience" }
                                        th { class: "pb-2 pr-4", "Actions" }
                                        th { class: "pb-2 pr-4", "Expires" }
                                        th { class: "pb-2", "CID" }
                                    }
                                }
                                tbody {
                                    for row in rows.iter() {
                                        tr { class: "border-b border-border/50",
                                            td { class: "py-2 pr-4", "{row.audience}" }
                                            td { class: "py-2 pr-4",
                                                div { class: "flex gap-1",
                                                    for action in row.actions.split(", ") {
                                                        Pill { variant: PillVariant::Info, "{action}" }
                                                    }
                                                }
                                            }
                                            td { class: "py-2 pr-4",
                                                if row.expires == "expired" {
                                                    Pill { variant: PillVariant::Bad, "expired" }
                                                } else {
                                                    span { "{row.expires}" }
                                                }
                                            }
                                            td { class: "py-2 font-mono text-xs text-fg-muted",
                                                "{&row.cid_hex[..16]}…"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Ok(_)) => rsx! {
                        p { class: "text-sm text-fg-muted", "No grants issued for this bucket." }
                    },
                    Some(Err(e)) => rsx! {
                        p { class: "text-sm text-danger", "Error loading grants: {e}" }
                    },
                    None => rsx! {
                        p { class: "text-sm text-fg-muted", "Loading…" }
                    },
                }
            }
        }
    }
}
