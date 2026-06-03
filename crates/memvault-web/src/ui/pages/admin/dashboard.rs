//! Admin dashboard — node status, tokens, peers.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{Card, PageHeader, Pill, PillVariant, SectionHeading, StatBlock, Td, TdMuted};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NodeStatusData {
    peer_id: String,
    cluster_id: String,
    block_count: u64,
    doc_count: u64,
    peer_count: u32,
    uptime_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TokenRow {
    cid: String,
    label: Option<String>,
    role: String,
    max_uses: u32,
    consumed_count: u32,
    revoked: bool,
}

#[server]
async fn get_admin_data() -> Result<(NodeStatusData, Vec<TokenRow>), ServerFnError> {
    let client = crate::ui::state::client()?;

    let status = client
        .status()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let tokens = client
        .list_tokens()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let status_data = NodeStatusData {
        peer_id: hex::encode(&status.peer_id),
        cluster_id: hex::encode(&status.cluster_id),
        block_count: status.block_count,
        doc_count: status.doc_count,
        peer_count: status.peer_count,
        uptime_secs: status.uptime_secs,
    };

    let token_rows: Vec<TokenRow> = tokens
        .into_iter()
        .map(|t| TokenRow {
            cid: hex::encode(&t.cid),
            label: t.label,
            role: format!("{:?}", t.role),
            max_uses: t.max_uses,
            consumed_count: t.consumed_count,
            revoked: t.revoked,
        })
        .collect();

    Ok((status_data, token_rows))
}

#[component]
pub fn AdminDashboard() -> Element {
    use_topbar(&t!("admin-title"));
    let data = use_server_future(get_admin_data)?;

    match &*data.read() {
        Some(Ok((status, tokens))) => {
            rsx! { AdminView { status: status.clone(), tokens: tokens.clone() } }
        }
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[component]
fn AdminView(status: NodeStatusData, tokens: Vec<TokenRow>) -> Element {
    rsx! {
        div { class: "space-y-6",
            PageHeader { {t!("admin-title")} }

            // Quick links
            div { class: "flex flex-wrap gap-2",
                Link { to: Route::TokenManagement {}, class: "btn btn-secondary", "Tokens" }
                Link { to: Route::TrustTreePage {}, class: "btn btn-secondary", "Trust tree" }
            }

            // Stats
            div { class: "grid grid-cols-2 lg:grid-cols-4 gap-3",
                StatBlock { label: t!("admin-stat-documents"), value: format!("{}", status.doc_count) }
                StatBlock { label: t!("admin-stat-blocks"), value: format!("{}", status.block_count) }
                StatBlock { label: t!("admin-stat-peers"), value: format!("{}", status.peer_count) }
                StatBlock { label: t!("admin-stat-uptime"), value: format_uptime(status.uptime_secs) }
            }

            // Node info
            Card {
                div { class: "p-5",
                    SectionHeading { {t!("admin-section-node")} }
                    table { class: "table mt-2",
                        tbody { class: "tbody",
                            tr {
                                td { class: "td font-medium text-sm", {t!("admin-peer-id")} }
                                td { class: "td", CidDisplay { cid: status.peer_id.clone(), len: Some(16) } }
                            }
                            tr {
                                td { class: "td font-medium text-sm", {t!("admin-cluster-id")} }
                                td { class: "td", CidDisplay { cid: status.cluster_id.clone(), len: Some(16) } }
                            }
                        }
                    }
                }
            }

            // Tokens
            Card {
                div { class: "p-5",
                    SectionHeading { {t!("admin-section-tokens", count: tokens.len())} }
                    if tokens.is_empty() {
                        p { class: "text-fg-muted mt-2", {t!("admin-no-tokens")} }
                    } else {
                        table { class: "table mt-2",
                            thead { class: "thead",
                                tr {
                                    th { class: "th", {t!("tokens-th-label")} }
                                    th { class: "th", {t!("tokens-th-role")} }
                                    th { class: "th", {t!("tokens-th-used")} }
                                    th { class: "th", {t!("tokens-th-status")} }
                                }
                            }
                            tbody { class: "tbody",
                                for token in &tokens {
                                    tr { key: "{token.cid}",
                                        Td {
                                            if let Some(label) = &token.label {
                                                "{label}"
                                            } else {
                                                CidDisplay { cid: token.cid.clone(), len: Some(8) }
                                            }
                                        }
                                        Td { Pill { variant: PillVariant::Info, "{token.role}" } }
                                        TdMuted { "{token.consumed_count} / {token.max_uses}" }
                                        Td {
                                            if token.revoked {
                                                Pill { variant: PillVariant::Bad, {t!("tokens-status-revoked")} }
                                            } else {
                                                Pill { variant: PillVariant::Ok, {t!("tokens-status-active")} }
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
    }
}
