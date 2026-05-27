//! Trust tree page — visualises the current admin → node → agent chain.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};

use crate::ui::components::cid_display::CidDisplay;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AgentRow {
    pubkey: String,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NodeRow {
    pubkey: String,
    /// "attested" or "pre-genesis"
    kind: String,
    revoked: bool,
    role: Option<String>,
    agents: Vec<AgentRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TrustTree {
    admin_pubkey: Option<String>,
    nodes: Vec<NodeRow>,
}

#[server]
async fn get_trust_tree() -> Result<TrustTree, ServerFnError> {
    use memvault_auth::jwt::NodeTrust;

    let client = crate::ui::state::local_client()?;
    let state = client
        .trust_state()
        .ok_or_else(|| ServerFnError::new("trust state not bootstrapped"))?;

    let admin_pubkey = client
        .admin_verifying_key()
        .map(|k| hex::encode(k.to_bytes()));

    let node_trust = state
        .node_trust
        .read()
        .map(|m| m.clone())
        .unwrap_or_default();
    let revoked_agents = state
        .revoked_agents
        .read()
        .map(|s| s.clone())
        .unwrap_or_default();
    let revoked_nodes = state
        .revoked_nodes
        .read()
        .map(|s| s.clone())
        .unwrap_or_default();

    // Build a node-pk → list of attested agents map from persisted
    // AgentAttestations. We re-scan rather than maintain a separate cache
    // here — this page is read-only and not on a hot path.
    let mut agents_by_node: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>> =
        std::collections::HashMap::new();
    if let Ok(atts) =
        memvault_api::sigchain::scan_agent_attestations(&*client)
    {
        for att in atts {
            agents_by_node
                .entry(att.node_pubkey)
                .or_default()
                .push(att.agent_pubkey);
        }
    }

    let mut nodes: Vec<NodeRow> = node_trust
        .into_iter()
        .map(|(pk, trust)| {
            let (kind, role) = match &trust {
                NodeTrust::Attested(att) => (
                    "attested".to_string(),
                    Some(format!("{:?}", att.role)),
                ),
                NodeTrust::PreGenesis => ("pre-genesis".to_string(), None),
            };
            let agents = agents_by_node
                .get(&pk)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|apk| AgentRow {
                    pubkey: hex::encode(apk),
                    revoked: revoked_agents.contains(&apk),
                })
                .collect();
            NodeRow {
                pubkey: hex::encode(pk),
                kind,
                revoked: revoked_nodes.contains(&pk),
                role,
                agents,
            }
        })
        .collect();
    // Stable sort: non-revoked first, then by pubkey hex.
    nodes.sort_by(|a, b| a.revoked.cmp(&b.revoked).then_with(|| a.pubkey.cmp(&b.pubkey)));

    Ok(TrustTree {
        admin_pubkey,
        nodes,
    })
}

#[component]
pub fn TrustTreePage() -> Element {
    use_topbar("Trust tree");
    let data = use_server_future(get_trust_tree)?;

    match &*data.read() {
        Some(Ok(tree)) => rsx! { TrustTreeView { tree: tree.clone() } },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", "Loading…" } },
    }
}

#[component]
fn TrustTreeView(tree: TrustTree) -> Element {
    rsx! {
        div { class: "space-y-6",
            PageHeader { "Trust tree" }

            Card {
                div { class: "p-5 space-y-3",
                    SectionHeading { "Cluster admin" }
                    if let Some(pk) = &tree.admin_pubkey {
                        div { class: "flex items-center gap-2",
                            Pill { variant: PillVariant::Ok, "admin" }
                            CidDisplay { cid: pk.clone(), len: Some(16) }
                        }
                    } else {
                        p { class: "text-fg-muted",
                            "Pre-genesis — no admin key configured on this node."
                        }
                    }
                }
            }

            Card {
                div { class: "p-5 space-y-3",
                    SectionHeading { "Trusted nodes ({tree.nodes.len()})" }
                    if tree.nodes.is_empty() {
                        p { class: "text-fg-muted", "No trusted nodes." }
                    } else {
                        ul { class: "space-y-4",
                            for node in &tree.nodes {
                                li { key: "{node.pubkey}", class: "border-l-2 border-border pl-4",
                                    div { class: "flex items-center gap-2 flex-wrap",
                                        if node.revoked {
                                            Pill { variant: PillVariant::Bad, "revoked" }
                                        } else if node.kind == "attested" {
                                            Pill { variant: PillVariant::Ok, "node" }
                                        } else {
                                            Pill { variant: PillVariant::Warn, "pre-genesis" }
                                        }
                                        CidDisplay { cid: node.pubkey.clone(), len: Some(16) }
                                        if let Some(role) = &node.role {
                                            Pill { variant: PillVariant::Info, "{role}" }
                                        }
                                    }
                                    if node.agents.is_empty() {
                                        p { class: "text-fg-muted text-sm mt-2 ml-4",
                                            "No agents attested."
                                        }
                                    } else {
                                        ul { class: "mt-2 ml-4 space-y-1",
                                            for agent in &node.agents {
                                                li { key: "{agent.pubkey}",
                                                    class: "flex items-center gap-2",
                                                    if agent.revoked {
                                                        Pill { variant: PillVariant::Bad, "agent (revoked)" }
                                                    } else {
                                                        Pill { variant: PillVariant::Muted, "agent" }
                                                    }
                                                    CidDisplay { cid: agent.pubkey.clone(), len: Some(12) }
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
}
