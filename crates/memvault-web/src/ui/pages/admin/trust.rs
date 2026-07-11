//! Trust tree page — visualises the current admin → node → agent chain.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader, Pill, PillVariant, SectionHeading};
use serde::{Deserialize, Serialize};

use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AgentRow {
    pubkey: String,
    agent_id: String,
    /// Mutable display label (set via agent rename). `None` when never renamed.
    label: Option<String>,
    role: String,
    revoked: bool,
    not_after_ns: u64,
    expired: bool,
}

impl AgentRow {
    /// Human display name: the mutable label, else the enrolled agent_id,
    /// else a short pubkey prefix.
    fn display_name(&self) -> String {
        self.label
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if self.agent_id.is_empty() {
                    None
                } else {
                    Some(self.agent_id.clone())
                }
            })
            .unwrap_or_else(|| format!("{}…", &self.pubkey[..self.pubkey.len().min(8)]))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NodeRow {
    pubkey: String,
    /// "attested" or "pre-genesis"
    kind: String,
    revoked: bool,
    is_local: bool,
    role: Option<String>,
    /// Only set for Attested nodes.
    origin: Option<String>,
    /// Only set for Attested nodes.
    not_after_ns: Option<u64>,
    expired: bool,
    agents: Vec<AgentRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TrustTree {
    admin_pubkey: Option<String>,
    nodes: Vec<NodeRow>,
    /// Agents whose attestation is valid (signature checks) but whose
    /// attesting node is not currently in `node_trust` — e.g. the
    /// NodeAttestation hasn't synced yet, or admin never attested that
    /// node. Surfaced separately because the chain to admin is broken.
    orphan_agents: Vec<OrphanAgentRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OrphanAgentRow {
    pubkey: String,
    agent_id: String,
    role: String,
    revoked: bool,
    not_after_ns: u64,
    expired: bool,
    /// The (unknown) node pubkey this attestation claims.
    node_pubkey: String,
}

#[server]
async fn get_trust_tree() -> Result<TrustTree, ServerFnError> {
    use memvault_auth::jwt::NodeTrust;

    let client = crate::ui::state::local_client()?;
    let state = client
        .trust_state()
        .ok_or_else(|| ServerFnError::new("trust state not bootstrapped"))?;

    // Prefer the pinned AdminGenesis (cluster-wide truth) over the local
    // admin signing key (which is `None` on peer nodes). They must match
    // when both are set — bootstrap_cluster_trust enforces that.
    let admin_pubkey = client
        .pinned_admin_genesis()
        .map(|g| hex::encode(g.admin_pubkey))
        .or_else(|| {
            client
                .admin_verifying_key()
                .map(|k| hex::encode(k.to_bytes()))
        });
    let local_node_pubkey = client.node_verifying_key().map(|k| k.to_bytes());

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

    let now_ns = memvault_core::time::wall_ns();

    // Group every persisted AgentAttestation by its node pubkey. Orphans
    // (attesting node not in node_trust) get surfaced separately below.
    let mut atts_by_node: std::collections::HashMap<
        [u8; 32],
        Vec<memvault_auth::AgentAttestation>,
    > = std::collections::HashMap::new();
    if let Ok(atts) = memvault_api::sigchain::scan_agent_attestations(&*client) {
        for att in atts {
            atts_by_node.entry(att.node_pubkey).or_default().push(att);
        }
    }

    let mut nodes: Vec<NodeRow> = node_trust
        .iter()
        .map(|(pk, trust)| {
            let (kind, role, origin, not_after_ns) = match trust {
                NodeTrust::Attested(att) => (
                    "attested".to_string(),
                    // NodeAttestation carries no role.
                    None,
                    Some(match &att.issued_via {
                        memvault_auth::AttestationOrigin::Direct => "direct".to_string(),
                        memvault_auth::AttestationOrigin::TokenRedemption(_) => "token".to_string(),
                    }),
                    Some(att.not_after_ns),
                ),
                NodeTrust::PreGenesis => ("pre-genesis".to_string(), None, None, None),
            };
            let node_expired = not_after_ns
                .map(|n| n != u64::MAX && n < now_ns)
                .unwrap_or(false);
            let agents: Vec<AgentRow> = atts_by_node
                .get(pk)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|att| AgentRow {
                    pubkey: hex::encode(att.agent_pubkey),
                    agent_id: att.agent_id.0.clone(),
                    label: memvault_api::sigchain::agent_label(&*client, &att.agent_pubkey)
                        .ok()
                        .flatten(),
                    role: format!("{:?}", att.role),
                    revoked: revoked_agents.contains(&att.agent_pubkey),
                    not_after_ns: att.not_after_ns,
                    expired: att.not_after_ns != u64::MAX && att.not_after_ns < now_ns,
                })
                .collect();
            NodeRow {
                pubkey: hex::encode(pk),
                kind,
                revoked: revoked_nodes.contains(pk),
                is_local: local_node_pubkey
                    .as_ref()
                    .map(|local| local == pk)
                    .unwrap_or(false),
                role,
                origin,
                not_after_ns,
                expired: node_expired,
                agents,
            }
        })
        .collect();
    // Stable sort: local node first, then non-revoked, then by pubkey hex.
    nodes.sort_by(|a, b| {
        a.is_local
            .cmp(&b.is_local)
            .reverse()
            .then(a.revoked.cmp(&b.revoked))
            .then_with(|| a.pubkey.cmp(&b.pubkey))
    });

    // Orphans: AgentAttestations whose `node_pubkey` is not in node_trust.
    // These can't chain back to admin and so should not authenticate any
    // write — surfaced for diagnostic visibility, not as trusted entries.
    let revoked_agents_ref = &revoked_agents;
    let mut orphan_agents: Vec<OrphanAgentRow> = atts_by_node
        .iter()
        .filter(|(node_pk, _)| !node_trust.contains_key(*node_pk))
        .flat_map(|(node_pk, atts)| {
            let node_pubkey_hex = hex::encode(node_pk);
            atts.iter().map(move |att| OrphanAgentRow {
                pubkey: hex::encode(att.agent_pubkey),
                agent_id: att.agent_id.0.clone(),
                role: format!("{:?}", att.role),
                revoked: revoked_agents_ref.contains(&att.agent_pubkey),
                not_after_ns: att.not_after_ns,
                expired: att.not_after_ns != u64::MAX && att.not_after_ns < now_ns,
                node_pubkey: node_pubkey_hex.clone(),
            })
        })
        .collect();
    orphan_agents.sort_by(|a, b| {
        a.node_pubkey
            .cmp(&b.node_pubkey)
            .then(a.pubkey.cmp(&b.pubkey))
    });

    Ok(TrustTree {
        admin_pubkey,
        nodes,
        orphan_agents,
    })
}

/// Set an agent's display label (by hex pubkey). Display-only; never affects
/// access. Authorised for the agent's attesting node / admin.
#[server]
async fn rename_agent(pubkey: String, label: String) -> Result<(), ServerFnError> {
    use memvault_api::MemvaultClient;
    let bytes = hex::decode(&pubkey).map_err(|_| ServerFnError::new("invalid pubkey hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ServerFnError::new("agent pubkey must be 32 bytes"))?;
    let client = crate::ui::state::local_client()?;
    client
        .agent_rename(&arr, label.trim())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
}

/// Inline control to relabel an agent. Shows the current display name and,
/// on submit, calls [`rename_agent`] then refreshes the trust tree.
#[component]
fn AgentRenameControl(pubkey: String, current: String, on_saved: EventHandler<()>) -> Element {
    let mut editing = use_signal(|| false);
    let mut value = use_signal(|| current.clone());
    let mut saving = use_signal(|| false);

    if !editing() {
        return rsx! {
            button {
                class: "text-xs text-fg-muted hover:text-fg underline",
                onclick: move |_| editing.set(true),
                "rename"
            }
        };
    }

    let pubkey_for_save = pubkey.clone();
    rsx! {
        form {
            class: "flex items-center gap-1",
            onsubmit: move |evt: Event<FormData>| {
                // Without this the browser does a native form submit → full page reload.
                evt.prevent_default();
                let pk = pubkey_for_save.clone();
                let new_label = value();
                async move {
                    saving.set(true);
                    if rename_agent(pk, new_label).await.is_ok() {
                        editing.set(false);
                        // Ask the parent to refresh so the new label shows.
                        on_saved.call(());
                    }
                    saving.set(false);
                }
            },
            input {
                class: "px-1 py-0.5 text-xs border border-border rounded bg-bg",
                value: "{value}",
                disabled: saving(),
                oninput: move |e| value.set(e.value()),
            }
            button {
                r#type: "submit",
                class: "text-xs text-accent hover:underline",
                disabled: saving(),
                "save"
            }
            button {
                r#type: "button",
                class: "text-xs text-fg-muted hover:underline",
                onclick: move |_| editing.set(false),
                "cancel"
            }
        }
    }
}

#[component]
pub fn TrustTreePage() -> Element {
    use_topbar("Trust tree");
    let mut data = use_server_future(get_trust_tree)?;

    match &*data.read() {
        Some(Ok(tree)) => rsx! {
            TrustTreeView { tree: tree.clone(), on_refresh: move |_| data.restart() }
        },
        Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
        None => rsx! { p { class: "text-fg-muted", "Loading…" } },
    }
}

fn fmt_expiry(not_after_ns: u64) -> String {
    if not_after_ns == u64::MAX {
        return "never".to_string();
    }
    let now_ns = memvault_core::time::wall_ns();
    if not_after_ns <= now_ns {
        return "expired".to_string();
    }
    let remaining = not_after_ns - now_ns;
    let days = remaining / (24 * 60 * 60 * 1_000_000_000);
    let hours = (remaining / (60 * 60 * 1_000_000_000)) % 24;
    if days > 0 {
        format!("{days}d {hours}h")
    } else {
        let mins = (remaining / (60 * 1_000_000_000)) % 60;
        format!("{hours}h {mins}m")
    }
}

#[component]
fn TrustTreeView(tree: TrustTree, on_refresh: EventHandler<()>) -> Element {
    rsx! {
        div { class: "space-y-6",
            PageHeader { "Trust tree" }

            Card {
                div { class: "p-5 space-y-3",
                    SectionHeading { "Cluster admin" }
                    if let Some(pk) = &tree.admin_pubkey {
                        div { class: "flex items-center gap-2",
                            Pill { variant: PillVariant::Ok, "admin" }
                            span { class: "font-mono text-xs break-all", "{pk}" }
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
                                        if node.is_local {
                                            Pill { variant: PillVariant::Accent, "this node" }
                                        }
                                        if node.revoked {
                                            Pill { variant: PillVariant::Bad, "revoked" }
                                        } else if node.kind == "attested" {
                                            if node.expired {
                                                Pill { variant: PillVariant::Warn, "expired" }
                                            } else {
                                                Pill { variant: PillVariant::Ok, "node" }
                                            }
                                        } else {
                                            Pill { variant: PillVariant::Warn, "pre-genesis" }
                                        }
                                        span { class: "font-mono text-xs break-all", "{node.pubkey}" }
                                        if let Some(role) = &node.role {
                                            Pill { variant: PillVariant::Info, "{role}" }
                                        }
                                        if let Some(origin) = &node.origin {
                                            Pill { variant: PillVariant::Muted, "via {origin}" }
                                        }
                                        if let Some(exp) = node.not_after_ns {
                                            span { class: "text-xs text-fg-muted",
                                                "expires: {fmt_expiry(exp)}"
                                            }
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
                                                    class: "flex items-center gap-2 flex-wrap",
                                                    if agent.revoked {
                                                        Pill { variant: PillVariant::Bad, "agent (revoked)" }
                                                    } else if agent.expired {
                                                        Pill { variant: PillVariant::Warn, "agent (expired)" }
                                                    } else {
                                                        Pill { variant: PillVariant::Muted, "agent" }
                                                    }
                                                    span { class: "font-medium text-sm", "{agent.display_name()}" }
                                                    if agent.label.is_some() && !agent.agent_id.is_empty() {
                                                        span { class: "font-mono text-xs text-fg-muted", "({agent.agent_id})" }
                                                    }
                                                    span { class: "font-mono text-xs break-all", "{agent.pubkey}" }
                                                    Pill { variant: PillVariant::Info, "{agent.role}" }
                                                    span { class: "text-xs text-fg-muted",
                                                        "expires: {fmt_expiry(agent.not_after_ns)}"
                                                    }
                                                    AgentRenameControl {
                                                        pubkey: agent.pubkey.clone(),
                                                        current: agent.display_name(),
                                                        on_saved: move |_| on_refresh.call(()),
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

            if !tree.orphan_agents.is_empty() {
                Card {
                    div { class: "p-5 space-y-3",
                        SectionHeading {
                            "Orphan agents ({tree.orphan_agents.len()})"
                        }
                        p { class: "text-sm text-fg-muted",
                            "Agent attestations whose attesting node is not (yet?) trusted on this daemon. "
                            "They may appear once their NodeAttestation syncs in, or be permanently broken if admin never attested that node."
                        }
                        ul { class: "space-y-2",
                            for agent in &tree.orphan_agents {
                                li { key: "{agent.pubkey}",
                                    class: "flex items-center gap-2 flex-wrap border-l-2 border-warn pl-3",
                                    if agent.revoked {
                                        Pill { variant: PillVariant::Bad, "revoked" }
                                    } else if agent.expired {
                                        Pill { variant: PillVariant::Warn, "expired" }
                                    } else {
                                        Pill { variant: PillVariant::Warn, "orphan" }
                                    }
                                    span { class: "font-mono text-sm", "{agent.agent_id}" }
                                    span { class: "font-mono text-xs break-all", "{agent.pubkey}" }
                                    Pill { variant: PillVariant::Info, "{agent.role}" }
                                    span { class: "text-xs text-fg-muted", "claims node " }
                                    span { class: "font-mono text-xs break-all", "{agent.node_pubkey}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
