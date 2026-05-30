//! Token management page.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{
    Button, ButtonVariant, Card, FormField, PageHeader, Pill, PillVariant, Td, TdMuted,
};
use serde::{Deserialize, Serialize};

use crate::ui::components::cid_display::CidDisplay;
use crate::ui::topbar::use_topbar;

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
async fn list_tokens() -> Result<Vec<TokenRow>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let tokens = client
        .list_tokens()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(tokens
        .into_iter()
        .map(|t| TokenRow {
            cid: hex::encode(&t.cid),
            label: t.label,
            role: format!("{:?}", t.role),
            max_uses: t.max_uses,
            consumed_count: t.consumed_count,
            revoked: t.revoked,
        })
        .collect())
}

#[server]
async fn issue_token(role: String, label: String, max_uses: u32) -> Result<String, ServerFnError> {
    use memvault_auth::{AgentRole, NodeRole, TokenRole};

    let client = crate::ui::state::client()?;
    // `role` is a category-qualified value: "agent:<role>" or "node:<role>".
    let role = match role.as_str() {
        "agent:agenthost" => TokenRole::Agent(AgentRole::AgentHost),
        "agent:auditor" => TokenRole::Agent(AgentRole::Auditor),
        "agent:service" => TokenRole::Agent(AgentRole::Service),
        "agent:admin" => TokenRole::Agent(AgentRole::Admin),
        "node:node" => TokenRole::Node(NodeRole::Node),
        "node:admin" => TokenRole::Node(NodeRole::Admin),
        other => return Err(ServerFnError::new(format!("unknown role: {other}"))),
    };
    let label = if label.is_empty() { None } else { Some(label) };
    let token = client
        .issue_token(role, 30 * 86400, max_uses, label)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(token)
}

#[server]
async fn revoke_token(cid: String) -> Result<(), ServerFnError> {
    let client = crate::ui::state::client()?;
    let cid_bytes = hex::decode(&cid).map_err(|_| ServerFnError::new("Invalid CID"))?;
    client
        .revoke_token(&cid_bytes, "revoked via web UI")
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(())
}

#[component]
pub fn TokenManagement() -> Element {
    use_topbar(&t!("tokens-title"));
    let mut tokens = use_server_future(list_tokens)?;
    let mut show_form = use_signal(|| false);
    let mut new_role = use_signal(|| "agent:service".to_string());
    let mut new_label = use_signal(String::new);
    let mut new_max_uses = use_signal(|| "1000".to_string());
    let mut issued_token = use_signal(|| None::<String>);
    // Tracks whether the most-recently-issued token was for agent
    // enrollment, so the success card can render an `agent-enroll`
    // command snippet alongside the token.
    let mut issued_agent_id = use_signal(|| None::<String>);
    let mut error = use_signal(|| None::<String>);

    let on_issue = move |e: Event<FormData>| {
        e.prevent_default();
        let role = new_role.read().clone();
        let label = new_label.read().clone();
        let max_uses: u32 = new_max_uses.read().parse().unwrap_or(1000);
        let agent_id_for_success = if role == "agent:agenthost" && !label.is_empty() {
            Some(label.clone())
        } else {
            None
        };
        spawn(async move {
            match issue_token(role, label, max_uses).await {
                Ok(token) => {
                    issued_token.set(Some(token));
                    issued_agent_id.set(agent_id_for_success);
                    tokens.restart();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    // "Enroll an agent" shortcut: pre-populates the form for the
    // common case (Role=AgentHost, max_uses=1, label = agent id).
    // Operator types the agent id and submits; the success card shows
    // the resulting `memctl agent-enroll` invocation.
    let prefill_enrollment = move |_| {
        new_role.set("agent:agenthost".to_string());
        new_max_uses.set("1".to_string());
        new_label.set(String::new());
        show_form.set(true);
    };

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center justify-between",
                PageHeader { class: "mb-0", {t!("tokens-title")} }
                div { class: "flex gap-2",
                    Button {
                        variant: ButtonVariant::Secondary,
                        onclick: prefill_enrollment,
                        "Enroll an agent"
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        onclick: move |_| { let v = *show_form.read(); show_form.set(!v); },
                        {t!("tokens-issue")}
                    }
                }
            }

            if let Some(err) = &*error.read() {
                div { class: "alert alert-danger", "{err}" }
            }

            if let Some(token) = &*issued_token.read() {
                div { class: "alert alert-success",
                    p { class: "font-semibold", {t!("tokens-issued-message")} }
                    code { class: "block mt-1 font-mono text-sm break-all", "{token}" }
                    if let Some(agent_id) = &*issued_agent_id.read() {
                        p { class: "mt-3 text-sm",
                            "Run on the agent host (or this node) to enroll:"
                        }
                        code { class: "block mt-1 font-mono text-sm break-all",
                            "memctl agent enroll --agent-id {agent_id} --token {token}"
                        }
                    }
                }
            }

            if *show_form.read() {
                Card {
                    form { class: "p-5 space-y-3", onsubmit: on_issue,
                        div { class: "flex gap-3",
                            div { class: "flex-1",
                                FormField { label: t!("tokens-th-label"),
                                    input {
                                        class: "input input-sm",
                                        placeholder: t!("tokens-placeholder-label"),
                                        value: "{new_label}",
                                        oninput: move |e: Event<FormData>| new_label.set(e.value()),
                                    }
                                }
                            }
                            div { class: "w-36",
                                FormField { label: t!("tokens-th-role"),
                                    select {
                                        class: "input input-sm",
                                        value: "{new_role}",
                                        onchange: move |e: Event<FormData>| new_role.set(e.value()),
                                        optgroup { label: "Agent roles",
                                            option { value: "agent:agenthost", {t!("tokens-role-agent-host")} }
                                            option { value: "agent:auditor", {t!("tokens-role-auditor")} }
                                            option { value: "agent:service", {t!("tokens-role-service")} }
                                            option { value: "agent:admin", {t!("tokens-role-admin")} }
                                        }
                                        optgroup { label: "Node roles",
                                            option { value: "node:node", {t!("tokens-role-node")} }
                                            option { value: "node:admin", {t!("tokens-role-admin")} }
                                        }
                                    }
                                }
                            }
                            div { class: "w-28",
                                FormField { label: t!("tokens-placeholder-max-uses"),
                                    input {
                                        class: "input input-sm",
                                        r#type: "number",
                                        value: "{new_max_uses}",
                                        oninput: move |e: Event<FormData>| new_max_uses.set(e.value()),
                                    }
                                }
                            }
                        }
                        Button { variant: ButtonVariant::Primary, {t!("tokens-issue-button")} }
                    }
                }
            }

            {match &*tokens.read() {
                Some(Ok(list)) => rsx! {
                    Card {
                        table { class: "table",
                            thead { class: "thead",
                                tr {
                                    th { class: "th", {t!("tokens-th-label")} }
                                    th { class: "th", {t!("tokens-th-role")} }
                                    th { class: "th", {t!("tokens-th-used")} }
                                    th { class: "th", {t!("tokens-th-status")} }
                                    th { class: "th", "" }
                                }
                            }
                            tbody { class: "tbody",
                                for token in list {
                                    {
                                        let revoke_cid = token.cid.clone();
                                        rsx! {
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
                                                Td {
                                                    if !token.revoked {
                                                        button {
                                                            class: "btn btn-xs btn-danger",
                                                            onclick: move |_| {
                                                                let cid = revoke_cid.clone();
                                                                spawn(async move {
                                                                    let _ = revoke_token(cid).await;
                                                                    tokens.restart();
                                                                });
                                                            },
                                                            {t!("tokens-revoke")}
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
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
            }}
        }
    }
}
