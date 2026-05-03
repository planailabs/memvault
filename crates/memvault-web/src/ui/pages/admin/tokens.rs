//! Token management page.

use dioxus::prelude::*;
use plan_ai_design::{Button, ButtonVariant, Card, FormField, PageHeader, Pill, PillVariant, Td, TdMuted};
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
    use memvault_auth::Role;

    let client = crate::ui::state::client()?;
    let role = match role.as_str() {
        "Admin" => Role::Admin,
        "AgentHost" => Role::AgentHost,
        "Auditor" => Role::Auditor,
        _ => Role::Service,
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
    use_topbar("Tokens");
    let mut tokens = use_server_future(list_tokens)?;
    let mut show_form = use_signal(|| false);
    let mut new_role = use_signal(|| "Service".to_string());
    let mut new_label = use_signal(String::new);
    let mut new_max_uses = use_signal(|| "1000".to_string());
    let mut issued_token = use_signal(|| None::<String>);
    let mut error = use_signal(|| None::<String>);

    let on_issue = move |_: Event<FormData>| {
        let role = new_role.read().clone();
        let label = new_label.read().clone();
        let max_uses: u32 = new_max_uses.read().parse().unwrap_or(1000);
        spawn(async move {
            match issue_token(role, label, max_uses).await {
                Ok(token) => {
                    issued_token.set(Some(token));
                    tokens.restart();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center justify-between",
                PageHeader { class: "mb-0", "API Tokens" }
                Button {
                    variant: ButtonVariant::Primary,
                    onclick: move |_| { let v = *show_form.read(); show_form.set(!v); },
                    "Issue Token"
                }
            }

            if let Some(err) = &*error.read() {
                div { class: "alert alert-danger", "{err}" }
            }

            if let Some(token) = &*issued_token.read() {
                div { class: "alert alert-success",
                    p { class: "font-semibold", "Token issued! Copy it now — it won't be shown again:" }
                    code { class: "block mt-1 font-mono text-sm break-all", "{token}" }
                }
            }

            if *show_form.read() {
                Card {
                    form { class: "p-5 space-y-3", onsubmit: on_issue,
                        div { class: "flex gap-3",
                            div { class: "flex-1",
                                FormField { label: "Label".to_string(),
                                    input {
                                        class: "input input-sm",
                                        placeholder: "Token label",
                                        value: "{new_label}",
                                        oninput: move |e: Event<FormData>| new_label.set(e.value()),
                                    }
                                }
                            }
                            div { class: "w-36",
                                FormField { label: "Role".to_string(),
                                    select {
                                        class: "input input-sm",
                                        value: "{new_role}",
                                        onchange: move |e: Event<FormData>| new_role.set(e.value()),
                                        option { value: "Service", "Service" }
                                        option { value: "AgentHost", "Agent Host" }
                                        option { value: "Auditor", "Auditor" }
                                        option { value: "Admin", "Admin" }
                                    }
                                }
                            }
                            div { class: "w-28",
                                FormField { label: "Max Uses".to_string(),
                                    input {
                                        class: "input input-sm",
                                        r#type: "number",
                                        value: "{new_max_uses}",
                                        oninput: move |e: Event<FormData>| new_max_uses.set(e.value()),
                                    }
                                }
                            }
                        }
                        Button { variant: ButtonVariant::Primary, "Issue" }
                    }
                }
            }

            {match &*tokens.read() {
                Some(Ok(list)) => rsx! {
                    Card {
                        table { class: "table",
                            thead { class: "thead",
                                tr {
                                    th { class: "th", "Label" }
                                    th { class: "th", "Role" }
                                    th { class: "th", "Used" }
                                    th { class: "th", "Status" }
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
                                                        Pill { variant: PillVariant::Bad, "Revoked" }
                                                    } else {
                                                        Pill { variant: PillVariant::Ok, "Active" }
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
                                                            "Revoke"
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
                None => rsx! { p { class: "text-fg-muted", "Loading..." } },
            }}
        }
    }
}
