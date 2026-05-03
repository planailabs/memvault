//! Note history page — document audit trail.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader};
use serde::{Deserialize, Serialize};

use crate::ui::components::cid_display::CidDisplay;
use crate::ui::components::op_kind_badge::OpKindBadge;
use crate::ui::components::time_ago::TimeAgo;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct HistoryEntry {
    cid: String,
    op_kind: String,
    wall_ns: u64,
    author: String,
}

#[server]
async fn get_note_history(id: String) -> Result<Vec<HistoryEntry>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let doc_id = crate::api::docs::parse_doc_id(&id)
        .map_err(|e| ServerFnError::new(format!("{e}")))?;
    let records = client
        .history_of(&doc_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(records
        .into_iter()
        .map(|r| HistoryEntry {
            cid: hex::encode(&r.cid),
            op_kind: format!("{:?}", r.op_kind),
            wall_ns: r.wall_ns,
            author: hex::encode(&r.author),
        })
        .collect())
}

#[component]
pub fn NoteHistory(id: String) -> Element {
    use_topbar("Note History");
    let history = use_server_future(move || {
        let id = id.clone();
        async move { get_note_history(id).await }
    })?;

    rsx! {
        div { class: "space-y-4",
            PageHeader { "History" }

            {match &*history.read() {
                Some(Ok(entries)) => rsx! {
                    Card {
                        div { class: "divide-y divide-line",
                            for entry in entries {
                                div { class: "flex items-center gap-3 px-5 py-3",
                                    OpKindBadge { kind: entry.op_kind.clone() }
                                    div { class: "flex-1 min-w-0",
                                        span { class: "text-sm text-fg-muted", "by " }
                                        CidDisplay { cid: entry.author.clone(), len: Some(8) }
                                    }
                                    TimeAgo { wall_ns: entry.wall_ns }
                                    CidDisplay { cid: entry.cid.clone() }
                                }
                            }
                            if entries.is_empty() {
                                div { class: "px-5 py-8 text-center text-fg-muted",
                                    "No history entries."
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
