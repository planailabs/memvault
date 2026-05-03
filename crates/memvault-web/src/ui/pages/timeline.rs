//! Timeline page — chronological activity feed.

use dioxus::prelude::*;
use plan_ai_design::{Card, PageHeader};
use serde::{Deserialize, Serialize};

use crate::ui::components::cid_display::CidDisplay;
use crate::ui::components::op_kind_badge::OpKindBadge;
use crate::ui::components::time_ago::TimeAgo;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TimelineEntry {
    cid: String,
    op_kind: String,
    author: String,
    wall_ns: u64,
    doc_id: Option<String>,
    /// Formatted date for grouping (YYYY-MM-DD).
    date: String,
}

#[server]
async fn get_timeline(limit: usize) -> Result<Vec<TimelineEntry>, ServerFnError> {
    use memvault_query::AuditQuery;

    let client = crate::ui::state::client()?;
    let records = client
        .audit(AuditQuery {
            limit: Some(limit),
            ..Default::default()
        })
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(records
        .into_iter()
        .map(|r| {
            let secs = r.wall_ns / 1_000_000_000;
            let date = chrono::DateTime::from_timestamp(secs as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d").to_string())
                .unwrap_or_default();
            TimelineEntry {
                cid: hex::encode(&r.cid),
                op_kind: format!("{:?}", r.op_kind),
                author: hex::encode(&r.author),
                wall_ns: r.wall_ns,
                doc_id: r.doc_id.map(|d| hex::encode(d.0)),
                date,
            }
        })
        .collect())
}

#[component]
pub fn Timeline() -> Element {
    use_topbar("Timeline");
    let entries = use_server_future(|| get_timeline(200))?;

    rsx! {
        div { class: "space-y-4 max-w-2xl mx-auto",
            PageHeader { "Timeline" }
            {match &*entries.read() {
                Some(Ok(list)) => rsx! { TimelineView { entries: list.clone() } },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", "Loading..." } },
            }}
        }
    }
}

#[component]
fn TimelineView(entries: Vec<TimelineEntry>) -> Element {
    if entries.is_empty() {
        return rsx! {
            Card {
                div { class: "p-8 text-center text-fg-muted",
                    "No activity yet."
                }
            }
        };
    }

    // Group by date.
    let mut groups: Vec<(String, Vec<TimelineEntry>)> = Vec::new();
    for entry in &entries {
        if let Some((date, group)) = groups.last_mut() {
            if *date == entry.date {
                group.push(entry.clone());
                continue;
            }
        }
        groups.push((entry.date.clone(), vec![entry.clone()]));
    }

    rsx! {
        div { class: "space-y-6",
            for (date, group) in &groups {
                div {
                    h3 { class: "text-sm font-semibold text-fg-muted mb-2", "{date}" }
                    Card {
                        div { class: "divide-y divide-line",
                            for entry in group {
                                div { class: "flex items-center gap-3 px-4 py-3",
                                    OpKindBadge { kind: entry.op_kind.clone() }
                                    div { class: "flex-1 min-w-0",
                                        span { class: "text-sm text-fg-muted", "by " }
                                        CidDisplay { cid: entry.author.clone(), len: Some(8) }
                                    }
                                    TimeAgo { wall_ns: entry.wall_ns }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
