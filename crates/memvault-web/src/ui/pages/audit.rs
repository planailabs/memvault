//! Audit log page — filterable audit trail.

use dioxus::prelude::*;
use plan_ai_design::{DataTable, PageHeader, SortState, SortableTh, Td, TdMuted};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::components::op_kind_badge::OpKindBadge;
use crate::ui::components::tag_pills::TagPills;
use crate::ui::components::time_ago::TimeAgo;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AuditRow {
    cid: String,
    op_kind: String,
    author: String,
    wall_ns: u64,
    doc_id: Option<String>,
    tags: Vec<(String, String)>,
}

impl AuditRow {
    fn matches_search(&self, query: &str) -> bool {
        self.op_kind.to_lowercase().contains(query)
            || self.author.contains(query)
            || self.cid.contains(query)
            || self.doc_id.as_ref().is_some_and(|d| d.contains(query))
    }
}

#[server]
async fn list_audit(limit: usize) -> Result<Vec<AuditRow>, ServerFnError> {
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
        .map(|r| AuditRow {
            cid: hex::encode(&r.cid),
            op_kind: format!("{:?}", r.op_kind),
            author: hex::encode(&r.author),
            wall_ns: r.wall_ns,
            doc_id: r.doc_id.map(|d| hex::encode(d.0)),
            tags: r.tags,
        })
        .collect())
}

#[component]
pub fn AuditLog() -> Element {
    use_topbar("Audit");
    let audit = use_server_future(|| list_audit(500))?;

    rsx! {
        div { class: "space-y-4",
            PageHeader { "Audit Trail" }
            {match &*audit.read() {
                Some(Ok(list)) => rsx! { AuditTable { list: list.clone() } },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", "Loading..." } },
            }}
        }
    }
}

#[component]
fn AuditTable(list: Vec<AuditRow>) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 50usize);
    let sort = use_signal::<SortState>(|| ("time".to_string(), false));

    let list_clone = list.clone();
    let filtered = use_memo(move || {
        let q = search.read().to_lowercase();
        let mut items: Vec<AuditRow> = if q.is_empty() {
            list_clone.clone()
        } else {
            list_clone.iter().filter(|r| r.matches_search(&q)).cloned().collect()
        };
        let (key, asc) = sort.read().clone();
        items.sort_by(|a, b| {
            let ord = match key.as_str() {
                "op" => a.op_kind.cmp(&b.op_kind),
                "author" => a.author.cmp(&b.author),
                _ => a.wall_ns.cmp(&b.wall_ns),
            };
            if asc { ord } else { ord.reverse() }
        });
        items
    });

    let total = list.len();
    let filtered_count = filtered.read().len();
    let limit_val = *limit.read();
    let shown = filtered_count.min(limit_val);

    rsx! {
        DataTable {
            search, limit, total, filtered: filtered_count, shown,
            headers: rsx! {
                th { class: "th", "CID" }
                SortableTh { label: "Operation".to_string(), sort_key: "op".to_string(), sort }
                SortableTh { label: "Author".to_string(), sort_key: "author".to_string(), sort }
                th { class: "th", "Document" }
                th { class: "th", "Tags" }
                SortableTh { label: "Time".to_string(), sort_key: "time".to_string(), sort }
            },
            body: rsx! {
                for row in filtered.read().iter().take(limit_val) {
                    tr { key: "{row.cid}",
                        Td { CidDisplay { cid: row.cid.clone() } }
                        Td { OpKindBadge { kind: row.op_kind.clone() } }
                        Td { CidDisplay { cid: row.author.clone(), len: Some(8) } }
                        Td {
                            if let Some(doc_id) = &row.doc_id {
                                Link { to: Route::NoteDetail { id: doc_id.clone() }, class: "link",
                                    CidDisplay { cid: doc_id.clone(), len: Some(8) }
                                }
                            } else {
                                span { class: "text-fg-faint", "—" }
                            }
                        }
                        Td { TagPills { tags: row.tags.clone() } }
                        TdMuted { TimeAgo { wall_ns: row.wall_ns } }
                    }
                }
            },
        }
    }
}
