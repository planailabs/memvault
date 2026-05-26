//! Bucket list page — shows all buckets with status, actions.

use dioxus::prelude::*;
use plan_ai_design::{
    Button, ButtonVariant, Card, DataTable, PageHeader, Pill, PillVariant, SortState, SortableTh,
    Td, TdMuted,
};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BucketRow {
    id_hex: String,
    name: String,
    status: String,      // "unbound", "private", "attached", "archived"
    cluster_hex: String, // empty if unbound
    is_default: bool,
    envelope_count: u64,
}

impl BucketRow {
    fn matches_search(&self, query: &str) -> bool {
        self.name.to_lowercase().contains(query)
            || self.status.contains(query)
            || self.id_hex.contains(query)
    }
}

#[server]
async fn list_buckets() -> Result<Vec<BucketRow>, ServerFnError> {
    let client = crate::ui::state::client()?;
    let buckets = client
        .bucket_list()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(buckets
        .into_iter()
        .map(|b| {
            let status = if b.name.contains("[ARCHIVED]") {
                "archived"
            } else if !b.is_attached {
                "private"
            } else if b.cluster_id.is_none() {
                "unbound"
            } else {
                "attached"
            };
            BucketRow {
                id_hex: hex::encode(b.id.0),
                name: b.name,
                status: status.to_string(),
                cluster_hex: b.cluster_id.map(|c| hex::encode(c.0)).unwrap_or_default(),
                is_default: b.is_default,
                envelope_count: b.envelope_count,
            }
        })
        .collect())
}

#[server]
async fn create_bucket(name: String) -> Result<String, ServerFnError> {
    let client = crate::ui::state::client()?;
    let bid = client
        .bucket_create(
            &name,
            None,
            memvault_core::Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(hex::encode(bid.0))
}

fn pill_for_status(status: &str) -> Element {
    let variant = match status {
        "unbound" => PillVariant::Muted,
        "private" => PillVariant::Warn,
        "attached" => PillVariant::Ok,
        "archived" => PillVariant::Bad,
        _ => PillVariant::Muted,
    };
    rsx! { Pill { variant, "{status}" } }
}

#[component]
pub fn BucketList() -> Element {
    use_topbar("Buckets");
    let buckets = use_server_future(list_buckets)?;
    let mut show_create = use_signal(|| false);
    let mut new_name = use_signal(String::new);

    rsx! {
        div { class: "space-y-4",
            div { class: "flex items-center justify-between",
                PageHeader { class: "mb-0", "Buckets" }
                Button {
                    variant: ButtonVariant::Primary,
                    onclick: move |_| show_create.set(true),
                    "New Bucket"
                }
            }

            if *show_create.read() {
                Card {
                    div { class: "p-5 space-y-3",
                        div {
                            label { class: "text-xs text-fg-muted", "Bucket Name" }
                            input {
                                class: "input input-sm w-full mt-1",
                                r#type: "text",
                                placeholder: "e.g. research, archive, shared",
                                value: "{new_name}",
                                oninput: move |e: Event<FormData>| new_name.set(e.value()),
                            }
                        }
                        div { class: "flex gap-2",
                            Button {
                                variant: ButtonVariant::Primary,
                                onclick: move |_| {
                                    let name = new_name.read().trim().to_string();
                                    if !name.is_empty() {
                                        spawn(async move {
                                            let _ = create_bucket(name).await;
                                            show_create.set(false);
                                            new_name.set(String::new());
                                        });
                                    }
                                },
                                "Create"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                onclick: move |_| show_create.set(false),
                                "Cancel"
                            }
                        }
                    }
                }
            }

            match &*buckets.read() {
                Some(Ok(list)) if !list.is_empty() => rsx! {
                    BucketTable { list: list.clone() }
                },
                Some(Ok(_)) => rsx! {
                    Card {
                        div { class: "p-8 text-center text-fg-muted",
                            "No buckets yet. Create one to get started."
                        }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", "Loading..." } },
            }
        }
    }
}

#[component]
fn BucketTable(list: Vec<BucketRow>) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 20usize);
    let sort = use_signal::<SortState>(|| ("name".to_string(), true));

    let list_clone = list.clone();
    let filtered = use_memo(move || {
        let q = search.read().to_lowercase();
        let mut items: Vec<BucketRow> = if q.is_empty() {
            list_clone.clone()
        } else {
            list_clone
                .iter()
                .filter(|b| b.matches_search(&q))
                .cloned()
                .collect()
        };
        let (key, asc) = sort.read().clone();
        items.sort_by(|a, b| {
            let ord = match key.as_str() {
                "status" => a.status.cmp(&b.status),
                "items" => a.envelope_count.cmp(&b.envelope_count),
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
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
                SortableTh { label: "Name".to_string(), sort_key: "name".to_string(), sort }
                SortableTh { label: "Status".to_string(), sort_key: "status".to_string(), sort }
                th { class: "th", "Cluster" }
                SortableTh { label: "Items".to_string(), sort_key: "items".to_string(), sort }
            },
            body: rsx! {
                for b in filtered.read().iter().take(limit_val) {
                    tr {
                        key: "{b.id_hex}",
                        class: "cursor-pointer hover:bg-surface-3",
                        onclick: {
                            let id = b.id_hex.clone();
                            move |_| {
                                navigator().push(Route::BucketDetail { id: id.clone() });
                            }
                        },
                        Td {
                            span { class: "font-medium text-fg-strong", "{b.name}" }
                            if b.is_default {
                                Pill { variant: PillVariant::Info, class: "ml-2", "default" }
                            }
                        }
                        Td { {pill_for_status(&b.status)} }
                        TdMuted {
                            {
                                if b.cluster_hex.is_empty() {
                                    "\u{2014}".to_string()
                                } else {
                                    b.cluster_hex.chars().take(8).collect::<String>()
                                }
                            }
                        }
                        Td { class: "text-right tabular-nums", "{b.envelope_count}" }
                    }
                }
            },
        }
    }
}
