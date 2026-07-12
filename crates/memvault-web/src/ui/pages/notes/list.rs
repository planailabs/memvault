//! Notes list page.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{DataTable, PageHeader, SortState, SortableTh, Td, TdMuted, page_window};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::components::tag_pills::TagPills;
use crate::ui::components::time_ago::TimeAgo;
use crate::ui::components::visibility_pill::VisibilityPill;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NoteRow {
    id: String,
    title: String,
    tags: Vec<(String, String)>,
    visibility: String,
    attachment_count: usize,
    updated_ns: u64,
}

impl NoteRow {
    fn matches_search(&self, query: &str) -> bool {
        self.title.to_lowercase().contains(query)
            || self
                .tags
                .iter()
                .any(|(s, l)| s.to_lowercase().contains(query) || l.to_lowercase().contains(query))
    }
}

#[server]
async fn list_notes(
    view: Option<String>,
    bucket_hex: Option<String>,
    show_retracted: bool,
) -> Result<Vec<NoteRow>, ServerFnError> {
    let client = crate::ui::state::client()?;

    let bucket_id = bucket_hex.as_deref().and_then(|h| {
        let bytes = hex::decode(h).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(memvault_core::BucketId(arr))
    });

    // If a view is active, scope by (view ∩ bucket ∩ retracted) via list_scoped
    // — the old view path ignored the active bucket entirely. (Doc-only rows
    // carry no attachment count / mtime here, as before.)
    if view.is_some() {
        let scope = crate::ui::state::query_scope(
            view,
            bucket_hex.into_iter().collect(),
            show_retracted,
            Some(memvault_core::NodeKind::Document),
        );
        let items = client
            .list_scoped(&scope, 500)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        return Ok(items
            .into_iter()
            .map(|n| NoteRow {
                id: n.node_id,
                title: n.label,
                tags: n.tags,
                visibility: "internal".to_string(),
                attachment_count: 0,
                updated_ns: 0,
            })
            .collect());
    }

    let docs = client
        .list_docs_ex(None, 500, bucket_id.as_ref(), show_retracted)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(docs
        .into_iter()
        .map(|d| NoteRow {
            id: format!("doc:{}", hex::encode(d.id.0)),
            title: d.title.unwrap_or_else(|| "Untitled".to_string()),
            tags: d.tags,
            visibility: "internal".to_string(),
            attachment_count: d.attachment_count,
            updated_ns: d.updated_ns,
        })
        .collect())
}

#[component]
pub fn NoteList() -> Element {
    use_topbar(&t!("notes-title"));
    let filters = crate::ui::filters::use_filters();
    let notes = use_server_future(move || {
        let f = filters.read();
        async move { list_notes(f.view, f.bucket, f.show_retracted).await }
    })?;
    // `use_server_future` fetches on mount/SSR but isn't reactive to in-place
    // signal changes — it only re-runs on remount (route change). Re-fetch
    // when the scope (view/bucket/retracted/epoch) changes while on the page.
    use_effect(move || {
        let _ = filters.read();
        let mut r = notes;
        r.restart();
    });

    rsx! {
        div { class: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4",
            PageHeader { class: "mb-0", {t!("notes-title")} }
            Link { to: Route::NoteForm {}, class: "btn btn-md btn-primary",
                {t!("notes-new")}
            }
        }
        {match &*notes.read() {
            Some(Ok(list)) => rsx! { NoteTable { list: list.clone() } },
            Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
            None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
        }}
    }
}

#[component]
fn NoteTable(list: ReadSignal<Vec<NoteRow>>) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 20usize);
    let page = use_signal(|| 0usize);
    let sort = use_signal::<SortState>(|| ("updated".to_string(), false));

    let filtered = use_memo(move || {
        // Read the `list` prop reactively so this memo re-runs when the
        // parent re-fetches on a scope (bucket/view/retracted) change.
        // Capturing a plain Vec here instead would leave the table showing
        // stale data after the scope changed.
        let list = list.read();
        let q = search.read().to_lowercase();
        let mut items: Vec<NoteRow> = if q.is_empty() {
            list.clone()
        } else {
            list.iter()
                .filter(|n| n.matches_search(&q))
                .cloned()
                .collect()
        };
        let (key, asc) = sort.read().clone();
        items.sort_by(|a, b| {
            let ord = match key.as_str() {
                "title" => a.title.to_lowercase().cmp(&b.title.to_lowercase()),
                "attachments" => a.attachment_count.cmp(&b.attachment_count),
                _ => a.updated_ns.cmp(&b.updated_ns),
            };
            if asc { ord } else { ord.reverse() }
        });
        items
    });

    let total = list.read().len();
    let filtered_count = filtered.read().len();
    let limit_val = *limit.read();
    let (start, shown) = page_window(*page.read(), limit_val, filtered_count);

    rsx! {
        DataTable {
            search, limit, page, total, filtered: filtered_count, shown,
            headers: rsx! {
                SortableTh { label: t!("notes-th-title"), sort_key: "title".to_string(), sort }
                th { class: "th", {t!("notes-th-tags")} }
                th { class: "th", {t!("notes-th-visibility")} }
                SortableTh { label: t!("notes-th-files"), sort_key: "attachments".to_string(), sort }
                SortableTh { label: t!("notes-th-updated"), sort_key: "updated".to_string(), sort }
            },
            body: rsx! {
                for note in filtered.read().iter().skip(start).take(limit_val) {
                    NoteRowView { key: "{note.id}", note: note.clone() }
                }
            },
        }
    }
}

#[component]
fn NoteRowView(note: NoteRow) -> Element {
    rsx! {
        tr {
            Td {
                Link { to: Route::NoteDetail { id: note.id.clone() }, class: "link",
                    "{note.title}"
                }
            }
            Td { TagPills { tags: note.tags.clone() } }
            Td { VisibilityPill { visibility: note.visibility.clone() } }
            Td { class: "text-center", "{note.attachment_count}" }
            TdMuted { TimeAgo { wall_ns: note.updated_ns } }
        }
    }
}
