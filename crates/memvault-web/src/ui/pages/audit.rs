//! Audit log page — filterable audit trail.

use dioxus::prelude::*;
use dioxus_i18n::t;
use plan_ai_design::{
    DataTable, FormField, PageHeader, Pill, PillVariant, SortState, SortableTh, Td, TdMuted,
};
use serde::{Deserialize, Serialize};

use crate::ui::app::Route;
use crate::ui::components::cid_display::CidDisplay;
use crate::ui::components::op_kind_badge::OpKindBadge;
use crate::ui::components::time_ago::TimeAgo;
use crate::ui::topbar::use_topbar;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AuditRow {
    cid: String,
    op_kind: String,
    author: String,
    wall_ns: u64,
    /// Human-readable description built from op_kind + tags + resolved labels.
    description: String,
    /// Optional link target (Route-compatible id).
    link_target: Option<AuditLink>,
    tags: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AuditLink {
    kind: String, // "note", "entity", "file"
    id: String,
    label: String,
}

impl AuditRow {
    fn matches_search(&self, query: &str) -> bool {
        self.op_kind.to_lowercase().contains(query)
            || self.description.to_lowercase().contains(query)
            || self.author.contains(query)
            || self.cid.contains(query)
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

    let mut rows = Vec::new();
    for r in records {
        let op_kind = format!("{:?}", r.op_kind);

        // Build description and link from op_kind + tags
        let (description, link_target) =
            build_description(&client, &op_kind, &r.tags, r.doc_id.as_ref()).await;

        rows.push(AuditRow {
            cid: hex::encode(&r.cid),
            op_kind,
            author: hex::encode(&r.author),
            wall_ns: r.wall_ns,
            description,
            link_target,
            tags: r.tags,
        });
    }
    Ok(rows)
}

#[cfg(feature = "server")]
async fn resolve_node(
    client: &std::sync::Arc<dyn memvault_api::MemvaultClient>,
    node_tag: &str,
) -> (String, Option<AuditLink>) {
    // Try text index first (fast).
    if let Ok(Some(label)) = client.resolve_label(node_tag).await {
        let link = audit_link_from_tag(node_tag, &label);
        return (label, link);
    }
    // Also try with legacy "attachment:" prefix if "file:" lookup failed.
    if node_tag.starts_with("file:") {
        let legacy = format!("attachment:{}", &node_tag[5..]);
        if let Ok(Some(label)) = client.resolve_label(&legacy).await {
            let link = audit_link_from_tag(node_tag, &label);
            return (label, link);
        }
    }
    // Fall back to fetching the actual object for its name.
    if let Some(node_ref) = memvault_core::NodeRef::from_tag_label(node_tag) {
        let label = match &node_ref {
            memvault_core::NodeRef::Doc(did) => {
                client.get_doc(did).await.ok().flatten().and_then(|d| {
                    d.frontmatter
                        .get("title")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
            }
            memvault_core::NodeRef::Entity(eid) => {
                client.get_entity(eid).await.ok().flatten().and_then(|e| {
                    e.props
                        .get("name")
                        .or_else(|| e.props.get("title"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
            }
            memvault_core::NodeRef::Attachment(cid) => client
                .get_file_manifest(cid)
                .await
                .ok()
                .flatten()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|v| {
                    v.get("filename")
                        .and_then(|f| f.as_str())
                        .map(|s| s.to_string())
                }),
        };
        if let Some(name) = label {
            let link = audit_link_from_tag(node_tag, &name);
            return (name, link);
        }
    }
    let display = short_id(node_tag);
    let link = audit_link_from_tag(node_tag, &display);
    (display, link)
}

#[cfg(feature = "server")]
async fn build_description(
    client: &std::sync::Arc<dyn memvault_api::MemvaultClient>,
    op_kind: &str,
    tags: &[(String, String)],
    _doc_id: Option<&memvault_core::DocId>,
) -> (String, Option<AuditLink>) {
    let doc_tag = tags
        .iter()
        .find(|(s, _)| s == "doc")
        .map(|(_, l)| l.as_str());
    let entity_tag = tags
        .iter()
        .find(|(s, _)| s == "entity")
        .map(|(_, l)| l.as_str());
    let edge_source = tags
        .iter()
        .find(|(s, _)| s == "edge_source")
        .map(|(_, l)| l.as_str());
    let edge_target = tags
        .iter()
        .find(|(s, _)| s == "edge_target")
        .map(|(_, l)| l.as_str());
    // Unified annotation target (type:hex node_id)
    let ann_target = tags
        .iter()
        .find(|(s, _)| s == "_ann")
        .map(|(_, l)| l.as_str());

    match op_kind {
        "DocCreate" => {
            if let Some(hex_id) = doc_tag {
                let (name, link) = resolve_node(client, &format!("doc:{hex_id}")).await;
                (format!("Created document \"{name}\""), link)
            } else {
                ("Created document".to_string(), None)
            }
        }
        "DocEdit" => {
            if let Some(hex_id) = doc_tag {
                let (name, link) = resolve_node(client, &format!("doc:{hex_id}")).await;
                (format!("Edited \"{name}\""), link)
            } else {
                ("Edited document".to_string(), None)
            }
        }
        "DocSetMeta" | "DocRemoveMeta" => {
            if let Some(hex_id) = doc_tag {
                let (name, link) = resolve_node(client, &format!("doc:{hex_id}")).await;
                (format!("Updated metadata on \"{name}\""), link)
            } else {
                ("Updated document metadata".to_string(), None)
            }
        }
        "AttachFile" => {
            if let Some(hex_id) = doc_tag {
                let (name, link) = resolve_node(client, &format!("doc:{hex_id}")).await;
                (format!("Attached file to \"{name}\""), link)
            } else if let Some(target) = ann_target {
                let (name, link) = resolve_node(client, target).await;
                (format!("Attached file \"{name}\""), link)
            } else {
                ("Attached file".to_string(), None)
            }
        }
        "DetachFile" => {
            if let Some(hex_id) = doc_tag {
                let (name, link) = resolve_node(client, &format!("doc:{hex_id}")).await;
                (format!("Detached file from \"{name}\""), link)
            } else {
                ("Detached file".to_string(), None)
            }
        }
        "EntityCreate" => {
            if let Some(hex_id) = entity_tag {
                let (name, link) = resolve_node(client, &format!("entity:{hex_id}")).await;
                (format!("Created entity \"{name}\""), link)
            } else {
                ("Created entity".to_string(), None)
            }
        }
        "EdgeAdd" => {
            let (src, _) = if let Some(s) = edge_source {
                resolve_node(client, s).await
            } else {
                ("?".to_string(), None)
            };
            let (tgt, _) = if let Some(t) = edge_target {
                resolve_node(client, t).await
            } else {
                ("?".to_string(), None)
            };
            let link = edge_source.and_then(|s| audit_link_from_tag(s, &src));
            (format!("Linked {src} \u{2192} {tgt}"), link)
        }
        "EdgeRemove" => {
            let (src, _) = if let Some(s) = edge_source {
                resolve_node(client, s).await
            } else {
                ("?".to_string(), None)
            };
            let link = edge_source.and_then(|s| audit_link_from_tag(s, &src));
            (format!("Removed edge from {src}"), link)
        }
        "Retract" => {
            if let Some(target) = ann_target {
                let (name, link) = resolve_node(client, target).await;
                (format!("Retracted \"{name}\""), link)
            } else if let Some(hex_id) = doc_tag {
                let (name, link) = resolve_node(client, &format!("doc:{hex_id}")).await;
                (format!("Retracted \"{name}\""), link)
            } else if let Some(hex_id) = entity_tag {
                let (name, link) = resolve_node(client, &format!("entity:{hex_id}")).await;
                (format!("Retracted entity \"{name}\""), link)
            } else {
                ("Retracted item".to_string(), None)
            }
        }
        "TagUpdate" => {
            if let Some(target) = ann_target {
                let (name, link) = resolve_node(client, target).await;
                (format!("Updated tags on \"{name}\""), link)
            } else {
                ("Updated tags".to_string(), None)
            }
        }
        "Extraction" => {
            if let Some(target) = ann_target {
                let (name, link) = resolve_node(client, target).await;
                (format!("Extracted text from \"{name}\""), link)
            } else {
                ("Extracted text".to_string(), None)
            }
        }
        // ── Bucket events ────────────────────────────────────────
        "BucketCreate" => {
            let bucket_tag = tags
                .iter()
                .find(|(s, _)| s == "bucket")
                .map(|(_, l)| l.as_str());
            // Try to resolve bucket name from the store.
            if let Some(bid) = bucket_tag {
                if let Ok(Some(info)) = resolve_bucket_name(client, bid).await {
                    (format!("Created bucket \"{info}\""), None)
                } else {
                    (format!("Created bucket {}", short_id(bid)), None)
                }
            } else {
                ("Created bucket".to_string(), None)
            }
        }
        "BucketRename" => {
            let bucket_tag = tags
                .iter()
                .find(|(s, _)| s == "bucket")
                .map(|(_, l)| l.as_str());
            (
                format!(
                    "Renamed bucket {}",
                    bucket_tag.map(short_id).unwrap_or("?".into())
                ),
                None,
            )
        }
        "BucketAttach" => {
            let bucket_tag = tags
                .iter()
                .find(|(s, _)| s == "bucket")
                .map(|(_, l)| l.as_str());
            (
                format!(
                    "Attached bucket {} to cluster",
                    bucket_tag.map(short_id).unwrap_or("?".into())
                ),
                None,
            )
        }
        "BucketArchive" => {
            let bucket_tag = tags
                .iter()
                .find(|(s, _)| s == "bucket")
                .map(|(_, l)| l.as_str());
            (
                format!(
                    "Archived bucket {}",
                    bucket_tag.map(short_id).unwrap_or("?".into())
                ),
                None,
            )
        }
        "BucketBind" => {
            let bucket_tag = tags
                .iter()
                .find(|(s, _)| s == "bucket")
                .map(|(_, l)| l.as_str());
            (
                format!(
                    "Bound bucket {} to cluster",
                    bucket_tag.map(short_id).unwrap_or("?".into())
                ),
                None,
            )
        }
        "BucketTrust" => ("Cross-cluster bucket trust established".to_string(), None),
        // ── View events ─────────────────────────────────────────
        "ViewCreate" => {
            let view_tag = tags
                .iter()
                .find(|(s, _)| s == "view")
                .map(|(_, l)| l.as_str());
            (
                format!(
                    "Created view {}",
                    view_tag.map(short_id).unwrap_or("?".into())
                ),
                None,
            )
        }
        // ── Token events ────────────────────────────────────────
        "TokenIssue" | "JoinToken" => {
            let label = tags
                .iter()
                .find(|(s, _)| s == "role")
                .map(|(_, l)| l.as_str());
            (
                format!("Issued join token (role: {})", label.unwrap_or("?")),
                None,
            )
        }
        // ── Share events ────────────────────────────────────────
        "SharePropose" => ("Sent share proposal".to_string(), None),
        "ShareDecide" => ("Decided share proposal".to_string(), None),
        other => {
            if let Some(target) = ann_target {
                let (name, link) = resolve_node(client, target).await;
                (format!("{other} on \"{name}\""), link)
            } else {
                (other.to_string(), None)
            }
        }
    }
}

#[cfg(feature = "server")]
async fn resolve_bucket_name(
    client: &std::sync::Arc<dyn memvault_api::MemvaultClient>,
    bucket_tag: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // bucket_tag is the bs58-encoded bucket ID from the tag.
    // Try to find it via bucket_list.
    let buckets = client.bucket_list().await?;
    for b in &buckets {
        if b.id.to_string() == bucket_tag || hex::encode(b.id.0) == bucket_tag {
            return Ok(Some(b.name.clone()));
        }
    }
    Ok(None)
}

#[cfg(feature = "server")]
fn short_id(tag_label: &str) -> String {
    if let Some((_prefix, hex)) = tag_label.split_once(':') {
        if hex.len() > 12 {
            format!("{}...", &hex[..12])
        } else {
            hex.to_string()
        }
    } else if tag_label.len() > 12 {
        format!("{}...", &tag_label[..12])
    } else {
        tag_label.to_string()
    }
}

#[cfg(feature = "server")]
fn audit_link_from_tag(tag_label: &str, label: &str) -> Option<AuditLink> {
    let (prefix, hex) = tag_label.split_once(':')?;
    let kind = match prefix {
        "entity" => "entity",
        "doc" => "note",
        "file" | "attachment" => "file",
        _ => return None,
    };
    Some(AuditLink {
        kind: kind.to_string(),
        id: hex.to_string(),
        label: label.to_string(),
    })
}

#[component]
pub fn AuditLog() -> Element {
    use_topbar(&t!("audit-title"));
    let audit = use_server_future(|| list_audit(500))?;

    rsx! {
        div { class: "space-y-4",
            PageHeader { {t!("audit-title")} }
            {match &*audit.read() {
                Some(Ok(list)) => rsx! { AuditTable { list: list.clone() } },
                Some(Err(e)) => rsx! { p { class: "text-danger", "Error: {e}" } },
                None => rsx! { p { class: "text-fg-muted", {t!("loading")} } },
            }}
        }
    }
}

#[component]
fn AuditTable(list: Vec<AuditRow>) -> Element {
    let search = use_signal(String::new);
    let limit = use_signal(|| 50usize);
    let sort = use_signal::<SortState>(|| ("time".to_string(), false));
    let mut op_filter = use_signal(|| "all".to_string());
    let mut author_filter = use_signal(String::new);

    let list_clone = list.clone();
    let filtered = use_memo(move || {
        let q = search.read().to_lowercase();
        let op = op_filter.read().clone();
        let auth = author_filter.read().to_lowercase();

        let mut items: Vec<AuditRow> = list_clone
            .iter()
            .filter(|r| {
                let text_match = q.is_empty() || r.matches_search(&q);
                let op_match = op == "all" || r.op_kind == op;
                let author_match = auth.is_empty() || r.author.contains(&auth);
                text_match && op_match && author_match
            })
            .cloned()
            .collect();

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

    // Collect unique op kinds for filter dropdown.
    let mut op_kinds: Vec<String> = list.iter().map(|r| r.op_kind.clone()).collect();
    op_kinds.sort();
    op_kinds.dedup();

    rsx! {
        // Filter row
        div { class: "flex flex-wrap gap-3 mb-3",
            div { class: "w-40",
                FormField { label: t!("audit-th-operation"),
                    select {
                        class: "input input-sm",
                        value: "{op_filter}",
                        onchange: move |e: Event<FormData>| op_filter.set(e.value()),
                        option { value: "all", {t!("all")} }
                        for kind in &op_kinds {
                            option { value: "{kind}", "{kind}" }
                        }
                    }
                }
            }
            div { class: "w-48",
                FormField { label: t!("audit-th-author"),
                    input {
                        class: "input input-sm",
                        r#type: "text",
                        placeholder: t!("audit-placeholder-author"),
                        value: "{author_filter}",
                        oninput: move |e: Event<FormData>| author_filter.set(e.value()),
                    }
                }
            }
        }

        DataTable {
            search, limit, total, filtered: filtered_count, shown,
            headers: rsx! {
                SortableTh { label: t!("audit-th-operation"), sort_key: "op".to_string(), sort }
                th { class: "th", {t!("audit-th-description")} }
                SortableTh { label: t!("audit-th-author"), sort_key: "author".to_string(), sort }
                SortableTh { label: t!("audit-th-time"), sort_key: "time".to_string(), sort }
            },
            body: rsx! {
                for row in filtered.read().iter().take(limit_val) {
                    tr { key: "{row.cid}",
                        Td { OpKindBadge { kind: row.op_kind.clone() } }
                        Td {
                            div { class: "space-y-1",
                                // Main description with optional link
                                div { class: "text-sm",
                                    if let Some(link) = &row.link_target {
                                        {
                                            let route = match link.kind.as_str() {
                                                "note" => Route::NoteDetail { id: link.id.clone() },
                                                "entity" => Route::EntityDetail { id: link.id.clone() },
                                                "file" => Route::FileDetail { cid: link.id.clone() },
                                                _ => Route::NoteList {},
                                            };
                                            rsx! {
                                                Link { to: route, class: "link", "{row.description}" }
                                            }
                                        }
                                    } else {
                                        span { "{row.description}" }
                                    }
                                }
                                // Tags as small pills underneath
                                if !row.tags.is_empty() {
                                    div { class: "flex flex-wrap gap-1",
                                        for (scope, label) in &row.tags {
                                            // Skip internal indexing tags that are already reflected in the description
                                            if scope != "doc" && scope != "entity" && scope != "edge_source" && scope != "edge_target" {
                                                Pill { variant: PillVariant::Muted,
                                                    span { class: "text-[10px]", "{scope}:{label}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Td { CidDisplay { cid: row.author.clone(), len: Some(8) } }
                        TdMuted { TimeAgo { wall_ns: row.wall_ns } }
                    }
                }
            },
        }
    }
}
