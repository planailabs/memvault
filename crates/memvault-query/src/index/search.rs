//! Unified full-text search index for memvault — indexes documents, entities, and attachments.

use std::collections::{HashMap, HashSet};

use memvault_core::{DocId, RetractionMode};
use serde::{Deserialize, Serialize};

/// A legacy search hit (doc-only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub doc_id: DocId,
    pub score: f32,
    pub snippet: String,
}

/// A unified search hit that covers all node types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedHit {
    pub node_id: String,
    pub node_type: String,
    pub label: String,
    pub score: f32,
    pub snippet: String,
    pub match_contexts: Vec<String>,
}

/// Parameters for a search query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: String,
    pub limit: usize,
    pub tag_filter: Option<(String, String)>,
}

/// Indexed entry for any node type.
#[derive(Serialize, Deserialize)]
struct IndexedEntry {
    node_type: String,
    label: String,
    text: String,
    tags: Vec<(String, String)>,
}

/// Bump this when the index format changes to trigger automatic re-indexing.
///
/// v6: retraction retains the indexed entry (flag-only) instead of deleting it,
/// so retracted nodes — with their labels/tags — remain visible under
/// `RetractionMode::{IncludeRetracted,RetractedOnly}`. Old v5 caches dropped
/// retracted entries, so they must be rebuilt.
pub const INDEX_FORMAT_VERSION: u32 = 6;

#[derive(Serialize, Deserialize)]
struct IndexSnapshot {
    version: u32,
    unified: HashMap<String, IndexedEntry>,
    #[serde(default)]
    retracted: HashSet<String>,
}

/// In-memory full-text search index (simple TF-based).
pub struct TextIndex {
    unified: HashMap<String, IndexedEntry>,
    retracted: HashSet<String>,
}

impl TextIndex {
    pub fn new() -> Self {
        Self {
            unified: HashMap::new(),
            retracted: HashSet::new(),
        }
    }

    /// Save the index atomically (write to temp, then rename).
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let snapshot = IndexSnapshot {
            version: INDEX_FORMAT_VERSION,
            unified: self
                .unified
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        IndexedEntry {
                            node_type: v.node_type.clone(),
                            label: v.label.clone(),
                            text: v.text.clone(),
                            tags: v.tags.clone(),
                        },
                    )
                })
                .collect(),
            retracted: self.retracted.clone(),
        };
        let data = serde_json::to_vec(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &data)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load from cache. Returns None if missing, corrupt, or stale version.
    pub fn load(path: &std::path::Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        let snapshot: IndexSnapshot = serde_json::from_slice(&data).ok()?;
        if snapshot.version != INDEX_FORMAT_VERSION {
            return None;
        }
        Some(Self {
            unified: snapshot.unified,
            retracted: snapshot.retracted,
        })
    }

    pub fn len(&self) -> usize {
        self.unified.len()
    }
    pub fn is_empty(&self) -> bool {
        self.unified.is_empty()
    }

    // ── Indexing ───────────────────────────────────────────────────

    pub fn index_doc(
        &mut self,
        doc_id: DocId,
        body: &str,
        title: Option<&str>,
        tags: Vec<(String, String)>,
    ) {
        let label = title.unwrap_or("Untitled").to_string();
        let node_id = format!("doc:{}", hex::encode(doc_id.0));
        let mut text_parts = vec![body.to_string()];
        if let Some(t) = title {
            text_parts.push(t.to_string());
        }
        for (scope, lbl) in &tags {
            text_parts.push(format!("{scope}:{lbl}"));
        }
        self.unified.insert(
            node_id,
            IndexedEntry {
                node_type: "doc".to_string(),
                label,
                text: text_parts.join(" "),
                tags,
            },
        );
    }

    pub fn index_entity(
        &mut self,
        entity_id: &memvault_core::EntityId,
        kind: &str,
        props: &std::collections::BTreeMap<String, serde_json::Value>,
        tags: Vec<(String, String)>,
    ) {
        let node_id = format!("entity:{}", hex::encode(entity_id.0));
        let label = props
            .get("name")
            .or_else(|| props.get("title"))
            .and_then(|v| v.as_str())
            .unwrap_or(kind)
            .to_string();
        let mut text_parts = vec![kind.to_string(), label.clone()];
        for (key, val) in props {
            text_parts.push(key.clone());
            match val {
                serde_json::Value::String(s) => text_parts.push(s.clone()),
                other => text_parts.push(other.to_string()),
            }
        }
        for (scope, lbl) in &tags {
            text_parts.push(format!("{scope}:{lbl}"));
        }
        self.unified.insert(
            node_id,
            IndexedEntry {
                node_type: "entity".to_string(),
                label,
                text: text_parts.join(" "),
                tags,
            },
        );
    }

    pub fn index_attachment(
        &mut self,
        manifest_cid: &[u8],
        filename: Option<&str>,
        mime_type: &str,
        extracted_text: Option<&str>,
        tags: Vec<(String, String)>,
    ) {
        let node_id = format!("file:{}", hex::encode(manifest_cid));
        let label = filename.unwrap_or("unnamed file").to_string();
        let mut text_parts = vec![label.clone(), mime_type.to_string()];
        if let Some(f) = filename {
            for part in f.split(|c: char| c == '.' || c == '-' || c == '_' || c == ' ') {
                if !part.is_empty() {
                    text_parts.push(part.to_string());
                }
            }
        }
        if let Some(text) = extracted_text {
            text_parts.push(text.to_string());
        }
        for (scope, lbl) in &tags {
            text_parts.push(format!("{scope}:{lbl}"));
        }
        self.unified.insert(
            node_id,
            IndexedEntry {
                node_type: "file".to_string(),
                label,
                text: text_parts.join(" "),
                tags,
            },
        );
    }

    pub fn remove_doc(&mut self, doc_id: &DocId) {
        let node_id = format!("doc:{}", hex::encode(doc_id.0));
        self.unified.remove(&node_id);
    }

    // ── Retraction ─────────────────────────────────────────────────

    /// Mark a node retracted. The indexed entry is **retained** (so the node's
    /// label/tags remain available to admins/auditors under
    /// `RetractionMode::{IncludeRetracted,RetractedOnly}`); only the flag flips.
    pub fn retract_node(&mut self, node_id: &str) {
        self.retracted.insert(node_id.to_string());
    }

    /// Clear a node's retracted flag.
    pub fn unretract_node(&mut self, node_id: &str) {
        self.retracted.remove(node_id);
    }

    pub fn is_retracted(&self, node_id: &str) -> bool {
        self.retracted.contains(node_id)
    }

    /// Whether a node passes the given retraction mode's filter.
    fn passes_mode(&self, node_id: &str, mode: RetractionMode) -> bool {
        mode.admits(self.retracted.contains(node_id))
    }

    // ── Tags ───────────────────────────────────────────────────────

    pub fn apply_tag_update(
        &mut self,
        node_id: &str,
        add: &[(String, String)],
        remove: &[(String, String)],
    ) {
        if let Some(entry) = self.unified.get_mut(node_id) {
            entry.tags.retain(|t| !remove.contains(t));
            for tag in add {
                if !entry.tags.contains(tag) {
                    entry.tags.push(tag.clone());
                }
            }
        }
    }

    pub fn get_tags(&self, node_id: &str) -> Vec<(String, String)> {
        self.unified
            .get(node_id)
            .map(|e| e.tags.clone())
            .unwrap_or_default()
    }

    // ── Queries ────────────────────────────────────────────────────

    pub fn members_of_view(&self, required_tags: &[(String, String)]) -> Vec<String> {
        self.members_of_view_ex(required_tags, false)
    }

    /// As [`members_of_view`], but when `include_retracted` is true the
    /// retracted-node filter is skipped (auditor/admin view).
    pub fn members_of_view_ex(
        &self,
        required_tags: &[(String, String)],
        include_retracted: bool,
    ) -> Vec<String> {
        if required_tags.is_empty() {
            if include_retracted {
                return self.unified.keys().cloned().collect();
            }
            return self
                .unified
                .keys()
                .filter(|id| !self.retracted.contains(id.as_str()))
                .cloned()
                .collect();
        }
        self.unified
            .iter()
            .filter(|(id, entry)| {
                (include_retracted || !self.retracted.contains(id.as_str()))
                    && required_tags.iter().all(|(scope, label)| {
                        entry.tags.iter().any(|(s, l)| s == scope && l == label)
                    })
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn list_all(
        &self,
        view_tags: Option<&[(String, String)]>,
        limit: usize,
    ) -> Vec<(String, String, String, Vec<(String, String)>)> {
        self.list_all_ex(view_tags, limit, false)
    }

    /// As [`list_all`], but when `include_retracted` is true retracted nodes
    /// are included (auditor/admin view).
    pub fn list_all_ex(
        &self,
        view_tags: Option<&[(String, String)]>,
        limit: usize,
        include_retracted: bool,
    ) -> Vec<(String, String, String, Vec<(String, String)>)> {
        self.unified
            .iter()
            .filter(|(id, entry)| {
                if !include_retracted && self.retracted.contains(id.as_str()) {
                    return false;
                }
                if let Some(tags) = view_tags {
                    tags.iter().all(|(scope, label)| {
                        entry.tags.iter().any(|(s, l)| s == scope && l == label)
                    })
                } else {
                    true
                }
            })
            .take(limit)
            .map(|(id, entry)| {
                (
                    id.clone(),
                    entry.node_type.clone(),
                    entry.label.clone(),
                    entry.tags.clone(),
                )
            })
            .collect()
    }

    pub fn resolve_label(&self, node_id: &str) -> Option<String> {
        self.resolve_label_ex(node_id, false)
    }

    /// As [`resolve_label`], but when `include_retracted` is true a retracted
    /// node's label still resolves (auditor/admin view).
    pub fn resolve_label_ex(&self, node_id: &str, include_retracted: bool) -> Option<String> {
        if !include_retracted && self.retracted.contains(node_id) {
            return None;
        }
        self.unified.get(node_id).map(|e| e.label.clone())
    }

    /// Legacy doc-only search. Returns SearchHit with DocId.
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchHit> {
        self.search_filtered(query, None, limit, false)
    }

    /// As [`search`], but when `include_retracted` is true retracted docs are
    /// included (auditor/admin view).
    pub fn search_ex(&self, query: &str, limit: usize, include_retracted: bool) -> Vec<SearchHit> {
        self.search_filtered(query, None, limit, include_retracted)
    }

    pub fn search_query(&self, query: &SearchQuery) -> Vec<SearchHit> {
        let limit = if query.limit == 0 { 10 } else { query.limit };
        self.search_filtered(&query.text, query.tag_filter.as_ref(), limit, false)
    }

    fn search_filtered(
        &self,
        query: &str,
        tag_filter: Option<&(String, String)>,
        limit: usize,
        include_retracted: bool,
    ) -> Vec<SearchHit> {
        let query_lower = query.to_lowercase();
        let terms: Vec<&str> = query_lower.split_whitespace().collect();
        if terms.is_empty() {
            return Vec::new();
        }

        let mut hits: Vec<SearchHit> = Vec::new();
        for (node_id, entry) in &self.unified {
            if entry.node_type != "doc" {
                continue;
            }
            if !include_retracted && self.retracted.contains(node_id) {
                continue;
            }
            if let Some((scope, label)) = tag_filter {
                if !entry.tags.iter().any(|(s, l)| s == scope && l == label) {
                    continue;
                }
            }
            let text_lower = entry.text.to_lowercase();
            let label_lower = entry.label.to_lowercase();
            let mut score: f32 = 0.0;
            let mut matched = false;
            for term in &terms {
                let text_count = text_lower.matches(term).count();
                let label_count = label_lower.matches(term).count();
                if text_count > 0 || label_count > 0 {
                    matched = true;
                    score += text_count as f32 + label_count as f32 * 3.0;
                }
            }
            if matched {
                // Parse doc_id from node_id "doc:<hex>"
                if let Some(hex_str) = node_id.strip_prefix("doc:") {
                    if let Ok(bytes) = hex::decode(hex_str) {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            hits.push(SearchHit {
                                doc_id: DocId(arr),
                                score,
                                snippet: extract_snippet(&entry.text, &terms),
                            });
                        }
                    }
                }
            }
        }
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(limit);
        hits
    }

    /// Unified search across all indexed nodes.
    pub fn search_unified(&self, query: &str, limit: usize) -> Vec<UnifiedHit> {
        self.search_unified_ex(query, limit, false)
    }

    /// As [`search_unified`], but when `include_retracted` is true retracted
    /// nodes are included in the results (auditor/admin view).
    pub fn search_unified_ex(
        &self,
        query: &str,
        limit: usize,
        include_retracted: bool,
    ) -> Vec<UnifiedHit> {
        let query_lower = query.to_lowercase();
        let terms: Vec<&str> = query_lower.split_whitespace().collect();
        if terms.is_empty() {
            return Vec::new();
        }

        let mut hits: Vec<UnifiedHit> = Vec::new();
        for (node_id, entry) in &self.unified {
            if !include_retracted && self.retracted.contains(node_id.as_str()) {
                continue;
            }
            let text_lower = entry.text.to_lowercase();
            let label_lower = entry.label.to_lowercase();
            let mut score: f32 = 0.0;
            let mut matched = false;
            for term in &terms {
                let text_count = text_lower.matches(term).count();
                let label_count = label_lower.matches(term).count();
                if text_count > 0 || label_count > 0 {
                    matched = true;
                    score += text_count as f32 + label_count as f32 * 3.0;
                }
            }
            if matched {
                hits.push(UnifiedHit {
                    node_id: node_id.clone(),
                    node_type: entry.node_type.clone(),
                    label: entry.label.clone(),
                    score,
                    snippet: extract_snippet(&entry.text, &terms),
                    match_contexts: extract_match_contexts(&entry.text, &terms, 3),
                });
            }
        }
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(limit);
        hits
    }
    // ── RetractionMode-aware queries (scoped-indexes) ──────────────
    //
    // These supersede the boolean `_ex` variants: they support all three
    // modes (active-only / include-retracted / retracted-only) and, because
    // retraction now retains the entry, can actually surface retracted nodes.

    /// View members filtered by retraction mode.
    pub fn members_of_view_mode(
        &self,
        required_tags: &[(String, String)],
        mode: RetractionMode,
    ) -> Vec<String> {
        self.unified
            .iter()
            .filter(|(id, entry)| {
                self.passes_mode(id, mode)
                    && required_tags.iter().all(|(scope, label)| {
                        entry.tags.iter().any(|(s, l)| s == scope && l == label)
                    })
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// List all nodes (optionally view-filtered) by retraction mode, with each
    /// row's retracted flag. Returns (node_id, node_type, label, tags, retracted).
    #[allow(clippy::type_complexity)]
    pub fn list_all_mode(
        &self,
        view_tags: Option<&[(String, String)]>,
        mode: RetractionMode,
        limit: usize,
    ) -> Vec<(String, String, String, Vec<(String, String)>, bool)> {
        self.unified
            .iter()
            .filter(|(id, entry)| {
                if !self.passes_mode(id, mode) {
                    return false;
                }
                match view_tags {
                    Some(tags) => tags.iter().all(|(scope, label)| {
                        entry.tags.iter().any(|(s, l)| s == scope && l == label)
                    }),
                    None => true,
                }
            })
            .take(limit)
            .map(|(id, entry)| {
                (
                    id.clone(),
                    entry.node_type.clone(),
                    entry.label.clone(),
                    entry.tags.clone(),
                    self.retracted.contains(id),
                )
            })
            .collect()
    }

    /// Unified search filtered by retraction mode.
    pub fn search_unified_mode(
        &self,
        query: &str,
        mode: RetractionMode,
        limit: usize,
    ) -> Vec<UnifiedHit> {
        let query_lower = query.to_lowercase();
        let terms: Vec<&str> = query_lower.split_whitespace().collect();
        if terms.is_empty() {
            return Vec::new();
        }
        let mut hits: Vec<UnifiedHit> = Vec::new();
        for (node_id, entry) in &self.unified {
            if !self.passes_mode(node_id, mode) {
                continue;
            }
            let text_lower = entry.text.to_lowercase();
            let label_lower = entry.label.to_lowercase();
            let mut score: f32 = 0.0;
            let mut matched = false;
            for term in &terms {
                let text_count = text_lower.matches(term).count();
                let label_count = label_lower.matches(term).count();
                if text_count > 0 || label_count > 0 {
                    matched = true;
                    score += text_count as f32 + label_count as f32 * 3.0;
                }
            }
            if matched {
                hits.push(UnifiedHit {
                    node_id: node_id.clone(),
                    node_type: entry.node_type.clone(),
                    label: entry.label.clone(),
                    score,
                    snippet: extract_snippet(&entry.text, &terms),
                    match_contexts: extract_match_contexts(&entry.text, &terms, 3),
                });
            }
        }
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(limit);
        hits
    }

    /// Resolve a node's label under a retraction mode.
    pub fn resolve_label_mode(&self, node_id: &str, mode: RetractionMode) -> Option<String> {
        if !self.passes_mode(node_id, mode) {
            return None;
        }
        self.unified.get(node_id).map(|e| e.label.clone())
    }
}

impl Default for TextIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn extract_match_contexts(body: &str, terms: &[&str], max: usize) -> Vec<String> {
    let body_lower = body.to_lowercase();
    let mut positions: Vec<usize> = Vec::new();
    for term in terms {
        let mut start = 0;
        while let Some(pos) = body_lower[start..].find(term) {
            positions.push(start + pos);
            start += pos + term.len();
        }
    }
    positions.sort();
    positions.dedup();
    let mut contexts = Vec::new();
    let mut last_end: usize = 0;
    for &pos in &positions {
        if contexts.len() >= max {
            break;
        }
        let window_start = pos.saturating_sub(40);
        if window_start < last_end && !contexts.is_empty() {
            continue;
        }
        let snip: String = body.chars().skip(window_start).take(100).collect();
        let prefix = if window_start > 0 { "..." } else { "" };
        let suffix = if window_start + 100 < body.len() {
            "..."
        } else {
            ""
        };
        contexts.push(format!("{prefix}{snip}{suffix}"));
        last_end = window_start + 100;
    }
    contexts
}

fn extract_snippet(body: &str, terms: &[&str]) -> String {
    let body_lower = body.to_lowercase();
    let mut earliest_pos = body.len();
    for term in terms {
        if let Some(pos) = body_lower.find(term) {
            earliest_pos = earliest_pos.min(pos);
        }
    }
    if earliest_pos == body.len() {
        return body.chars().take(100).collect();
    }
    let start = earliest_pos.saturating_sub(30);
    let snippet: String = body.chars().skip(start).take(120).collect();
    if start > 0 {
        format!("...{snippet}")
    } else {
        snippet
    }
}
