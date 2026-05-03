//! Unified full-text search index for memvault — indexes documents, entities, and attachments.

use std::collections::HashMap;

use memvault_core::DocId;
use serde::{Deserialize, Serialize};

/// A search hit from the full-text index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub doc_id: DocId,
    pub score: f32,
    pub snippet: String,
}

/// A unified search hit that covers all node types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedHit {
    /// Node reference in tag_label format: "entity:<hex>", "doc:<hex>", "attachment:<hex>"
    pub node_id: String,
    /// "entity", "doc", "attachment"
    pub node_type: String,
    /// Human-readable label (title, name, filename, kind)
    pub label: String,
    pub score: f32,
    pub snippet: String,
}

/// Parameters for a search query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: String,
    pub limit: usize,
    pub tag_filter: Option<(String, String)>,
}

/// In-memory full-text search index (simple TF-based).
pub struct TextIndex {
    docs: HashMap<DocId, IndexedDoc>,
    /// Unified entries keyed by tag_label (e.g. "entity:abc123")
    unified: HashMap<String, IndexedEntry>,
}

#[derive(Serialize, Deserialize)]
struct IndexedDoc {
    body: String,
    title: Option<String>,
    tags: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
struct IndexedEntry {
    node_type: String,
    label: String,
    /// Searchable text blob (all concatenated searchable fields)
    text: String,
    tags: Vec<(String, String)>,
}

/// Bump this when the index format changes to trigger automatic re-indexing.
pub const INDEX_FORMAT_VERSION: u32 = 1;

/// Serializable snapshot of the entire index (for persistence).
#[derive(Serialize, Deserialize)]
struct IndexSnapshot {
    /// Format version — if this doesn't match INDEX_FORMAT_VERSION, the index is stale.
    version: u32,
    docs: HashMap<String, IndexedDoc>,     // hex-encoded DocId -> doc
    unified: HashMap<String, IndexedEntry>,
}

impl TextIndex {
    pub fn new() -> Self {
        Self {
            docs: HashMap::new(),
            unified: HashMap::new(),
        }
    }

    /// Save the index to a file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let snapshot = IndexSnapshot {
            version: INDEX_FORMAT_VERSION,
            docs: self.docs.iter()
                .map(|(k, v)| (hex::encode(k.0), IndexedDoc {
                    body: v.body.clone(),
                    title: v.title.clone(),
                    tags: v.tags.clone(),
                }))
                .collect(),
            unified: self.unified.iter()
                .map(|(k, v)| (k.clone(), IndexedEntry {
                    node_type: v.node_type.clone(),
                    label: v.label.clone(),
                    text: v.text.clone(),
                    tags: v.tags.clone(),
                }))
                .collect(),
        };
        let data = serde_json::to_vec(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, &data)
    }

    /// Load the index from a file. Returns `None` if the file doesn't exist,
    /// is corrupt, or has an outdated format version (caller should re-index).
    pub fn load(path: &std::path::Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        let snapshot: IndexSnapshot = serde_json::from_slice(&data).ok()?;
        if snapshot.version != INDEX_FORMAT_VERSION {
            return None; // stale format, needs re-indexing
        }
        let docs = snapshot.docs.into_iter()
            .filter_map(|(hex_id, doc)| {
                let bytes = hex::decode(&hex_id).ok()?;
                if bytes.len() != 32 { return None; }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some((DocId(arr), doc))
            })
            .collect();
        Some(Self {
            docs,
            unified: snapshot.unified,
        })
    }

    /// Number of entries in the unified index.
    pub fn len(&self) -> usize {
        self.unified.len()
    }

    pub fn is_empty(&self) -> bool {
        self.unified.is_empty()
    }

    /// Index a document's body text and metadata.
    pub fn index_doc(
        &mut self,
        doc_id: DocId,
        body: &str,
        title: Option<&str>,
        tags: Vec<(String, String)>,
    ) {
        let label = title.unwrap_or("Untitled").to_string();
        let node_id = format!("doc:{}", hex::encode(doc_id.0));

        // Unified entry
        let mut text_parts = vec![body.to_string()];
        if let Some(t) = title {
            text_parts.push(t.to_string());
        }
        for (scope, lbl) in &tags {
            text_parts.push(format!("{scope}:{lbl}"));
        }
        self.unified.insert(node_id, IndexedEntry {
            node_type: "doc".to_string(),
            label: label.clone(),
            text: text_parts.join(" "),
            tags: tags.clone(),
        });

        // Legacy doc index
        self.docs.insert(
            doc_id,
            IndexedDoc {
                body: body.to_string(),
                title: title.map(|s| s.to_string()),
                tags,
            },
        );
    }

    /// Index an entity's properties for unified search.
    pub fn index_entity(
        &mut self,
        entity_id: &memvault_core::EntityId,
        kind: &str,
        props: &std::collections::BTreeMap<String, serde_json::Value>,
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

        self.unified.insert(node_id, IndexedEntry {
            node_type: "entity".to_string(),
            label,
            text: text_parts.join(" "),
            tags: vec![],
        });
    }

    /// Index an attachment for unified search.
    pub fn index_attachment(
        &mut self,
        manifest_cid: &[u8],
        filename: Option<&str>,
        mime_type: &str,
    ) {
        let node_id = format!("attachment:{}", hex::encode(manifest_cid));
        let label = filename.unwrap_or("unnamed file").to_string();

        let mut text_parts = vec![label.clone(), mime_type.to_string()];
        if let Some(f) = filename {
            // Also index filename parts (split on dots, dashes, underscores)
            for part in f.split(|c: char| c == '.' || c == '-' || c == '_' || c == ' ') {
                if !part.is_empty() {
                    text_parts.push(part.to_string());
                }
            }
        }

        self.unified.insert(node_id, IndexedEntry {
            node_type: "attachment".to_string(),
            label,
            text: text_parts.join(" "),
            tags: vec![],
        });
    }

    /// Remove a document from the index.
    pub fn remove_doc(&mut self, doc_id: &DocId) {
        self.docs.remove(doc_id);
        let node_id = format!("doc:{}", hex::encode(doc_id.0));
        self.unified.remove(&node_id);
    }

    /// Unified search across all indexed nodes (docs, entities, attachments).
    pub fn search_unified(&self, query: &str, limit: usize) -> Vec<UnifiedHit> {
        let query_lower = query.to_lowercase();
        let terms: Vec<&str> = query_lower.split_whitespace().collect();
        if terms.is_empty() {
            return Vec::new();
        }

        let mut hits: Vec<UnifiedHit> = Vec::new();

        for (node_id, entry) in &self.unified {
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
                let snippet = extract_snippet(&entry.text, &terms);
                hits.push(UnifiedHit {
                    node_id: node_id.clone(),
                    node_type: entry.node_type.clone(),
                    label: entry.label.clone(),
                    score,
                    snippet,
                });
            }
        }

        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(limit);
        hits
    }

    /// Resolve a node_id (tag_label) to a human-readable label.
    /// Returns None if the node is not indexed.
    pub fn resolve_label(&self, node_id: &str) -> Option<String> {
        self.unified.get(node_id).map(|e| e.label.clone())
    }

    /// Search the index for documents matching the query text (legacy doc-only search).
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchHit> {
        self.search_filtered(query, None, limit)
    }

    /// Search with a structured query (supports tag filtering).
    pub fn search_query(&self, query: &SearchQuery) -> Vec<SearchHit> {
        let limit = if query.limit == 0 { 10 } else { query.limit };
        self.search_filtered(&query.text, query.tag_filter.as_ref(), limit)
    }

    fn search_filtered(
        &self,
        query: &str,
        tag_filter: Option<&(String, String)>,
        limit: usize,
    ) -> Vec<SearchHit> {
        let query_lower = query.to_lowercase();
        let terms: Vec<&str> = query_lower.split_whitespace().collect();
        if terms.is_empty() {
            return Vec::new();
        }

        let mut hits: Vec<SearchHit> = Vec::new();

        for (doc_id, indexed) in &self.docs {
            if let Some((scope, label)) = tag_filter {
                if !indexed.tags.iter().any(|(s, l)| s == scope && l == label) {
                    continue;
                }
            }

            let body_lower = indexed.body.to_lowercase();
            let title_lower = indexed.title.as_deref().unwrap_or("").to_lowercase();

            let mut score: f32 = 0.0;
            let mut matched = false;

            for term in &terms {
                let body_count = body_lower.matches(term).count();
                let title_count = title_lower.matches(term).count();
                if body_count > 0 || title_count > 0 {
                    matched = true;
                    score += body_count as f32 + title_count as f32 * 3.0;
                }
            }

            if matched {
                let snippet = extract_snippet(&indexed.body, &terms);
                hits.push(SearchHit {
                    doc_id: doc_id.clone(),
                    score,
                    snippet,
                });
            }
        }

        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(limit);
        hits
    }
}

impl Default for TextIndex {
    fn default() -> Self {
        Self::new()
    }
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
