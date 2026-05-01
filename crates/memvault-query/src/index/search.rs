//! Full-text search index for memvault documents.

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

/// Parameters for a search query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: String,
    pub limit: usize,
    pub tag_filter: Option<(String, String)>,
}

/// In-memory full-text search index (simple TF-based).
pub struct TextIndex {
    /// doc_id -> (body text, tags)
    docs: HashMap<DocId, IndexedDoc>,
}

struct IndexedDoc {
    body: String,
    title: Option<String>,
    tags: Vec<(String, String)>,
}

impl TextIndex {
    pub fn new() -> Self {
        Self {
            docs: HashMap::new(),
        }
    }

    /// Index a document's body text and metadata.
    pub fn index_doc(
        &mut self,
        doc_id: DocId,
        body: &str,
        title: Option<&str>,
        tags: Vec<(String, String)>,
    ) {
        self.docs.insert(
            doc_id,
            IndexedDoc {
                body: body.to_string(),
                title: title.map(|s| s.to_string()),
                tags,
            },
        );
    }

    /// Remove a document from the index.
    pub fn remove_doc(&mut self, doc_id: &DocId) {
        self.docs.remove(doc_id);
    }

    /// Search the index for documents matching the query text.
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
            // Apply tag filter if present
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
    // Find first occurrence of any term
    let mut earliest_pos = body.len();
    for term in terms {
        if let Some(pos) = body_lower.find(term) {
            earliest_pos = earliest_pos.min(pos);
        }
    }

    if earliest_pos == body.len() {
        // No match found, return start of body
        return body.chars().take(100).collect();
    }

    // Take context around the match
    let start = earliest_pos.saturating_sub(30);
    let snippet: String = body.chars().skip(start).take(120).collect();
    if start > 0 {
        format!("...{snippet}")
    } else {
        snippet
    }
}
