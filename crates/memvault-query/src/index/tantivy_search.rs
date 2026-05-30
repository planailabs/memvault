//! Tantivy-backed full-text search index.
//!
//! Promoted to primary search engine in B4. Indexes docs, entities, and files
//! with BM25 scoring and native bucket filtering.

use std::collections::BTreeMap;
use std::path::Path;

use memvault_core::{DocId, EntityId, RetractionMode};
use tantivy::{
    Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument,
    collector::TopDocs,
    query::QueryParser,
    schema::{Field, NumericOptions, STORED, STRING, Schema, TEXT, Value},
};

use crate::error::QueryError;

/// Tantivy full-text index for memvault documents, entities, and files.
pub struct TantivyIndex {
    index: Index,
    reader: IndexReader,
    writer: IndexWriter,
    schema: Schema,
    // Field handles
    f_cid: Field,
    f_node_id: Field,
    f_node_type: Field,
    f_body: Field,
    f_label: Field,
    f_tags: Field,
    f_wall_ns: Field,
    f_bucket_id: Field,
    /// 0 = active, 1 = retracted. Retraction flips this flag (re-add) instead
    /// of deleting the doc, so admins/auditors can still surface retracted
    /// content via `RetractionMode`.
    f_retracted: Field,
}

/// All stored fields of an indexed node — used to read/rewrite a doc by
/// node_id (Tantivy has no in-place update, so tag/retraction changes are
/// delete + re-add of the full stored field set).
struct StoredFields {
    cid: String,
    node_id: String,
    node_type: String,
    body: String,
    label: String,
    /// Tags as "scope:label" strings (the on-disk form).
    tags: Vec<String>,
    wall_ns: u64,
    bucket_id: String,
    retracted: u64,
}

/// Split a stored "scope:label" tag into a `(scope, label)` pair on the first
/// colon. Returns `None` if there's no colon.
fn split_tag(t: &str) -> Option<(String, String)> {
    t.split_once(':').map(|(s, l)| (s.to_string(), l.to_string()))
}

/// Unified search hit across all node types.
#[derive(Debug, Clone)]
pub struct TantivyHit {
    pub cid: String,
    pub node_id: String,
    pub node_type: String,
    pub label: String,
    pub score: f32,
    pub snippet: String,
}

impl TantivyIndex {
    /// Create or open an index at the given path.
    pub fn open(path: &Path) -> Result<Self, QueryError> {
        let mut schema_builder = Schema::builder();
        let f_cid = schema_builder.add_text_field("cid", STRING | STORED);
        let f_node_id = schema_builder.add_text_field("node_id", STRING | STORED);
        let f_node_type = schema_builder.add_text_field("node_type", STRING | STORED);
        let f_body = schema_builder.add_text_field("body", TEXT | STORED);
        let f_label = schema_builder.add_text_field("label", TEXT | STORED);
        let f_tags = schema_builder.add_text_field("tags", STRING | STORED);
        let f_wall_ns = schema_builder.add_u64_field(
            "wall_ns",
            NumericOptions::default().set_stored().set_indexed(),
        );
        let f_bucket_id = schema_builder.add_text_field("bucket_id", STRING | STORED);
        let f_retracted = schema_builder.add_u64_field(
            "retracted",
            NumericOptions::default().set_stored().set_indexed(),
        );
        let schema = schema_builder.build();

        std::fs::create_dir_all(path).map_err(|e| QueryError::Other(e.to_string()))?;

        let index = Index::create_in_dir(path, schema.clone())
            .or_else(|_| Index::open_in_dir(path))
            .map_err(|e| QueryError::Other(format!("tantivy index: {e}")))?;

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .map_err(|e| QueryError::Other(format!("tantivy reader: {e}")))?;

        let writer = index
            .writer(50_000_000) // 50 MB heap
            .map_err(|e| QueryError::Other(format!("tantivy writer: {e}")))?;

        Ok(Self {
            index,
            reader,
            writer,
            schema,
            f_cid,
            f_node_id,
            f_node_type,
            f_body,
            f_label,
            f_tags,
            f_wall_ns,
            f_bucket_id,
            f_retracted,
        })
    }

    /// Add a document to the index.
    pub fn add_document(
        &mut self,
        cid: &str,
        node_id: &str,
        body: &str,
        label: &str,
        tags: &[(String, String)],
        bucket_id: Option<&str>,
        wall_ns: u64,
    ) -> Result<(), QueryError> {
        let mut doc = TantivyDocument::default();
        doc.add_text(self.f_cid, cid);
        doc.add_text(self.f_node_id, node_id);
        doc.add_text(self.f_node_type, "doc");
        doc.add_text(self.f_body, body);
        doc.add_text(self.f_label, label);
        for (scope, lbl) in tags {
            doc.add_text(self.f_tags, &format!("{scope}:{lbl}"));
        }
        doc.add_u64(self.f_wall_ns, wall_ns);
        doc.add_text(self.f_bucket_id, bucket_id.unwrap_or(""));
        doc.add_u64(self.f_retracted, 0);

        self.writer
            .add_document(doc)
            .map_err(|e| QueryError::Other(e.to_string()))?;
        Ok(())
    }

    /// Add an entity to the index.
    pub fn add_entity(
        &mut self,
        cid: &str,
        node_id: &str,
        kind: &str,
        label: &str,
        properties_text: &str,
        tags: &[(String, String)],
        bucket_id: Option<&str>,
        wall_ns: u64,
    ) -> Result<(), QueryError> {
        let mut doc = TantivyDocument::default();
        doc.add_text(self.f_cid, cid);
        doc.add_text(self.f_node_id, node_id);
        doc.add_text(self.f_node_type, "entity");
        doc.add_text(self.f_body, &format!("{kind} {properties_text}"));
        doc.add_text(self.f_label, label);
        for (scope, lbl) in tags {
            doc.add_text(self.f_tags, &format!("{scope}:{lbl}"));
        }
        doc.add_u64(self.f_wall_ns, wall_ns);
        doc.add_text(self.f_bucket_id, bucket_id.unwrap_or(""));
        doc.add_u64(self.f_retracted, 0);

        self.writer
            .add_document(doc)
            .map_err(|e| QueryError::Other(e.to_string()))?;
        Ok(())
    }

    /// Add a file/attachment to the index.
    pub fn add_attachment(
        &mut self,
        cid: &str,
        node_id: &str,
        filename: &str,
        mime_type: &str,
        extracted_text: Option<&str>,
        tags: &[(String, String)],
        bucket_id: Option<&str>,
        wall_ns: u64,
    ) -> Result<(), QueryError> {
        let mut body_parts = vec![mime_type.to_string()];
        // Split filename for indexing
        for part in filename.split(|c: char| c == '.' || c == '-' || c == '_' || c == ' ') {
            if !part.is_empty() {
                body_parts.push(part.to_string());
            }
        }
        if let Some(text) = extracted_text {
            body_parts.push(text.to_string());
        }

        let mut doc = TantivyDocument::default();
        doc.add_text(self.f_cid, cid);
        doc.add_text(self.f_node_id, node_id);
        doc.add_text(self.f_node_type, "file");
        doc.add_text(self.f_body, &body_parts.join(" "));
        doc.add_text(self.f_label, filename);
        for (scope, lbl) in tags {
            doc.add_text(self.f_tags, &format!("{scope}:{lbl}"));
        }
        doc.add_u64(self.f_wall_ns, wall_ns);
        doc.add_text(self.f_bucket_id, bucket_id.unwrap_or(""));
        doc.add_u64(self.f_retracted, 0);

        self.writer
            .add_document(doc)
            .map_err(|e| QueryError::Other(e.to_string()))?;
        Ok(())
    }

    /// Commit pending writes.
    pub fn commit(&mut self) -> Result<(), QueryError> {
        self.writer
            .commit()
            .map_err(|e| QueryError::Other(e.to_string()))?;
        self.reader
            .reload()
            .map_err(|e| QueryError::Other(e.to_string()))?;
        Ok(())
    }

    // ── Node-typed convenience indexers (TextIndex-shaped + bucket/wall) ──
    //
    // These mirror the old `TextIndex::index_*` signatures (deriving node_id /
    // label / body the same way) but additionally thread the bucket id and
    // wall-clock time into the native fields, so callers only add two args.

    /// Index a document. node_id = "doc:<hex>"; cid surrogate = the hex id.
    pub fn index_doc(
        &mut self,
        doc_id: &DocId,
        body: &str,
        title: Option<&str>,
        tags: &[(String, String)],
        bucket_id: Option<&str>,
        wall_ns: u64,
    ) -> Result<(), QueryError> {
        let id_hex = hex::encode(doc_id.0);
        let node_id = format!("doc:{id_hex}");
        let label = title.unwrap_or("Untitled");
        self.add_document(&id_hex, &node_id, body, label, tags, bucket_id, wall_ns)
    }

    /// Index a graph entity. node_id = "entity:<hex>"; label from name/title.
    pub fn index_entity(
        &mut self,
        entity_id: &EntityId,
        kind: &str,
        props: &BTreeMap<String, serde_json::Value>,
        tags: &[(String, String)],
        bucket_id: Option<&str>,
        wall_ns: u64,
    ) -> Result<(), QueryError> {
        let id_hex = hex::encode(entity_id.0);
        let node_id = format!("entity:{id_hex}");
        let label = props
            .get("name")
            .or_else(|| props.get("title"))
            .and_then(|v| v.as_str())
            .unwrap_or(kind)
            .to_string();
        let mut parts: Vec<String> = Vec::new();
        for (k, v) in props {
            parts.push(k.clone());
            match v {
                serde_json::Value::String(s) => parts.push(s.clone()),
                other => parts.push(other.to_string()),
            }
        }
        self.add_entity(
            &id_hex,
            &node_id,
            kind,
            &label,
            &parts.join(" "),
            tags,
            bucket_id,
            wall_ns,
        )
    }

    /// Index a file/attachment. node_id = "file:<manifest_hex>".
    pub fn index_attachment(
        &mut self,
        manifest_cid: &[u8],
        filename: Option<&str>,
        mime_type: &str,
        extracted_text: Option<&str>,
        tags: &[(String, String)],
        bucket_id: Option<&str>,
        wall_ns: u64,
    ) -> Result<(), QueryError> {
        let cid_hex = hex::encode(manifest_cid);
        let node_id = format!("file:{cid_hex}");
        self.add_attachment(
            &cid_hex,
            &node_id,
            filename.unwrap_or("unnamed file"),
            mime_type,
            extracted_text,
            tags,
            bucket_id,
            wall_ns,
        )
    }

    /// Search the index with an optional single-bucket filter (active only).
    /// Thin back-compat wrapper over [`search_scoped`].
    pub fn search_filtered(
        &self,
        query_text: &str,
        bucket_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<TantivyHit>, QueryError> {
        let buckets: Vec<&str> = bucket_id.into_iter().collect();
        self.search_scoped(
            query_text,
            &buckets,
            &[],
            RetractionMode::ActiveOnly,
            limit,
        )
    }

    /// Scoped full-text search: the `(buckets, view_tags, retraction)` triplet
    /// is pushed natively into the Tantivy query.
    ///
    /// - `bucket_ids`: hex bucket ids; empty = no bucket clause (all buckets).
    ///   Multiple ids are OR-ed — this is how a single query spans the set of
    ///   buckets an agent has access to.
    /// - `view_tags`: `(scope, label)` pairs AND-ed in (a view is a tag
    ///   conjunction); empty = no view filter.
    /// - `retraction`: `ActiveOnly` adds `retracted:0`, `RetractedOnly` adds
    ///   `retracted:1`, `IncludeRetracted` adds no clause.
    pub fn search_scoped(
        &self,
        query_text: &str,
        bucket_ids: &[&str],
        view_tags: &[(String, String)],
        retraction: RetractionMode,
        limit: usize,
    ) -> Result<Vec<TantivyHit>, QueryError> {
        let searcher = self.reader.searcher();

        let mut clauses: Vec<String> = Vec::new();
        if !bucket_ids.is_empty() {
            let ors = bucket_ids
                .iter()
                .map(|b| format!("bucket_id:\"{b}\""))
                .collect::<Vec<_>>()
                .join(" OR ");
            clauses.push(format!("({ors})"));
        }
        for (scope, label) in view_tags {
            clauses.push(format!("tags:\"{scope}:{label}\""));
        }
        match retraction {
            RetractionMode::ActiveOnly => clauses.push("retracted:0".to_string()),
            RetractionMode::RetractedOnly => clauses.push("retracted:1".to_string()),
            RetractionMode::IncludeRetracted => {}
        }

        let query_text = query_text.trim();
        let effective_query = if clauses.is_empty() {
            query_text.to_string()
        } else if query_text.is_empty() {
            clauses.join(" AND ")
        } else {
            format!("{} AND ({})", clauses.join(" AND "), query_text)
        };
        if effective_query.is_empty() {
            return Ok(Vec::new());
        }

        let query_parser = QueryParser::for_index(&self.index, vec![self.f_body, self.f_label]);
        let query = query_parser
            .parse_query(&effective_query)
            .map_err(|e| QueryError::Other(format!("query parse: {e}")))?;

        let top_docs = searcher
            .search(&query, &TopDocs::with_limit(limit))
            .map_err(|e| QueryError::Other(format!("search: {e}")))?;

        let mut hits = Vec::new();
        for (score, doc_addr) in top_docs {
            if let Ok(retrieved) = searcher.doc::<TantivyDocument>(doc_addr) {
                let cid = self.get_text_field(&retrieved, self.f_cid);
                let node_id = self.get_text_field(&retrieved, self.f_node_id);
                let node_type = self.get_text_field(&retrieved, self.f_node_type);
                let label = self.get_text_field(&retrieved, self.f_label);
                let snippet: String = self
                    .get_text_field(&retrieved, self.f_body)
                    .chars()
                    .take(200)
                    .collect();

                hits.push(TantivyHit {
                    cid,
                    node_id,
                    node_type,
                    label,
                    score,
                    snippet,
                });
            }
        }
        Ok(hits)
    }

    /// Search across all node types (unified search), active only.
    pub fn search_unified(
        &self,
        query_text: &str,
        bucket_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<TantivyHit>, QueryError> {
        self.search_filtered(query_text, bucket_id, limit)
    }

    /// Remove all documents matching the given CID (hex string).
    pub fn remove(&mut self, cid: &str) -> Result<(), QueryError> {
        let term = tantivy::Term::from_field_text(self.f_cid, cid);
        self.writer.delete_term(term);
        Ok(())
    }

    /// Mark a node retracted by node_id (e.g. "doc:abcd"). Flips the
    /// `retracted` flag (delete + re-add) rather than deleting, so the node
    /// stays searchable under `RetractionMode::{IncludeRetracted,RetractedOnly}`.
    /// Returns true if a matching doc was found. Caller must `commit()`.
    pub fn retract(&mut self, node_id: &str) -> Result<bool, QueryError> {
        self.set_retracted(node_id, true)
    }

    /// Clear the retracted flag for a node_id. Caller must `commit()`.
    pub fn unretract(&mut self, node_id: &str) -> Result<bool, QueryError> {
        self.set_retracted(node_id, false)
    }

    /// Flip a node's `retracted` flag by re-indexing its stored fields.
    fn set_retracted(&mut self, node_id: &str, retracted: bool) -> Result<bool, QueryError> {
        // Collect the existing doc(s) for this node_id from committed state.
        let docs: Vec<TantivyDocument> = {
            let searcher = self.reader.searcher();
            let qp = QueryParser::for_index(&self.index, vec![self.f_node_id]);
            let q = qp
                .parse_query(&format!("node_id:\"{node_id}\""))
                .map_err(|e| QueryError::Other(format!("query parse: {e}")))?;
            let top = searcher
                .search(&q, &TopDocs::with_limit(16))
                .map_err(|e| QueryError::Other(format!("search: {e}")))?;
            let mut out = Vec::new();
            for (_, addr) in top {
                if let Ok(d) = searcher.doc::<TantivyDocument>(addr) {
                    out.push(d);
                }
            }
            out
        };
        if docs.is_empty() {
            return Ok(false);
        }
        let flag = u64::from(retracted);
        // Delete the old copies, then re-add with the flipped flag. Adds that
        // follow the delete in the same commit survive it.
        let term = tantivy::Term::from_field_text(self.f_node_id, node_id);
        self.writer.delete_term(term);
        for d in docs {
            let mut nd = TantivyDocument::default();
            nd.add_text(self.f_cid, self.get_text_field(&d, self.f_cid));
            nd.add_text(self.f_node_id, self.get_text_field(&d, self.f_node_id));
            nd.add_text(self.f_node_type, self.get_text_field(&d, self.f_node_type));
            nd.add_text(self.f_body, self.get_text_field(&d, self.f_body));
            nd.add_text(self.f_label, self.get_text_field(&d, self.f_label));
            for v in d.get_all(self.f_tags) {
                if let Some(s) = v.as_str() {
                    nd.add_text(self.f_tags, s);
                }
            }
            let wall_ns = d
                .get_first(self.f_wall_ns)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            nd.add_u64(self.f_wall_ns, wall_ns);
            nd.add_text(self.f_bucket_id, self.get_text_field(&d, self.f_bucket_id));
            nd.add_u64(self.f_retracted, flag);
            self.writer
                .add_document(nd)
                .map_err(|e| QueryError::Other(e.to_string()))?;
        }
        Ok(true)
    }

    /// Get the number of documents in the index.
    pub fn num_docs(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    // ── Node-addressed accessors / mutations (TextIndex parity) ────

    /// Fetch a node's full stored field set by node_id (first match).
    fn read_fields(&self, node_id: &str) -> Option<StoredFields> {
        let searcher = self.reader.searcher();
        let qp = QueryParser::for_index(&self.index, vec![self.f_node_id]);
        let q = qp.parse_query(&format!("node_id:\"{node_id}\"")).ok()?;
        let top = searcher.search(&q, &TopDocs::with_limit(1)).ok()?;
        let (_, addr) = top.first()?;
        let d: TantivyDocument = searcher.doc(*addr).ok()?;
        Some(self.fields_of(&d))
    }

    /// Extract a `StoredFields` from a retrieved document.
    fn fields_of(&self, d: &TantivyDocument) -> StoredFields {
        let mut tags = Vec::new();
        for v in d.get_all(self.f_tags) {
            if let Some(s) = v.as_str() {
                tags.push(s.to_string());
            }
        }
        StoredFields {
            cid: self.get_text_field(d, self.f_cid),
            node_id: self.get_text_field(d, self.f_node_id),
            node_type: self.get_text_field(d, self.f_node_type),
            body: self.get_text_field(d, self.f_body),
            label: self.get_text_field(d, self.f_label),
            tags,
            wall_ns: d.get_first(self.f_wall_ns).and_then(|v| v.as_u64()).unwrap_or(0),
            bucket_id: self.get_text_field(d, self.f_bucket_id),
            retracted: d.get_first(self.f_retracted).and_then(|v| v.as_u64()).unwrap_or(0),
        }
    }

    /// (Re)write a node from a `StoredFields`, replacing any existing copies.
    /// Caller must `commit()`.
    fn write_fields(&mut self, f: &StoredFields) -> Result<(), QueryError> {
        let term = tantivy::Term::from_field_text(self.f_node_id, &f.node_id);
        self.writer.delete_term(term);
        let mut nd = TantivyDocument::default();
        nd.add_text(self.f_cid, &f.cid);
        nd.add_text(self.f_node_id, &f.node_id);
        nd.add_text(self.f_node_type, &f.node_type);
        nd.add_text(self.f_body, &f.body);
        nd.add_text(self.f_label, &f.label);
        for t in &f.tags {
            nd.add_text(self.f_tags, t);
        }
        nd.add_u64(self.f_wall_ns, f.wall_ns);
        nd.add_text(self.f_bucket_id, &f.bucket_id);
        nd.add_u64(self.f_retracted, f.retracted);
        self.writer
            .add_document(nd)
            .map_err(|e| QueryError::Other(e.to_string()))?;
        Ok(())
    }

    /// Whether a node is currently flagged retracted.
    pub fn is_retracted(&self, node_id: &str) -> bool {
        self.read_fields(node_id).map(|f| f.retracted != 0).unwrap_or(false)
    }

    /// A node's effective tags as `(scope, label)` pairs.
    pub fn get_tags(&self, node_id: &str) -> Vec<(String, String)> {
        self.read_fields(node_id)
            .map(|f| f.tags.iter().filter_map(|t| split_tag(t)).collect())
            .unwrap_or_default()
    }

    /// Add/remove tags on a node (delete + re-add; Tantivy has no in-place
    /// update). No-op if the node isn't present. Caller must `commit()`.
    pub fn apply_tag_update(
        &mut self,
        node_id: &str,
        add: &[(String, String)],
        remove: &[(String, String)],
    ) -> Result<(), QueryError> {
        let Some(mut f) = self.read_fields(node_id) else {
            return Ok(());
        };
        let remove_set: std::collections::HashSet<String> =
            remove.iter().map(|(s, l)| format!("{s}:{l}")).collect();
        f.tags.retain(|t| !remove_set.contains(t));
        for (s, l) in add {
            let t = format!("{s}:{l}");
            if !f.tags.contains(&t) {
                f.tags.push(t);
            }
        }
        self.write_fields(&f)
    }

    /// Resolve a node's label, honouring the retraction mode.
    pub fn resolve_label_mode(&self, node_id: &str, mode: RetractionMode) -> Option<String> {
        let f = self.read_fields(node_id)?;
        if !mode.admits(f.retracted != 0) {
            return None;
        }
        Some(f.label)
    }

    /// Collect stored fields for all docs matching the given filter clauses
    /// (joined with AND); empty clauses ⇒ all docs.
    fn collect_rows(&self, clauses: &[String], limit: usize) -> Vec<StoredFields> {
        let searcher = self.reader.searcher();
        let want = if limit == 0 { usize::MAX } else { limit };
        let collector = TopDocs::with_limit(want.min(self.num_docs() as usize + 1).max(1));
        let results = if clauses.is_empty() {
            searcher.search(&tantivy::query::AllQuery, &collector)
        } else {
            let qp = QueryParser::for_index(&self.index, vec![self.f_body, self.f_label]);
            match qp.parse_query(&clauses.join(" AND ")) {
                Ok(q) => searcher.search(&q, &collector),
                Err(_) => return Vec::new(),
            }
        };
        let Ok(top) = results else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (_, addr) in top {
            if let Ok(d) = searcher.doc::<TantivyDocument>(addr) {
                out.push(self.fields_of(&d));
            }
        }
        out
    }

    /// Build the filter clauses for a `(view_tags, retraction)` pair.
    fn mode_clauses(view_tags: &[(String, String)], mode: RetractionMode) -> Vec<String> {
        let mut clauses: Vec<String> = view_tags
            .iter()
            .map(|(s, l)| format!("tags:\"{s}:{l}\""))
            .collect();
        match mode {
            RetractionMode::ActiveOnly => clauses.push("retracted:0".to_string()),
            RetractionMode::RetractedOnly => clauses.push("retracted:1".to_string()),
            RetractionMode::IncludeRetracted => {}
        }
        clauses
    }

    /// Node ids of all members of a view (tag conjunction) under a mode.
    pub fn members_of_view_mode(
        &self,
        view_tags: &[(String, String)],
        mode: RetractionMode,
    ) -> Vec<String> {
        let clauses = Self::mode_clauses(view_tags, mode);
        self.collect_rows(&clauses, 0)
            .into_iter()
            .map(|f| f.node_id)
            .collect()
    }

    /// List all nodes (optionally view-filtered) under a mode, with the
    /// retracted flag. Returns `(node_id, node_type, label, tags, retracted)`.
    #[allow(clippy::type_complexity)]
    pub fn list_all_mode(
        &self,
        view_tags: Option<&[(String, String)]>,
        mode: RetractionMode,
        limit: usize,
    ) -> Vec<(String, String, String, Vec<(String, String)>, bool)> {
        let clauses = Self::mode_clauses(view_tags.unwrap_or(&[]), mode);
        self.collect_rows(&clauses, limit)
            .into_iter()
            .map(|f| {
                let tags = f.tags.iter().filter_map(|t| split_tag(t)).collect();
                (f.node_id, f.node_type, f.label, tags, f.retracted != 0)
            })
            .collect()
    }

    /// Unified search honouring the retraction mode; returns `UnifiedHit`s.
    pub fn search_unified_mode(
        &self,
        query: &str,
        mode: RetractionMode,
        limit: usize,
    ) -> Vec<crate::index::search::UnifiedHit> {
        let hits = self
            .search_scoped(query, &[], &[], mode, limit)
            .unwrap_or_default();
        hits.into_iter()
            .map(|h| crate::index::search::UnifiedHit {
                node_id: h.node_id,
                node_type: h.node_type,
                label: h.label,
                score: h.score,
                snippet: h.snippet,
                match_contexts: Vec::new(),
            })
            .collect()
    }

    /// Schema accessor.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    fn get_text_field(&self, doc: &TantivyDocument, field: Field) -> String {
        use tantivy::schema::Value;
        doc.get_first(field)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_index() -> (TempDir, TantivyIndex) {
        let dir = TempDir::new().unwrap();
        let idx = TantivyIndex::open(dir.path()).unwrap();
        (dir, idx)
    }

    #[test]
    fn test_add_and_search_document() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "cid001",
            "doc:001",
            "The quick brown fox jumps over the lazy dog",
            "Fox Story",
            &[("category".into(), "animals".into())],
            None,
            1000,
        )
        .unwrap();
        idx.commit().unwrap();

        let hits = idx.search_filtered("fox", None, 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].cid, "cid001");
        assert_eq!(hits[0].node_id, "doc:001");
        assert_eq!(hits[0].node_type, "doc");
        assert_eq!(hits[0].label, "Fox Story");
    }

    #[test]
    fn test_add_entity() {
        let (_dir, mut idx) = make_index();
        idx.add_entity(
            "cid_e1",
            "entity:e1",
            "person",
            "Alice",
            "name Alice age 30 role engineer",
            &[("kind".into(), "person".into())],
            None,
            2000,
        )
        .unwrap();
        idx.commit().unwrap();

        let hits = idx.search_filtered("engineer", None, 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].node_type, "entity");
        assert_eq!(hits[0].label, "Alice");
    }

    #[test]
    fn test_add_attachment() {
        let (_dir, mut idx) = make_index();
        idx.add_attachment(
            "cid_f1",
            "file:f1",
            "report.pdf",
            "application/pdf",
            Some("quarterly financial report Q3 2025"),
            &[],
            None,
            3000,
        )
        .unwrap();
        idx.commit().unwrap();

        let hits = idx.search_filtered("quarterly", None, 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].node_type, "file");
        assert_eq!(hits[0].label, "report.pdf");
    }

    #[test]
    fn test_bucket_filter() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "cid_b1",
            "doc:b1",
            "shared document in bucket alpha",
            "Alpha Doc",
            &[],
            Some("bucket_alpha"),
            1000,
        )
        .unwrap();
        idx.add_document(
            "cid_b2",
            "doc:b2",
            "shared document in bucket beta",
            "Beta Doc",
            &[],
            Some("bucket_beta"),
            2000,
        )
        .unwrap();
        idx.commit().unwrap();

        // Search all buckets
        let all = idx.search_filtered("shared document", None, 10).unwrap();
        assert_eq!(all.len(), 2);

        // Search specific bucket
        let alpha = idx
            .search_filtered("shared document", Some("bucket_alpha"), 10)
            .unwrap();
        assert_eq!(alpha.len(), 1);
        assert_eq!(alpha[0].node_id, "doc:b1");
    }

    #[test]
    fn test_retract_flips_flag_not_delete() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "cid_r1",
            "doc:r1",
            "content to retract",
            "Retractable",
            &[],
            None,
            1000,
        )
        .unwrap();
        idx.commit().unwrap();
        assert_eq!(idx.num_docs(), 1);

        assert!(idx.retract("doc:r1").unwrap());
        idx.commit().unwrap();
        // Doc still present (flag flipped, not deleted).
        assert_eq!(idx.num_docs(), 1);

        // Active-only search no longer finds it.
        let active = idx
            .search_scoped("content", &[], &[], RetractionMode::ActiveOnly, 10)
            .unwrap();
        assert_eq!(active.len(), 0);
        // Retracted-only finds it.
        let retr = idx
            .search_scoped("content", &[], &[], RetractionMode::RetractedOnly, 10)
            .unwrap();
        assert_eq!(retr.len(), 1);
        // Include-retracted finds it.
        let incl = idx
            .search_scoped("content", &[], &[], RetractionMode::IncludeRetracted, 10)
            .unwrap();
        assert_eq!(incl.len(), 1);

        // Unretract restores active visibility.
        assert!(idx.unretract("doc:r1").unwrap());
        idx.commit().unwrap();
        let active = idx
            .search_scoped("content", &[], &[], RetractionMode::ActiveOnly, 10)
            .unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_search_scoped_multi_bucket_or() {
        let (_dir, mut idx) = make_index();
        idx.add_document("c1", "doc:1", "shared note", "A", &[], Some("baaa"), 1)
            .unwrap();
        idx.add_document("c2", "doc:2", "shared note", "B", &[], Some("bbbb"), 2)
            .unwrap();
        idx.add_document("c3", "doc:3", "shared note", "C", &[], Some("cccc"), 3)
            .unwrap();
        idx.commit().unwrap();

        // Union of two of three buckets.
        let hits = idx
            .search_scoped("shared", &["baaa", "bbbb"], &[], RetractionMode::ActiveOnly, 10)
            .unwrap();
        assert_eq!(hits.len(), 2);
        // All buckets (empty filter).
        let all = idx
            .search_scoped("shared", &[], &[], RetractionMode::ActiveOnly, 10)
            .unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_node_accessors_and_tag_update() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "c1",
            "doc:1",
            "body text",
            "Label",
            &[("a".into(), "x".into()), ("b".into(), "y".into())],
            Some("bkt"),
            10,
        )
        .unwrap();
        idx.commit().unwrap();

        // get_tags
        let mut tags = idx.get_tags("doc:1");
        tags.sort();
        assert_eq!(tags, vec![("a".to_string(), "x".to_string()), ("b".to_string(), "y".to_string())]);
        // is_retracted
        assert!(!idx.is_retracted("doc:1"));
        // resolve_label_mode
        assert_eq!(idx.resolve_label_mode("doc:1", RetractionMode::ActiveOnly).as_deref(), Some("Label"));

        // apply_tag_update: remove b:y, add c:z
        idx.apply_tag_update("doc:1", &[("c".into(), "z".into())], &[("b".into(), "y".into())]).unwrap();
        idx.commit().unwrap();
        let mut tags = idx.get_tags("doc:1");
        tags.sort();
        assert_eq!(tags, vec![("a".to_string(), "x".to_string()), ("c".to_string(), "z".to_string())]);
        // bucket + body preserved across the rewrite
        let hit = idx.search_scoped("body", &["bkt"], &[], RetractionMode::ActiveOnly, 10).unwrap();
        assert_eq!(hit.len(), 1);
    }

    #[test]
    fn test_members_and_list_modes() {
        let (_dir, mut idx) = make_index();
        idx.add_document("c1", "doc:1", "alpha", "A", &[("kind".into(), "note".into())], None, 1).unwrap();
        idx.add_document("c2", "doc:2", "beta", "B", &[("kind".into(), "note".into())], None, 2).unwrap();
        idx.add_document("c3", "doc:3", "gamma", "C", &[("kind".into(), "memo".into())], None, 3).unwrap();
        idx.commit().unwrap();

        // members of view {kind:note}
        let mut m = idx.members_of_view_mode(&[("kind".into(), "note".into())], RetractionMode::ActiveOnly);
        m.sort();
        assert_eq!(m, vec!["doc:1".to_string(), "doc:2".to_string()]);

        // list all (no view) active
        let all = idx.list_all_mode(None, RetractionMode::ActiveOnly, 100);
        assert_eq!(all.len(), 3);

        // retract doc:2, then modes
        idx.retract("doc:2").unwrap();
        idx.commit().unwrap();
        let active = idx.members_of_view_mode(&[("kind".into(), "note".into())], RetractionMode::ActiveOnly);
        assert_eq!(active, vec!["doc:1".to_string()]);
        let only = idx.members_of_view_mode(&[("kind".into(), "note".into())], RetractionMode::RetractedOnly);
        assert_eq!(only, vec!["doc:2".to_string()]);
        let incl = idx.members_of_view_mode(&[("kind".into(), "note".into())], RetractionMode::IncludeRetracted);
        assert_eq!(incl.len(), 2);
        // resolve_label of retracted node: hidden under ActiveOnly, shown under IncludeRetracted
        assert!(idx.resolve_label_mode("doc:2", RetractionMode::ActiveOnly).is_none());
        assert_eq!(idx.resolve_label_mode("doc:2", RetractionMode::IncludeRetracted).as_deref(), Some("B"));

        // search_unified_mode returns UnifiedHit
        let hits = idx.search_unified_mode("alpha", RetractionMode::ActiveOnly, 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].node_id, "doc:1");
    }

    #[test]
    fn test_search_scoped_view_tags_and() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "c1",
            "doc:1",
            "alpha note",
            "A",
            &[("proj".into(), "x".into()), ("kind".into(), "note".into())],
            None,
            1,
        )
        .unwrap();
        idx.add_document(
            "c2",
            "doc:2",
            "alpha note",
            "B",
            &[("proj".into(), "y".into())],
            None,
            2,
        )
        .unwrap();
        idx.commit().unwrap();

        // View = {proj:x} → only doc:1.
        let hits = idx
            .search_scoped(
                "alpha",
                &[],
                &[("proj".into(), "x".into())],
                RetractionMode::ActiveOnly,
                10,
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].node_id, "doc:1");
    }

    #[test]
    fn test_score_ordering() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "cid_a",
            "doc:a",
            "rust programming language",
            "Rust Intro",
            &[],
            None,
            100,
        )
        .unwrap();
        idx.add_document(
            "cid_b",
            "doc:b",
            "rust rust rust is amazing for rust developers",
            "All About Rust",
            &[],
            None,
            200,
        )
        .unwrap();
        idx.commit().unwrap();

        let hits = idx.search_filtered("rust", None, 10).unwrap();
        assert_eq!(hits.len(), 2);
        // Higher TF for "rust" in doc:b should score higher
        assert_eq!(hits[0].node_id, "doc:b");
    }

    #[test]
    fn test_unified_search_across_types() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "c1",
            "doc:1",
            "kubernetes cluster management",
            "K8s Guide",
            &[],
            None,
            100,
        )
        .unwrap();
        idx.add_entity(
            "c2",
            "entity:2",
            "tool",
            "kubectl",
            "kubernetes command line tool",
            &[],
            None,
            200,
        )
        .unwrap();
        idx.add_attachment(
            "c3",
            "file:3",
            "k8s-setup.md",
            "text/markdown",
            Some("kubernetes setup instructions"),
            &[],
            None,
            300,
        )
        .unwrap();
        idx.commit().unwrap();

        let hits = idx.search_unified("kubernetes", None, 10).unwrap();
        assert_eq!(hits.len(), 3);
        // All three types should be present
        let types: Vec<&str> = hits.iter().map(|h| h.node_type.as_str()).collect();
        assert!(types.contains(&"doc"));
        assert!(types.contains(&"entity"));
        assert!(types.contains(&"file"));
    }
}
