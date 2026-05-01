//! Tantivy-backed full-text search index.

use std::path::Path;

use tantivy::{
    collector::TopDocs,
    query::QueryParser,
    schema::{Field, NumericOptions, Schema, STORED, STRING, TEXT},
    Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument,
};

use crate::error::QueryError;

/// Tantivy full-text index for memvault documents.
pub struct TantivyIndex {
    index: Index,
    reader: IndexReader,
    writer: IndexWriter,
    schema: Schema,
    // Field handles
    f_cid: Field,
    f_doc_id: Field,
    f_body: Field,
    f_title: Field,
    f_tags: Field,
    f_wall_ns: Field,
}

/// Search hit from Tantivy.
#[derive(Debug, Clone)]
pub struct TantivyHit {
    pub cid: String,
    pub doc_id: String,
    pub score: f32,
    pub snippet: String,
    pub title: Option<String>,
}

impl TantivyIndex {
    /// Create or open an index at the given path.
    pub fn open(path: &Path) -> Result<Self, QueryError> {
        let mut schema_builder = Schema::builder();
        let f_cid = schema_builder.add_text_field("cid", STRING | STORED);
        let f_doc_id = schema_builder.add_text_field("doc_id", STRING | STORED);
        let f_body = schema_builder.add_text_field("body", TEXT | STORED);
        let f_title = schema_builder.add_text_field("title", TEXT | STORED);
        let f_tags = schema_builder.add_text_field("tags", STRING | STORED);
        let f_wall_ns = schema_builder.add_u64_field(
            "wall_ns",
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
            schema: schema,
            f_cid,
            f_doc_id,
            f_body,
            f_title,
            f_tags,
            f_wall_ns,
        })
    }

    /// Add a document to the index.
    ///
    /// `cid` and `doc_id` are hex-encoded identifiers.
    pub fn add_document(
        &mut self,
        cid: &str,
        doc_id: &str,
        body: &str,
        title: Option<&str>,
        tags: &[(String, String)],
        wall_ns: u64,
    ) -> Result<(), QueryError> {
        let mut doc = TantivyDocument::default();
        doc.add_text(self.f_cid, cid);
        doc.add_text(self.f_doc_id, doc_id);
        doc.add_text(self.f_body, body);
        if let Some(t) = title {
            doc.add_text(self.f_title, t);
        }
        for (scope, label) in tags {
            doc.add_text(self.f_tags, &format!("{scope}:{label}"));
        }
        doc.add_u64(self.f_wall_ns, wall_ns);

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

    /// Search the index.
    pub fn search(&self, query_text: &str, limit: usize) -> Result<Vec<TantivyHit>, QueryError> {
        let searcher = self.reader.searcher();
        let query_parser =
            QueryParser::for_index(&self.index, vec![self.f_body, self.f_title]);
        let query = query_parser
            .parse_query(query_text)
            .map_err(|e| QueryError::Other(format!("query parse: {e}")))?;

        let top_docs = searcher
            .search(&query, &TopDocs::with_limit(limit))
            .map_err(|e| QueryError::Other(format!("search: {e}")))?;

        let mut hits = Vec::new();
        for (score, doc_addr) in top_docs {
            if let Ok(retrieved) = searcher.doc::<TantivyDocument>(doc_addr) {
                let cid = self.get_text_field(&retrieved, self.f_cid);
                let doc_id = self.get_text_field(&retrieved, self.f_doc_id);
                let snippet: String = self
                    .get_text_field(&retrieved, self.f_body)
                    .chars()
                    .take(200)
                    .collect();
                let title = {
                    let t = self.get_text_field(&retrieved, self.f_title);
                    if t.is_empty() { None } else { Some(t) }
                };

                hits.push(TantivyHit {
                    cid,
                    doc_id,
                    score,
                    snippet,
                    title,
                });
            }
        }
        Ok(hits)
    }

    /// Remove all documents matching the given CID (hex string).
    pub fn remove(&mut self, cid: &str) -> Result<(), QueryError> {
        let term = tantivy::Term::from_field_text(self.f_cid, cid);
        self.writer.delete_term(term);
        Ok(())
    }

    /// Get the number of documents in the index.
    pub fn num_docs(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    /// Schema accessor (useful for JSON serialization of results).
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
    fn test_add_and_search() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "cid001",
            "doc001",
            "The quick brown fox jumps over the lazy dog",
            Some("Fox Story"),
            &[("category".into(), "animals".into())],
            1000,
        )
        .unwrap();
        idx.commit().unwrap();

        let hits = idx.search("fox", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].cid, "cid001");
        assert_eq!(hits[0].doc_id, "doc001");
        assert_eq!(hits[0].title, Some("Fox Story".to_string()));
        assert!(hits[0].score > 0.0);
    }

    #[test]
    fn test_score_ordering() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "cid_a",
            "doc_a",
            "rust programming language systems",
            Some("Rust Intro"),
            &[],
            100,
        )
        .unwrap();
        idx.add_document(
            "cid_b",
            "doc_b",
            "rust rust rust is amazing for rust developers who love rust",
            Some("All About Rust"),
            &[],
            200,
        )
        .unwrap();
        idx.commit().unwrap();

        let hits = idx.search("rust", 10).unwrap();
        assert_eq!(hits.len(), 2);
        // Higher TF for "rust" in doc_b should score higher
        assert_eq!(hits[0].cid, "cid_b");
        assert_eq!(hits[1].cid, "cid_a");
    }

    #[test]
    fn test_empty_query_returns_nothing() {
        let (_dir, mut idx) = make_index();
        idx.add_document("cid_x", "doc_x", "hello world", None, &[], 0)
            .unwrap();
        idx.commit().unwrap();

        // A query with no matching terms
        let hits = idx.search("zzzznonexistent", 10).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn test_multiple_documents() {
        let (_dir, mut idx) = make_index();
        for i in 0..5 {
            idx.add_document(
                &format!("cid_{i}"),
                &format!("doc_{i}"),
                &format!("document number {i} with some common text about searching"),
                None,
                &[("idx".into(), format!("{i}"))],
                i as u64 * 1000,
            )
            .unwrap();
        }
        idx.commit().unwrap();

        assert_eq!(idx.num_docs(), 5);

        let hits = idx.search("searching", 10).unwrap();
        assert_eq!(hits.len(), 5);
    }

    #[test]
    fn test_title_search() {
        let (_dir, mut idx) = make_index();
        idx.add_document(
            "cid_t1",
            "doc_t1",
            "some body text that does not match",
            Some("Kubernetes cluster management"),
            &[],
            0,
        )
        .unwrap();
        idx.commit().unwrap();

        let hits = idx.search("kubernetes", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].cid, "cid_t1");
    }

    #[test]
    fn test_remove_document() {
        let (_dir, mut idx) = make_index();
        idx.add_document("cid_rm", "doc_rm", "removable content", None, &[], 0)
            .unwrap();
        idx.commit().unwrap();
        assert_eq!(idx.num_docs(), 1);

        idx.remove("cid_rm").unwrap();
        idx.commit().unwrap();
        assert_eq!(idx.num_docs(), 0);

        let hits = idx.search("removable", 10).unwrap();
        assert!(hits.is_empty());
    }
}
