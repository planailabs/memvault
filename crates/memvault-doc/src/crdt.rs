//! Loro CRDT integration for true multi-writer convergence.

use loro::{ExportMode, LoroDoc, LoroValue};
use std::collections::BTreeMap;

/// A CRDT-backed collaborative document using Loro.
#[derive(Clone)]
pub struct CrdtDocument {
    doc: LoroDoc,
}

impl CrdtDocument {
    /// Create a new empty CRDT document.
    pub fn new() -> Self {
        Self {
            doc: LoroDoc::new(),
        }
    }

    /// Create from an existing Loro snapshot.
    pub fn from_snapshot(snapshot: &[u8]) -> Result<Self, CrdtError> {
        let doc = LoroDoc::new();
        doc.import(snapshot)
            .map_err(|e| CrdtError::Import(e.to_string()))?;
        Ok(Self { doc })
    }

    /// Get the document body text.
    pub fn body(&self) -> String {
        let text = self.doc.get_text("body");
        text.to_string()
    }

    /// Insert text at position.
    pub fn insert(&self, pos: usize, text: &str) -> Result<(), CrdtError> {
        let body = self.doc.get_text("body");
        body.insert(pos, text)
            .map_err(|e| CrdtError::Op(e.to_string()))?;
        Ok(())
    }

    /// Delete text at position.
    pub fn delete(&self, pos: usize, len: usize) -> Result<(), CrdtError> {
        let body = self.doc.get_text("body");
        body.delete(pos, len)
            .map_err(|e| CrdtError::Op(e.to_string()))?;
        Ok(())
    }

    /// Set a frontmatter key.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), CrdtError> {
        let meta = self.doc.get_map("frontmatter");
        meta.insert(key, value)
            .map_err(|e| CrdtError::Op(e.to_string()))?;
        Ok(())
    }

    /// Get a frontmatter key.
    pub fn get_meta(&self, key: &str) -> Option<String> {
        let meta = self.doc.get_map("frontmatter");
        let value = meta.get(key)?;
        match value.into_value() {
            Ok(LoroValue::String(s)) => Some(s.to_string()),
            _ => None,
        }
    }

    /// Get all frontmatter keys and values.
    pub fn frontmatter(&self) -> BTreeMap<String, String> {
        let meta = self.doc.get_map("frontmatter");
        let mut result = BTreeMap::new();
        meta.for_each(|key, value| {
            if let Ok(LoroValue::String(s)) = value.into_value() {
                result.insert(key.to_string(), s.to_string());
            }
        });
        result
    }

    /// Export a binary snapshot of the current state.
    pub fn export_snapshot(&self) -> Vec<u8> {
        self.doc
            .export(ExportMode::Snapshot)
            .unwrap_or_default()
    }

    /// Export all updates (for sync protocol).
    pub fn export_updates(&self) -> Vec<u8> {
        self.doc
            .export(ExportMode::all_updates())
            .unwrap_or_default()
    }

    /// Merge remote updates into this document.
    pub fn merge(&self, updates: &[u8]) -> Result<(), CrdtError> {
        self.doc
            .import(updates)
            .map_err(|e| CrdtError::Import(e.to_string()))?;
        Ok(())
    }

    /// Get the version vector (for sync protocol).
    pub fn version(&self) -> Vec<u8> {
        self.doc.oplog_vv().encode()
    }

    /// Commit pending changes (triggers events).
    pub fn commit(&self) {
        self.doc.commit();
    }
}

impl Default for CrdtDocument {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from CRDT operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CrdtError {
    #[error("import failed: {0}")]
    Import(String),
    #[error("operation failed: {0}")]
    Op(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_read_back() {
        let doc = CrdtDocument::new();
        doc.insert(0, "Hello, world!").unwrap();
        assert_eq!(doc.body(), "Hello, world!");
    }

    #[test]
    fn delete_text() {
        let doc = CrdtDocument::new();
        doc.insert(0, "Hello, world!").unwrap();
        doc.delete(5, 8).unwrap(); // delete ", world!"
        assert_eq!(doc.body(), "Hello");
    }

    #[test]
    fn multi_writer_convergence() {
        let a = CrdtDocument::new();
        let b = CrdtDocument::new();

        // Both start empty, make independent edits
        a.insert(0, "Hello").unwrap();
        a.commit();

        b.insert(0, "World").unwrap();
        b.commit();

        // Export and merge both ways
        let a_updates = a.export_updates();
        let b_updates = b.export_updates();

        a.merge(&b_updates).unwrap();
        b.merge(&a_updates).unwrap();

        // After merging, both documents should have the same content
        assert_eq!(a.body(), b.body());
        // Both texts should be present (order determined by CRDT)
        let merged = a.body();
        assert!(merged.contains("Hello"));
        assert!(merged.contains("World"));
    }

    #[test]
    fn snapshot_roundtrip() {
        let doc = CrdtDocument::new();
        doc.insert(0, "snapshot test").unwrap();
        doc.set_meta("title", "Test Doc").unwrap();
        doc.commit();

        let snapshot = doc.export_snapshot();
        let restored = CrdtDocument::from_snapshot(&snapshot).unwrap();

        assert_eq!(restored.body(), "snapshot test");
        assert_eq!(restored.get_meta("title"), Some("Test Doc".to_string()));
    }

    #[test]
    fn frontmatter_set_get() {
        let doc = CrdtDocument::new();
        doc.set_meta("title", "My Document").unwrap();
        doc.set_meta("author", "Alice").unwrap();

        assert_eq!(doc.get_meta("title"), Some("My Document".to_string()));
        assert_eq!(doc.get_meta("author"), Some("Alice".to_string()));
        assert_eq!(doc.get_meta("missing"), None);

        let fm = doc.frontmatter();
        assert_eq!(fm.len(), 2);
        assert_eq!(fm["title"], "My Document");
        assert_eq!(fm["author"], "Alice");
    }

    #[test]
    fn version_grows_after_edits() {
        let doc = CrdtDocument::new();
        let v0 = doc.version();

        doc.insert(0, "edit").unwrap();
        doc.commit();
        let v1 = doc.version();

        // Version vector should change after edits
        assert_ne!(v0, v1);

        doc.insert(4, " more").unwrap();
        doc.commit();
        let v2 = doc.version();

        assert_ne!(v1, v2);
    }
}
