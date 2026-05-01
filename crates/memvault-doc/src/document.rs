use std::collections::BTreeMap;

use memvault_core::DocId;
use serde::{Deserialize, Serialize};

/// A collaborative markdown document with structured frontmatter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: DocId,
    pub body: String,
    pub frontmatter: BTreeMap<String, serde_json::Value>,
}

impl Document {
    pub fn new(id: DocId, body: String, frontmatter: BTreeMap<String, serde_json::Value>) -> Self {
        Self {
            id,
            body,
            frontmatter,
        }
    }
}
