use memvault_core::DocId;
use serde::{Deserialize, Serialize};

use crate::op::Op;

/// An entry in the operation log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpEntry {
    pub cid: Vec<u8>,
    pub op: Op,
    pub timestamp_ns: u64,
}

/// Ordered operation log for a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpLog {
    pub doc_id: DocId,
    pub entries: Vec<OpEntry>,
}

impl OpLog {
    pub fn new(doc_id: DocId) -> Self {
        Self {
            doc_id,
            entries: Vec::new(),
        }
    }

    pub fn append(&mut self, entry: OpEntry) {
        self.entries.push(entry);
    }

    pub fn ops(&self) -> Vec<&Op> {
        self.entries.iter().map(|e| &e.op).collect()
    }

    pub fn cids(&self) -> Vec<Vec<u8>> {
        self.entries.iter().map(|e| e.cid.clone()).collect()
    }
}
