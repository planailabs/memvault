use memvault_core::EntityId;
use serde::{Deserialize, Serialize};

/// Scope of content to include in summarization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SummarizationScope {
    /// Summarize specific documents by their CIDs.
    Documents(Vec<Vec<u8>>),
    /// Summarize all documents matching a tag pattern.
    ByTag { scope: String, label: String },
    /// Summarize documents in a time range.
    TimeRange { after_ns: u64, before_ns: u64 },
    /// Summarize a knowledge graph subgraph starting from an entity.
    GraphNeighborhood {
        entity_id: EntityId,
        max_depth: usize,
    },
}

/// What kind of summary to produce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SummaryKind {
    /// Brief overview (1-3 sentences).
    Brief,
    /// Detailed summary preserving key points.
    Detailed,
    /// Bullet-point list of key facts.
    KeyFacts,
    /// Timeline of events/changes.
    Timeline,
    /// Custom prompt template.
    Custom(String),
}

/// A summarization request combining scope, kind, and token limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummarizationRequest {
    pub scope: SummarizationScope,
    pub kind: SummaryKind,
    pub max_input_tokens: usize,
    pub max_output_tokens: usize,
}
