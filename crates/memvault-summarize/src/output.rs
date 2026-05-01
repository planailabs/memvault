use serde::{Deserialize, Serialize};

use crate::scope::SummarizationRequest;

/// A generated summary with full provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    /// The original request that produced this summary.
    pub request: SummarizationRequest,
    /// CIDs of source blocks that were summarized.
    pub sources: Vec<Vec<u8>>,
    /// The summary text.
    pub output: String,
    /// Which LLM model produced this summary.
    pub model_id: String,
    /// Timestamp when the summary was generated (nanoseconds).
    pub generated_at_ns: u64,
    /// Estimated input token count.
    pub input_token_count: usize,
    /// Estimated output token count.
    pub output_token_count: usize,
}
