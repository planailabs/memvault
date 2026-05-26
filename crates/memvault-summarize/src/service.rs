use std::sync::Arc;

use crate::cache::SummaryCache;
use crate::error::SummarizeError;
use crate::llm::LlmClient;
use crate::output::Summary;
use crate::prompts::{build_prompt, truncate_context};
use crate::scope::SummarizationRequest;

/// The summarization service.
pub struct SummarizationService {
    llm: Arc<dyn LlmClient>,
    cache: SummaryCache,
}

impl SummarizationService {
    /// Create a new summarization service with the given LLM client.
    /// Uses a default cache size of 256 entries.
    pub fn new(llm: Arc<dyn LlmClient>) -> Self {
        Self {
            llm,
            cache: SummaryCache::new(256),
        }
    }

    /// Generate a summary for the given request.
    /// `sources` provides (cid, text_content) pairs for the documents to summarize.
    pub async fn summarize(
        &self,
        request: &SummarizationRequest,
        sources: &[(Vec<u8>, String)],
        model_id: &str,
    ) -> Result<Summary, SummarizeError> {
        if sources.is_empty() {
            return Err(SummarizeError::NoSources);
        }

        // Extract texts and truncate to token budget
        let texts: Vec<String> = sources.iter().map(|(_, text)| text.clone()).collect();
        let truncated = truncate_context(&texts, request.max_input_tokens, self.llm.as_ref());

        // Build the prompt
        let prompt = build_prompt(&request.kind, &truncated);

        // Estimate input tokens
        let input_token_count = self.llm.estimate_tokens(&prompt);

        // Call the LLM
        let output = self.llm.summarize(&prompt, &truncated).await?;

        // Estimate output tokens
        let output_token_count = self.llm.estimate_tokens(&output);

        // Collect source CIDs
        let source_cids: Vec<Vec<u8>> = sources.iter().map(|(cid, _)| cid.clone()).collect();

        let now_ns = memvault_core::time::wall_ns();

        Ok(Summary {
            request: request.clone(),
            sources: source_cids,
            output,
            model_id: model_id.to_string(),
            generated_at_ns: now_ns,
            input_token_count,
            output_token_count,
        })
    }

    /// Check if a cached summary exists for this request+sources combination.
    pub fn get_cached(
        &self,
        request: &SummarizationRequest,
        source_cids: &[Vec<u8>],
    ) -> Option<&Summary> {
        let key = SummaryCache::cache_key(request, source_cids);
        self.cache.get(&key)
    }

    /// Cache a summary for later retrieval.
    pub fn cache_summary(&mut self, request: &SummarizationRequest, summary: Summary) {
        let source_cids = summary.sources.clone();
        let key = SummaryCache::cache_key(request, &source_cids);
        let now_ns = summary.generated_at_ns;
        self.cache.put(key, summary, source_cids, now_ns);
    }

    /// Invalidate cached summaries that reference a given source CID.
    /// Returns the number of entries invalidated.
    pub fn invalidate_source(&mut self, source_cid: &[u8]) -> usize {
        self.cache.invalidate_by_source(source_cid)
    }
}
