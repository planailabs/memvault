use async_trait::async_trait;

use crate::error::SummarizeError;

/// Abstract LLM interface. Consumers inject their implementation.
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// Send a prompt with context documents and get a summary response.
    async fn summarize(&self, prompt: &str, context: &[String]) -> Result<String, SummarizeError>;

    /// Estimate token count for a string (simple heuristic).
    /// Default: ~4 chars per token.
    fn estimate_tokens(&self, text: &str) -> usize {
        text.len() / 4
    }
}

/// Mock LLM client for testing.
pub struct MockLlmClient {
    /// If set, returns this response for any summarize call.
    pub fixed_response: Option<String>,
}

impl MockLlmClient {
    pub fn new() -> Self {
        Self {
            fixed_response: None,
        }
    }

    pub fn with_response(response: impl Into<String>) -> Self {
        Self {
            fixed_response: Some(response.into()),
        }
    }
}

impl Default for MockLlmClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmClient for MockLlmClient {
    async fn summarize(&self, _prompt: &str, context: &[String]) -> Result<String, SummarizeError> {
        match &self.fixed_response {
            Some(resp) => Ok(resp.clone()),
            None => Ok(format!("Summary of {} documents", context.len())),
        }
    }
}
