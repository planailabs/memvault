use crate::llm::LlmClient;
use crate::scope::SummaryKind;

/// Build a prompt for the given summary kind.
pub fn build_prompt(kind: &SummaryKind, context_texts: &[String]) -> String {
    match kind {
        SummaryKind::Brief => brief_prompt(context_texts),
        SummaryKind::Detailed => detailed_prompt(context_texts),
        SummaryKind::KeyFacts => key_facts_prompt(context_texts),
        SummaryKind::Timeline => timeline_prompt(context_texts),
        SummaryKind::Custom(template) => custom_prompt(template, context_texts),
    }
}

/// Truncate context to fit within token budget.
pub fn truncate_context(
    texts: &[String],
    max_tokens: usize,
    estimator: &dyn LlmClient,
) -> Vec<String> {
    let mut result = Vec::new();
    let mut tokens_used = 0;

    for text in texts {
        let text_tokens = estimator.estimate_tokens(text);
        if tokens_used + text_tokens > max_tokens {
            // Try to include a truncated version of this text
            let remaining_tokens = max_tokens.saturating_sub(tokens_used);
            if remaining_tokens > 0 {
                // Approximate character count for remaining tokens
                let max_chars = remaining_tokens * 4;
                if max_chars > 0 && !text.is_empty() {
                    let truncated: String = text.chars().take(max_chars).collect();
                    result.push(truncated);
                }
            }
            break;
        }
        tokens_used += text_tokens;
        result.push(text.clone());
    }

    result
}

fn brief_prompt(context: &[String]) -> String {
    format!(
        "Summarize the following content in 1-3 concise sentences:\n\n{}\n\nSummary:",
        context.join("\n---\n")
    )
}

fn detailed_prompt(context: &[String]) -> String {
    format!(
        "Provide a detailed summary of the following content, preserving all key points and relationships:\n\n{}\n\nDetailed summary:",
        context.join("\n---\n")
    )
}

fn key_facts_prompt(context: &[String]) -> String {
    format!(
        "Extract the key facts from the following content as a bullet-point list:\n\n{}\n\nKey facts:\n-",
        context.join("\n---\n")
    )
}

fn timeline_prompt(context: &[String]) -> String {
    format!(
        "Create a chronological timeline of events and changes from the following content:\n\n{}\n\nTimeline:",
        context.join("\n---\n")
    )
}

fn custom_prompt(template: &str, context: &[String]) -> String {
    format!("{}\n\n{}\n\nResponse:", template, context.join("\n---\n"))
}
