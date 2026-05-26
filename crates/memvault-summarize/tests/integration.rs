use std::sync::Arc;

use memvault_summarize::{
    LlmClient, MockLlmClient, SummarizationRequest, SummarizationScope, SummarizationService,
    SummaryCache, SummaryKind, build_prompt, truncate_context,
};

#[tokio::test]
async fn mock_client_default_response() {
    let client = MockLlmClient::new();
    let context = vec!["doc1".to_string(), "doc2".to_string()];
    let result = client.summarize("test prompt", &context).await.unwrap();
    assert_eq!(result, "Summary of 2 documents");
}

#[tokio::test]
async fn mock_client_fixed_response() {
    let client = MockLlmClient::with_response("custom summary");
    let context = vec!["doc1".to_string()];
    let result = client.summarize("test prompt", &context).await.unwrap();
    assert_eq!(result, "custom summary");
}

#[tokio::test]
async fn service_produces_summary_with_provenance() {
    let client = Arc::new(MockLlmClient::with_response("test output"));
    let service = SummarizationService::new(client);

    let request = SummarizationRequest {
        scope: SummarizationScope::Documents(vec![vec![1, 2, 3]]),
        kind: SummaryKind::Brief,
        max_input_tokens: 1000,
        max_output_tokens: 200,
    };

    let sources = vec![
        (vec![1, 2, 3], "First document content".to_string()),
        (vec![4, 5, 6], "Second document content".to_string()),
    ];

    let summary = service
        .summarize(&request, &sources, "mock-v1")
        .await
        .unwrap();

    assert_eq!(summary.output, "test output");
    assert_eq!(summary.model_id, "mock-v1");
    assert_eq!(summary.sources.len(), 2);
    assert_eq!(summary.sources[0], vec![1, 2, 3]);
    assert_eq!(summary.sources[1], vec![4, 5, 6]);
    assert!(summary.generated_at_ns > 0);
    assert!(summary.input_token_count > 0);
    assert!(summary.output_token_count > 0);
}

#[tokio::test]
async fn service_returns_error_on_empty_sources() {
    let client = Arc::new(MockLlmClient::new());
    let service = SummarizationService::new(client);

    let request = SummarizationRequest {
        scope: SummarizationScope::Documents(vec![]),
        kind: SummaryKind::Brief,
        max_input_tokens: 1000,
        max_output_tokens: 200,
    };

    let result = service.summarize(&request, &[], "mock-v1").await;
    assert!(result.is_err());
}

#[test]
fn cache_put_and_get() {
    let mut cache = SummaryCache::new(10);

    let request = SummarizationRequest {
        scope: SummarizationScope::Documents(vec![vec![1]]),
        kind: SummaryKind::Brief,
        max_input_tokens: 100,
        max_output_tokens: 50,
    };

    let source_cids = vec![vec![1u8, 2, 3]];
    let key = SummaryCache::cache_key(&request, &source_cids);

    let summary = memvault_summarize::Summary {
        request: request.clone(),
        sources: source_cids.clone(),
        output: "cached summary".to_string(),
        model_id: "test".to_string(),
        generated_at_ns: 1000,
        input_token_count: 10,
        output_token_count: 5,
    };

    cache.put(key.clone(), summary, source_cids, 1000);

    let cached = cache.get(&key).unwrap();
    assert_eq!(cached.output, "cached summary");
}

#[test]
fn cache_invalidation_by_source() {
    let mut cache = SummaryCache::new(10);

    let request = SummarizationRequest {
        scope: SummarizationScope::Documents(vec![vec![1]]),
        kind: SummaryKind::Brief,
        max_input_tokens: 100,
        max_output_tokens: 50,
    };

    let source_cid = vec![10u8, 20, 30];
    let source_cids = vec![source_cid.clone()];
    let key = SummaryCache::cache_key(&request, &source_cids);

    let summary = memvault_summarize::Summary {
        request,
        sources: source_cids.clone(),
        output: "to be invalidated".to_string(),
        model_id: "test".to_string(),
        generated_at_ns: 1000,
        input_token_count: 10,
        output_token_count: 5,
    };

    cache.put(key.clone(), summary, source_cids, 1000);
    assert!(cache.get(&key).is_some());

    let removed = cache.invalidate_by_source(&source_cid);
    assert_eq!(removed, 1);
    assert!(cache.get(&key).is_none());
}

#[test]
fn cache_lru_eviction() {
    let mut cache = SummaryCache::new(2);

    // Insert 3 entries, oldest should be evicted
    for i in 0u8..3 {
        let request = SummarizationRequest {
            scope: SummarizationScope::Documents(vec![vec![i]]),
            kind: SummaryKind::Brief,
            max_input_tokens: 100,
            max_output_tokens: 50,
        };
        let source_cids = vec![vec![i]];
        let key = SummaryCache::cache_key(&request, &source_cids);

        let summary = memvault_summarize::Summary {
            request,
            sources: source_cids.clone(),
            output: format!("summary {}", i),
            model_id: "test".to_string(),
            generated_at_ns: (i as u64) * 1000,
            input_token_count: 10,
            output_token_count: 5,
        };

        cache.put(key, summary, source_cids, (i as u64) * 1000);
    }

    // Cache should have max 2 entries
    assert_eq!(cache.len(), 2);

    // The oldest entry (i=0) should have been evicted
    let request_0 = SummarizationRequest {
        scope: SummarizationScope::Documents(vec![vec![0]]),
        kind: SummaryKind::Brief,
        max_input_tokens: 100,
        max_output_tokens: 50,
    };
    let key_0 = SummaryCache::cache_key(&request_0, &[vec![0u8]]);
    assert!(cache.get(&key_0).is_none());
}

#[test]
fn prompt_building_brief() {
    let texts = vec!["Hello world".to_string()];
    let prompt = build_prompt(&SummaryKind::Brief, &texts);
    assert!(prompt.contains("Summarize the following content in 1-3 concise sentences"));
    assert!(prompt.contains("Hello world"));
}

#[test]
fn prompt_building_detailed() {
    let texts = vec!["Content here".to_string()];
    let prompt = build_prompt(&SummaryKind::Detailed, &texts);
    assert!(prompt.contains("detailed summary"));
    assert!(prompt.contains("Content here"));
}

#[test]
fn prompt_building_key_facts() {
    let texts = vec!["Facts content".to_string()];
    let prompt = build_prompt(&SummaryKind::KeyFacts, &texts);
    assert!(prompt.contains("key facts"));
    assert!(prompt.contains("Facts content"));
}

#[test]
fn prompt_building_timeline() {
    let texts = vec!["Events content".to_string()];
    let prompt = build_prompt(&SummaryKind::Timeline, &texts);
    assert!(prompt.contains("timeline"));
    assert!(prompt.contains("Events content"));
}

#[test]
fn prompt_building_custom() {
    let texts = vec!["Data".to_string()];
    let prompt = build_prompt(
        &SummaryKind::Custom("Analyze sentiment of:".to_string()),
        &texts,
    );
    assert!(prompt.contains("Analyze sentiment of:"));
    assert!(prompt.contains("Data"));
}

#[test]
fn token_truncation_respects_budget() {
    let client = MockLlmClient::new();
    // Each text is ~25 chars = ~6 tokens with the 4-chars-per-token heuristic
    let texts = vec![
        "aaaaaaaaaaaaaaaaaaaaaaaaa".to_string(), // 25 chars = 6 tokens
        "bbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        "ccccccccccccccccccccccccc".to_string(),
    ];

    // Budget of 10 tokens: should fit first text (6 tokens) and partial second
    let result = truncate_context(&texts, 10, &client);
    assert!(result.len() <= 2);
    assert_eq!(result[0], texts[0]);
}

#[test]
fn token_truncation_empty_budget() {
    let client = MockLlmClient::new();
    let texts = vec!["some text".to_string()];
    let result = truncate_context(&texts, 0, &client);
    assert!(result.is_empty() || result[0].is_empty());
}

#[test]
fn cache_key_stability() {
    let request = SummarizationRequest {
        scope: SummarizationScope::Documents(vec![vec![1, 2, 3]]),
        kind: SummaryKind::Brief,
        max_input_tokens: 100,
        max_output_tokens: 50,
    };
    let source_cids = vec![vec![10u8, 20], vec![30u8, 40]];

    let key1 = SummaryCache::cache_key(&request, &source_cids);
    let key2 = SummaryCache::cache_key(&request, &source_cids);
    assert_eq!(key1, key2);

    // Order of source_cids shouldn't matter (they're sorted internally)
    let source_cids_reversed = vec![vec![30u8, 40], vec![10u8, 20]];
    let key3 = SummaryCache::cache_key(&request, &source_cids_reversed);
    assert_eq!(key1, key3);
}

#[test]
fn cache_key_differs_for_different_requests() {
    let source_cids = vec![vec![1u8]];

    let request1 = SummarizationRequest {
        scope: SummarizationScope::Documents(vec![vec![1]]),
        kind: SummaryKind::Brief,
        max_input_tokens: 100,
        max_output_tokens: 50,
    };

    let request2 = SummarizationRequest {
        scope: SummarizationScope::Documents(vec![vec![1]]),
        kind: SummaryKind::Detailed,
        max_input_tokens: 100,
        max_output_tokens: 50,
    };

    let key1 = SummaryCache::cache_key(&request1, &source_cids);
    let key2 = SummaryCache::cache_key(&request2, &source_cids);
    assert_ne!(key1, key2);
}

#[test]
fn estimate_tokens_heuristic() {
    let client = MockLlmClient::new();
    // 100 chars should be ~25 tokens
    let text = "a".repeat(100);
    assert_eq!(client.estimate_tokens(&text), 25);
}
