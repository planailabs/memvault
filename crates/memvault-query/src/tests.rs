//! Comprehensive tests for memvault-query.

use memvault_core::{AgentId, DocId, PeerId, Tag};
use memvault_store::{EnvelopeMeta, MemvaultStore};

use crate::audit::retraction::{is_retracted, retract};
use crate::history::checkpoint::Checkpoint;
use crate::history::diff::{DiffEntry, diff_doc};
use crate::history::trace::trace_provenance;
use crate::index::effective_tags::effective_tags;
use crate::index::search::TextIndex;
use crate::quotas::{AgentQuota, QuotaManager};

fn temp_store() -> (tempfile::TempDir, MemvaultStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.redb");
    let store = MemvaultStore::open(&path).unwrap();
    (dir, store)
}

// === TextIndex Tests ===

#[test]
fn text_index_add_and_search() {
    let mut index = TextIndex::new();
    let doc1 = DocId::random();
    let doc2 = DocId::random();

    index.index_doc(
        doc1.clone(),
        "The quick brown fox jumps over the lazy dog",
        Some("Fox Story"),
        vec![],
    );
    index.index_doc(
        doc2.clone(),
        "A lazy cat sleeps all day long",
        Some("Cat Story"),
        vec![],
    );

    let results = index.search("fox", 10);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].doc_id, doc1);

    let results = index.search("lazy", 10);
    assert_eq!(results.len(), 2);
}

#[test]
fn text_index_scoring_order() {
    let mut index = TextIndex::new();
    let doc1 = DocId::random();
    let doc2 = DocId::random();

    // doc1 has "rust" once
    index.index_doc(doc1.clone(), "I love rust programming", None, vec![]);
    // doc2 has "rust" multiple times
    index.index_doc(
        doc2.clone(),
        "rust rust rust is the best rust language rust",
        None,
        vec![],
    );

    let results = index.search("rust", 10);
    assert_eq!(results.len(), 2);
    // doc2 should score higher (more occurrences)
    assert_eq!(results[0].doc_id, doc2);
    assert_eq!(results[1].doc_id, doc1);
}

#[test]
fn text_index_remove() {
    let mut index = TextIndex::new();
    let doc1 = DocId::random();

    index.index_doc(doc1.clone(), "hello world", None, vec![]);
    assert_eq!(index.search("hello", 10).len(), 1);

    index.remove_doc(&doc1);
    assert_eq!(index.search("hello", 10).len(), 0);
}

#[test]
fn text_index_empty_query() {
    let mut index = TextIndex::new();
    let doc1 = DocId::random();
    index.index_doc(doc1, "some content", None, vec![]);

    let results = index.search("", 10);
    assert!(results.is_empty());
}

#[test]
fn text_index_no_match() {
    let mut index = TextIndex::new();
    let doc1 = DocId::random();
    index.index_doc(doc1, "hello world", None, vec![]);

    let results = index.search("xyz123", 10);
    assert!(results.is_empty());
}

#[test]
fn text_index_title_boost() {
    let mut index = TextIndex::new();
    let doc1 = DocId::random();
    let doc2 = DocId::random();

    // doc1 has "database" only in body
    index.index_doc(doc1.clone(), "database is a tool for storage", None, vec![]);
    // doc2 has "database" in title (boosted 3x)
    index.index_doc(
        doc2.clone(),
        "just some text",
        Some("database guide"),
        vec![],
    );

    let results = index.search("database", 10);
    assert_eq!(results.len(), 2);
    // doc2 should rank higher due to title boost
    assert_eq!(results[0].doc_id, doc2);
}

// === QuotaManager Tests ===

#[test]
fn quota_check_write_within_limits() {
    let manager = QuotaManager::default();
    let agent = AgentId("agent-1".into());
    assert!(manager.check_write(&agent, 100).is_ok());
}

#[test]
fn quota_check_write_exceeds_storage() {
    let mut manager = QuotaManager::new(AgentQuota {
        max_docs: 10,
        max_bytes: 100,
        max_entities: 10,
    });
    let agent = AgentId("agent-1".into());

    // Record some bytes first
    manager.record_write(&agent, 90);

    // Now check a write that would exceed
    let result = manager.check_write(&agent, 20);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("byte limit exceeded"));
}

#[test]
fn quota_doc_create_limit() {
    let mut manager = QuotaManager::new(AgentQuota {
        max_docs: 2,
        max_bytes: 1_000_000,
        max_entities: 100,
    });
    let agent = AgentId("agent-1".into());

    manager.record_doc_create(&agent, 100);
    assert!(manager.check_doc_create(&agent).is_ok());

    manager.record_doc_create(&agent, 100);
    // Now at 2 docs, which equals the max
    let result = manager.check_doc_create(&agent);
    assert!(result.is_err());
}

#[test]
fn quota_entity_create_limit() {
    let mut manager = QuotaManager::new(AgentQuota {
        max_docs: 100,
        max_bytes: 1_000_000,
        max_entities: 1,
    });
    let agent = AgentId("agent-1".into());

    manager.record_entity_create(&agent);
    let result = manager.check_entity_create(&agent);
    assert!(result.is_err());
}

#[test]
fn quota_custom_quota_per_agent() {
    let mut manager = QuotaManager::default();
    let agent = AgentId("special-agent".into());

    // Set a very small custom quota
    manager.set_quota(
        &agent,
        AgentQuota {
            max_docs: 1,
            max_bytes: 50,
            max_entities: 1,
        },
    );

    manager.record_write(&agent, 40);
    // 40 + 20 > 50
    let result = manager.check_write(&agent, 20);
    assert!(result.is_err());
}

// === Retraction Tests ===

#[test]
fn retraction_basic() {
    let (_dir, store) = temp_store();

    // Store a block
    let target_cid = b"block-to-retract";
    store.put_block(target_cid, b"some data").unwrap();

    // Not retracted initially
    assert!(!is_retracted(&store, target_cid).unwrap());

    // Retract it
    let tombstone_cid = b"tombstone-1";
    retract(&store, target_cid, tombstone_cid).unwrap();

    // Now it is retracted
    assert!(is_retracted(&store, target_cid).unwrap());
}

#[test]
fn retraction_double_retract_errors() {
    let (_dir, store) = temp_store();

    let target_cid = b"block-double";
    store.put_block(target_cid, b"data").unwrap();

    let tombstone = b"tomb-1";
    retract(&store, target_cid, tombstone).unwrap();

    // Second retraction should fail
    let result = retract(&store, target_cid, b"tomb-2");
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("already retracted")
    );
}

// === DiffEntry Tests ===

#[test]
fn diff_empty_to_ops() {
    use memvault_doc::Op;
    use std::collections::BTreeMap;

    let before: Vec<Op> = vec![];
    let after = vec![Op::DocCreate {
        doc_id: DocId::random(),
        initial_body: "hello".into(),
        frontmatter: BTreeMap::new(),
    }];

    let diff = diff_doc(&before, &after);
    assert_eq!(diff.len(), 1);
    assert!(matches!(diff[0], DiffEntry::Added(_)));
}

#[test]
fn diff_ops_to_empty() {
    use memvault_doc::Op;
    use std::collections::BTreeMap;

    let before = vec![Op::DocCreate {
        doc_id: DocId::random(),
        initial_body: "hello".into(),
        frontmatter: BTreeMap::new(),
    }];
    let after: Vec<Op> = vec![];

    let diff = diff_doc(&before, &after);
    assert_eq!(diff.len(), 1);
    assert!(matches!(diff[0], DiffEntry::Removed(_)));
}

#[test]
fn diff_same_ops() {
    use memvault_doc::Op;
    use std::collections::BTreeMap;

    let doc_id = DocId::random();
    let ops = vec![Op::DocCreate {
        doc_id: doc_id.clone(),
        initial_body: "same".into(),
        frontmatter: BTreeMap::new(),
    }];

    let diff = diff_doc(&ops, &ops);
    assert!(diff.is_empty());
}

#[test]
fn diff_mixed_changes() {
    use memvault_doc::Op;
    use std::collections::BTreeMap;

    let doc_id = DocId::random();
    let op_a = Op::DocCreate {
        doc_id: doc_id.clone(),
        initial_body: "a".into(),
        frontmatter: BTreeMap::new(),
    };
    let op_b = Op::DocSetMeta {
        doc_id: doc_id.clone(),
        key: "title".into(),
        value: serde_json::json!("hello"),
    };
    let op_c = Op::DocRemoveMeta {
        doc_id: doc_id.clone(),
        key: "title".into(),
    };

    let before = vec![op_a.clone(), op_b.clone()];
    let after = vec![op_a.clone(), op_c.clone()];

    let diff = diff_doc(&before, &after);
    // op_b removed, op_c added
    assert_eq!(diff.len(), 2);
    let removed_count = diff
        .iter()
        .filter(|d| matches!(d, DiffEntry::Removed(_)))
        .count();
    let added_count = diff
        .iter()
        .filter(|d| matches!(d, DiffEntry::Added(_)))
        .count();
    assert_eq!(removed_count, 1);
    assert_eq!(added_count, 1);
}

// === Effective Tags Tests ===

#[test]
fn effective_tags_no_parents() {
    let own = vec![
        Tag::new("project", "memvault"),
        Tag::new("classification", "internal"),
    ];
    let parent_tags: Vec<Vec<Tag>> = vec![];

    let result = effective_tags(&own, &parent_tags);
    assert_eq!(result.len(), 2);
    assert!(result.contains(&Tag::new("project", "memvault")));
    assert!(result.contains(&Tag::new("classification", "internal")));
}

#[test]
fn effective_tags_inherits_from_parents() {
    let own = vec![Tag::new("project", "memvault")];
    let parent_tags = vec![vec![
        Tag::new("team", "infra"),
        Tag::new("priority", "high"),
    ]];

    let result = effective_tags(&own, &parent_tags);
    assert_eq!(result.len(), 3);
    assert!(result.contains(&Tag::new("project", "memvault")));
    assert!(result.contains(&Tag::new("team", "infra")));
    assert!(result.contains(&Tag::new("priority", "high")));
}

#[test]
fn effective_tags_no_duplicates() {
    let own = vec![Tag::new("project", "memvault"), Tag::new("team", "infra")];
    let parent_tags = vec![vec![
        Tag::new("team", "infra"),
        Tag::new("org", "engineering"),
    ]];

    let result = effective_tags(&own, &parent_tags);
    assert_eq!(result.len(), 3);
    // "team:infra" appears once
    let team_count = result
        .iter()
        .filter(|t| t.scope == "team" && t.label == "infra")
        .count();
    assert_eq!(team_count, 1);
}

#[test]
fn effective_tags_multiple_parents() {
    let own = vec![Tag::new("kind", "doc")];
    let parent_tags = vec![
        vec![Tag::new("team", "alpha")],
        vec![Tag::new("team", "beta"), Tag::new("priority", "low")],
    ];

    let result = effective_tags(&own, &parent_tags);
    assert_eq!(result.len(), 4);
    assert!(result.contains(&Tag::new("kind", "doc")));
    assert!(result.contains(&Tag::new("team", "alpha")));
    assert!(result.contains(&Tag::new("team", "beta")));
    assert!(result.contains(&Tag::new("priority", "low")));
}

// === Checkpoint Tests ===

#[test]
fn checkpoint_creation() {
    let doc_id = DocId::random();
    let peer_id = PeerId(b"peer-1".to_vec());
    let cp = Checkpoint::new(
        "v1.0".into(),
        doc_id.clone(),
        b"op-cid-123".to_vec(),
        1_000_000,
        peer_id.clone(),
    );

    assert_eq!(cp.name, "v1.0");
    assert_eq!(cp.doc_id, doc_id);
    assert_eq!(cp.op_cid, b"op-cid-123");
    assert_eq!(cp.wall_ns, 1_000_000);
    assert_eq!(cp.created_by, peer_id);
}

#[test]
fn checkpoint_serialization_roundtrip() {
    let cp = Checkpoint::new(
        "release-2".into(),
        DocId::random(),
        b"cid-bytes".to_vec(),
        999,
        PeerId(b"author".to_vec()),
    );

    let json = serde_json::to_string(&cp).unwrap();
    let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, cp.name);
    assert_eq!(deserialized.wall_ns, cp.wall_ns);
}

// === Trace Provenance Tests ===

#[test]
fn trace_provenance_with_linked_blocks() {
    let (_dir, store) = temp_store();

    // Create a parent block with metadata
    let parent_data = serde_json::json!({
        "author": "alice",
        "wall_ns": 1000,
        "tags": [["project", "memvault"]],
        "provenance": []
    });
    let parent_bytes = serde_json::to_vec(&parent_data).unwrap();
    store.put_block(b"parent-cid", &parent_bytes).unwrap();

    // Create a child block that references parent in provenance
    let child_data = serde_json::json!({
        "author": "bob",
        "wall_ns": 2000,
        "tags": [["kind", "update"]],
        "provenance": ["parent-cid"]
    });
    let child_bytes = serde_json::to_vec(&child_data).unwrap();
    store.put_block(b"child-cid", &child_bytes).unwrap();

    let trace = trace_provenance(&store, b"child-cid", 5).unwrap();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].cid, b"parent-cid");
    assert_eq!(trace[0].depth, 1);
    assert_eq!(trace[0].wall_ns, 1000);
}

#[test]
fn trace_provenance_respects_max_depth() {
    let (_dir, store) = temp_store();

    // Chain: c -> b -> a
    let a_data = serde_json::json!({
        "author": "a",
        "wall_ns": 100,
        "tags": [],
        "provenance": []
    });
    store
        .put_block(b"a", &serde_json::to_vec(&a_data).unwrap())
        .unwrap();

    let b_data = serde_json::json!({
        "author": "b",
        "wall_ns": 200,
        "tags": [],
        "provenance": ["a"]
    });
    store
        .put_block(b"b", &serde_json::to_vec(&b_data).unwrap())
        .unwrap();

    let c_data = serde_json::json!({
        "author": "c",
        "wall_ns": 300,
        "tags": [],
        "provenance": ["b"]
    });
    store
        .put_block(b"c", &serde_json::to_vec(&c_data).unwrap())
        .unwrap();

    // max_depth=1: only finds b, not a
    let trace = trace_provenance(&store, b"c", 1).unwrap();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].cid, b"b");

    // max_depth=5: finds both b and a
    let trace = trace_provenance(&store, b"c", 5).unwrap();
    assert_eq!(trace.len(), 2);
}

#[test]
fn trace_provenance_empty_for_root() {
    let (_dir, store) = temp_store();

    let root_data = serde_json::json!({
        "author": "root",
        "wall_ns": 100,
        "tags": [],
        "provenance": []
    });
    store
        .put_block(b"root", &serde_json::to_vec(&root_data).unwrap())
        .unwrap();

    let trace = trace_provenance(&store, b"root", 10).unwrap();
    assert!(trace.is_empty());
}

// === Audit Query Tests ===

#[test]
fn audit_query_by_time_range() {
    use crate::audit::query::{AuditQuery, query_audit};

    let (_dir, store) = temp_store();

    // Insert some envelope-like blocks
    for i in 0..5u64 {
        let data = serde_json::json!({
            "author": [1, 2, 3],
            "wall_ns": (i + 1) * 100,
            "tags": [["system", "event"]],
            "payload": { "DocCreate": { "doc_id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], "initial_body": "test" } }
        });
        let cid = format!("audit-cid-{i}");
        let meta = EnvelopeMeta {
            author: vec![1, 2, 3],
            tags: vec![("system".into(), "event".into())],
            wall_ns: (i + 1) * 100,
            causal: vec![],
            provenance: vec![],
            cluster_id: None,
            bucket_id: None,
        };
        store
            .insert_envelope(cid.as_bytes(), &serde_json::to_vec(&data).unwrap(), &meta)
            .unwrap();
    }

    let query = AuditQuery {
        after_ns: Some(200),
        before_ns: Some(400),
        limit: Some(10),
        ..Default::default()
    };
    let records = query_audit(&store, &query).unwrap();
    // wall_ns 200 and 300 are in range [200, 400)
    assert_eq!(records.len(), 2);
}
