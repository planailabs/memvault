//! Integration tests for LocalClient.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use memvault_api::{EventBus, LocalClient, MemvaultClient, MemvaultEvent};
use memvault_core::{DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{BucketRole, Document, Edge, Entity};
use memvault_query::QuotaManager;
use memvault_store::MemvaultStore;
use rand::RngCore;

fn make_client() -> (tempfile::TempDir, Arc<LocalClient>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let quotas = Arc::new(RwLock::new(QuotaManager::default()));
    let event_bus = Arc::new(EventBus::new(64));
    // Use proper 32-byte IDs so bucket auto-bind works correctly.
    let mut peer_id = [0u8; 32];
    peer_id[..6].copy_from_slice(b"peer-1");
    let mut cluster_id = [0u8; 32];
    cluster_id[..9].copy_from_slice(b"cluster-1");
    let client = Arc::new(LocalClient::new(
        store,
        quotas,
        event_bus,
        peer_id.to_vec(),
        cluster_id.to_vec(),
    ));
    // LocalClient now refuses writes without a node signing key; install
    // a deterministic one so this test harness can issue write ops.
    client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]));
    (dir, client)
}

#[tokio::test]
async fn put_doc_and_get_doc_roundtrip() {
    let (_dir, client) = make_client();

    let doc_id = DocId::random();
    let mut frontmatter = BTreeMap::new();
    frontmatter.insert("title".to_string(), serde_json::json!("Test Document"));

    let doc = Document::new(doc_id.clone(), "Hello, world!".to_string(), frontmatter);

    let cid = client
        .put_doc(
            doc,
            vec![("ns".into(), "test".into())],
            Visibility::Internal,
            None,
        )
        .await
        .unwrap();
    assert!(!cid.is_empty());

    let retrieved = client.get_doc(&doc_id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, doc_id);
    assert_eq!(retrieved.body, "Hello, world!");
    assert_eq!(
        retrieved.frontmatter.get("title"),
        Some(&serde_json::json!("Test Document"))
    );
}

#[tokio::test]
async fn attach_file_and_get_attachment_roundtrip() {
    let (_dir, client) = make_client();

    let doc_id = DocId::random();
    let doc = Document::new(
        doc_id.clone(),
        "doc with attachment".to_string(),
        BTreeMap::new(),
    );
    client
        .put_doc(doc, vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let file_data = b"This is a test file with some content for chunking tests.";
    let manifest_cid = client
        .upload_file(
            file_data,
            Some("test.txt"),
            "text/plain",
            vec![("classification".to_string(), "internal".to_string())],
            "internal",
            None,
        )
        .await
        .unwrap();
    assert!(!manifest_cid.is_empty());

    let retrieved_data = client.read_file(&manifest_cid).await.unwrap();
    assert_eq!(retrieved_data, file_data.to_vec());
}

#[tokio::test]
async fn add_entity_and_traverse() {
    let (_dir, client) = make_client();

    // Create entities
    let entity_a = Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props: BTreeMap::new(),
        edges_out: vec![],
    };
    let entity_b = Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props: BTreeMap::new(),
        edges_out: vec![],
    };
    let entity_c = Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props: BTreeMap::new(),
        edges_out: vec![],
    };

    let id_a = client
        .add_entity(entity_a.clone(), Visibility::Internal, None)
        .await
        .unwrap();
    let id_b = client
        .add_entity(entity_b.clone(), Visibility::Internal, None)
        .await
        .unwrap();
    let id_c = client
        .add_entity(entity_c.clone(), Visibility::Internal, None)
        .await
        .unwrap();

    // Add edges: A -> B, B -> C
    let edge_ab = Edge {
        id: EdgeId::random(),
        relation: "knows".to_string(),
        target: NodeRef::Entity(id_b.clone()),
        weight: Some(1.0),
        props: BTreeMap::new(),
        provenance: None,
    };
    client
        .add_link(
            &NodeRef::Entity(id_a.clone()),
            edge_ab,
            Visibility::Internal,
        )
        .await
        .unwrap();

    let edge_bc = Edge {
        id: EdgeId::random(),
        relation: "knows".to_string(),
        target: NodeRef::Entity(id_c.clone()),
        weight: Some(1.0),
        props: BTreeMap::new(),
        provenance: None,
    };
    client
        .add_link(
            &NodeRef::Entity(id_b.clone()),
            edge_bc,
            Visibility::Internal,
        )
        .await
        .unwrap();

    // Traverse from A with max_depth=2
    let hits = client
        .traverse_from(&NodeRef::Entity(id_a.clone()), Some("knows"), 2)
        .await
        .unwrap();
    assert_eq!(hits.len(), 2);

    // First hit should be B at depth 1
    assert_eq!(hits[0].node, NodeRef::Entity(id_b));
    assert_eq!(hits[0].depth, 1);

    // Second hit should be C at depth 2
    assert_eq!(hits[1].node, NodeRef::Entity(id_c));
    assert_eq!(hits[1].depth, 2);
}

#[tokio::test]
async fn skill_publish_get_list_rename_roundtrip() {
    let (_dir, client) = make_client();

    let spec = memvault_api::SkillSpec {
        name: "Code Review".to_string(),
        description: Some("Review a diff for bugs".to_string()),
        trigger: Some("when asked to review code".to_string()),
        instruction_body: Some("# Code Review\nRun the linter, then read the diff.".to_string()),
    };
    let skill_id = client
        .skill_publish(spec, Visibility::Internal, None)
        .await
        .unwrap();

    // get() assembles the manifest plus the linked instruction doc.
    let bundle = client.skill_get(&skill_id).await.unwrap().expect("skill exists");
    assert_eq!(bundle.info.name, "Code Review");
    assert_eq!(bundle.info.description.as_deref(), Some("Review a diff for bugs"));
    assert_eq!(bundle.instructions.len(), 1);
    assert_eq!(bundle.instructions[0].relation, memvault_core::SKILL_INSTRUCTION_REL);
    assert!(bundle.instructions[0].node.starts_with("doc:"));

    // A plain (non-skill) entity must not appear in skill_list.
    let other = Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props: BTreeMap::new(),
        edges_out: vec![],
    };
    client.add_entity(other, Visibility::Internal, None).await.unwrap();

    let skills = client.skill_list(100, None).await.unwrap();
    assert_eq!(skills.len(), 1, "only the skill, not the person entity");
    assert_eq!(skills[0].id, skill_id);
    assert_eq!(skills[0].name, "Code Review");

    // Link a script resource with a bundle path + exec bit.
    let file_cid = client
        .upload_file(
            b"#!/bin/sh\necho hi\n",
            Some("run.sh"),
            "text/x-shellscript",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();
    let edge_id = client
        .skill_link_resource(
            &skill_id,
            &NodeRef::Attachment(file_cid.clone()),
            memvault_core::SKILL_RESOURCE_REL,
            Some("scripts/run.sh"),
            true,
            Visibility::Internal,
        )
        .await
        .unwrap();

    let bundle = client.skill_get(&skill_id).await.unwrap().unwrap();
    assert_eq!(bundle.resources.len(), 1);
    assert_eq!(bundle.resources[0].path.as_deref(), Some("scripts/run.sh"));
    assert!(bundle.resources[0].executable);

    // Unlink the resource.
    client.skill_unlink_resource(&skill_id, &edge_id).await.unwrap();
    let bundle = client.skill_get(&skill_id).await.unwrap().unwrap();
    assert_eq!(bundle.resources.len(), 0);

    // Rename via EntityUpdate; both get() and list() reflect it.
    client.skill_rename(&skill_id, "Diff Review").await.unwrap();
    let bundle = client.skill_get(&skill_id).await.unwrap().unwrap();
    assert_eq!(bundle.info.name, "Diff Review");
    let skills = client.skill_list(100, None).await.unwrap();
    assert_eq!(skills[0].name, "Diff Review");

    // Delete (retract): no longer listed.
    client.skill_delete(&skill_id, "obsolete").await.unwrap();
    let skills = client.skill_list(100, None).await.unwrap();
    assert_eq!(skills.len(), 0);
}

#[tokio::test]
async fn skill_hydrate_materializes_bundle() {
    let (_dir, client) = make_client();

    let spec = memvault_api::SkillSpec {
        name: "Deploy".to_string(),
        description: None,
        trigger: None,
        instruction_body: Some("# Deploy\nRun scripts/run.sh".to_string()),
    };
    let skill_id = client
        .skill_publish(spec, Visibility::Internal, None)
        .await
        .unwrap();

    let script = b"#!/bin/sh\necho deploying\n";
    let cid = client
        .upload_file(script, Some("run.sh"), "text/x-shellscript", vec![], "internal", None)
        .await
        .unwrap();
    client
        .skill_link_resource(
            &skill_id,
            &NodeRef::Attachment(cid),
            memvault_core::SKILL_RESOURCE_REL,
            Some("scripts/run.sh"),
            true,
            Visibility::Internal,
        )
        .await
        .unwrap();

    let out = tempfile::tempdir().unwrap();
    let report = memvault_api::skill_hydrate::hydrate_skill(
        client.as_ref(),
        &skill_id,
        out.path(),
        true,
    )
    .await
    .unwrap();

    // SKILL.md (instruction) + scripts/run.sh (resource) both written.
    let skill_md = std::fs::read_to_string(out.path().join("SKILL.md")).unwrap();
    assert!(skill_md.contains("Run scripts/run.sh"));
    let run_sh = std::fs::read(out.path().join("scripts/run.sh")).unwrap();
    assert_eq!(run_sh, script);
    assert_eq!(report.written.len(), 2);

    // Trust gate: the test harness writes as the node (no bound agent
    // identity), so the manifest carries no agent attestation — the executable
    // bit is withheld even though set_executable=true was requested.
    assert!(!report.author_attested, "node-authored skill is not attested");
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.contains("not attested")),
        "withholding the exec bit is reported, got {:?}",
        report.skipped
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(out.path().join("scripts/run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o111,
            0,
            "executable bit withheld for an unattested author"
        );
    }

    // Path traversal is rejected (defense-in-depth on the join helper).
    let evil = tempfile::tempdir().unwrap();
    // Re-link a resource with a traversal path and confirm hydrate errors.
    client
        .skill_link_resource(
            &skill_id,
            &NodeRef::Attachment(client
                .upload_file(b"x", Some("x"), "text/plain", vec![], "internal", None)
                .await
                .unwrap()),
            memvault_core::SKILL_RESOURCE_REL,
            Some("../escape.sh"),
            false,
            Visibility::Internal,
        )
        .await
        .unwrap();
    let res = memvault_api::skill_hydrate::hydrate_skill(
        client.as_ref(),
        &skill_id,
        evil.path(),
        false,
    )
    .await;
    assert!(res.is_err(), "traversal path must be rejected");
}

#[tokio::test]
async fn search_after_indexing() {
    let (_dir, client) = make_client();

    let doc_id = DocId::random();
    let mut frontmatter = BTreeMap::new();
    frontmatter.insert("title".to_string(), serde_json::json!("Rust Programming"));

    let doc = Document::new(
        doc_id.clone(),
        "Rust is a systems programming language focused on safety.".to_string(),
        frontmatter,
    );
    client
        .put_doc(
            doc,
            vec![("lang".into(), "rust".into())],
            Visibility::Internal,
            None,
        )
        .await
        .unwrap();

    // Search for "safety"
    let hits = client.search("safety", 10).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].doc_id, doc_id);
    assert!(hits[0].score > 0.0);

    // Search for something that doesn't exist
    let hits = client.search("python", 10).await.unwrap();
    assert!(hits.is_empty());
}

#[tokio::test]
async fn event_bus_publish_subscribe() {
    let bus = EventBus::new(16);
    let mut rx = bus.subscribe();

    let doc_id = DocId::random();
    bus.publish(MemvaultEvent::DocCreated {
        doc_id: doc_id.clone(),
        cid: vec![1, 2, 3],
    });

    let event = rx.recv().await.unwrap();
    match event {
        MemvaultEvent::DocCreated { doc_id: id, cid } => {
            assert_eq!(id, doc_id);
            assert_eq!(cid, vec![1, 2, 3]);
        }
        _ => panic!("unexpected event"),
    }
}

#[tokio::test]
async fn quota_manager_integration() {
    use memvault_query::AgentQuota;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let quotas = Arc::new(RwLock::new(QuotaManager::new(AgentQuota {
        max_docs: 2,
        max_bytes: 1_000_000,
        max_entities: 100,
    })));
    let event_bus = Arc::new(EventBus::new(64));
    let _client = Arc::new(LocalClient::new(
        store,
        quotas.clone(),
        event_bus,
        b"peer-1".to_vec(),
        b"cluster-1".to_vec(),
    ));

    let agent = [0x11u8; 32]; // agent ed25519 pubkey (quota is keyed by pubkey)

    // Check that writes are allowed initially
    {
        let q = quotas.read().await;
        assert!(q.check_write(&agent, 100).is_ok());
        assert!(q.check_doc_create(&agent).is_ok());
    }

    // Record some usage
    {
        let mut q = quotas.write().await;
        q.record_doc_create(&agent, 500);
        q.record_doc_create(&agent, 500);
    }

    // Now doc creation should be denied (max_docs = 2)
    {
        let q = quotas.read().await;
        assert!(q.check_doc_create(&agent).is_err());
    }

    // But writes are still allowed (under byte limit)
    {
        let q = quotas.read().await;
        assert!(q.check_write(&agent, 100).is_ok());
    }
}

// ── Bucket lifecycle tests ──────────────────────────────────────────

#[tokio::test]
async fn bucket_create_and_list() {
    let (_dir, client) = make_client();

    // Initially no buckets
    let buckets = client.bucket_list().await.unwrap();
    assert!(buckets.is_empty());

    // Create a bucket
    let bucket_id = client
        .bucket_create(
            "test-bucket",
            Some("A test bucket"),
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    // List should return it
    let buckets = client.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].name, "test-bucket");
    assert_eq!(buckets[0].id, bucket_id);
    // With a non-zero cluster_id, bucket_create auto-attaches and auto-binds.
    assert!(buckets[0].is_attached);
    assert!(buckets[0].cluster_id.is_some());
}

#[tokio::test]
async fn bucket_get_by_id() {
    let (_dir, client) = make_client();
    let bucket_id = client
        .bucket_create(
            "alpha",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap();
    assert!(info.is_some());
    let info = info.unwrap();
    assert_eq!(info.name, "alpha");
    assert_eq!(info.id, bucket_id);
}

#[tokio::test]
async fn bucket_get_nonexistent_returns_none() {
    let (_dir, client) = make_client();
    let fake_id = memvault_core::BucketId([99u8; 32]);
    let info = client.bucket_get(&fake_id).await.unwrap();
    assert!(info.is_none());
}

#[tokio::test]
async fn bucket_rename() {
    let (_dir, client) = make_client();
    let bucket_id = client
        .bucket_create(
            "old-name",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    client.bucket_rename(&bucket_id, "new-name").await.unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert_eq!(info.name, "new-name");
}

#[tokio::test]
async fn bucket_bind_to_cluster() {
    // Use a zero cluster to test explicit binding without auto-bind.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let client = Arc::new(LocalClient::new(
        store,
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        b"peer-1".to_vec(),
        vec![0u8; 32],
    ));
    client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]));
    let bucket_id = client
        .bucket_create(
            "bindable",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    // Not bound yet (zero cluster = no auto-bind)
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.cluster_id.is_none());

    let cluster_id = memvault_core::ClusterId([1u8; 32]);
    client
        .bucket_bind(&bucket_id, &cluster_id)
        .await
        .unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert_eq!(info.cluster_id, Some(cluster_id));
}

#[tokio::test]
async fn bucket_attach_flips_private() {
    // Use zero cluster so bucket starts private (no auto-attach).
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let client = Arc::new(LocalClient::new(
        store,
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        b"peer-1".to_vec(),
        vec![0u8; 32],
    ));
    client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]));
    let bucket_id = client
        .bucket_create(
            "private-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    // Initially private (no cluster → not auto-attached)
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(!info.is_attached);

    // Attach
    client.bucket_attach(&bucket_id).await.unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.is_attached);

    // Idempotent
    client.bucket_attach(&bucket_id).await.unwrap();
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.is_attached);
}

#[tokio::test]
async fn bucket_archive() {
    let (_dir, client) = make_client();
    // First bucket becomes auto-bound default; create a second one to archive.
    let _default = client
        .bucket_create(
            "default",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    let bucket_id = client
        .bucket_create(
            "archivable",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    client
        .bucket_archive(&bucket_id, "no longer needed")
        .await
        .unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.name.contains("[ARCHIVED]"));
    assert!(
        info.description
            .unwrap_or_default()
            .contains("no longer needed")
    );
}

#[tokio::test]
async fn bucket_archive_default_refused() {
    let (_dir, client) = make_client();
    let bucket_id = client
        .bucket_create(
            "the-default",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    // Auto-bound by bucket_create. Bind explicitly.
    let mut cluster_arr = [0u8; 32];
    cluster_arr[..9].copy_from_slice(b"cluster-1");
    client
        .bucket_bind(&bucket_id, &memvault_core::ClusterId(cluster_arr))
        .await
        .unwrap();
    // Archiving is now allowed (no default-bucket guard).
    let result = client.bucket_archive(&bucket_id, "try to remove").await;
    assert!(result.is_ok(), "archiving bucket should succeed");
}

#[tokio::test]
async fn bucket_create_multiple_and_list() {
    let (_dir, client) = make_client();

    let _b1 = client
        .bucket_create(
            "alpha",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    let _b2 = client
        .bucket_create(
            "beta",
            None,
            Visibility::Federated,
            memvault_core::classification::Classification::Public,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    let _b3 = client
        .bucket_create(
            "gamma",
            None,
            Visibility::Public,
            memvault_core::classification::Classification::Confidential,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    let buckets = client.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 3);

    let names: Vec<&str> = buckets.iter().map(|b| b.name.as_str()).collect();
    assert!(names.contains(&"alpha"));
    assert!(names.contains(&"beta"));
    assert!(names.contains(&"gamma"));
}

// ── PeerId persistence tests ────────────────────────────────────────

#[test]
fn store_peer_id_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    // Initially no peer_id
    assert!(store.get_local_peer_id().unwrap().is_none());

    // Set it
    let peer_id = vec![42u8; 32];
    store.set_local_peer_id(&peer_id).unwrap();

    // Read it back
    assert_eq!(store.get_local_peer_id().unwrap().unwrap(), peer_id);

    // Setting the same value again is OK (idempotent)
    store.set_local_peer_id(&peer_id).unwrap();

    // Setting a different value fails
    let other_peer_id = vec![99u8; 32];
    assert!(store.set_local_peer_id(&other_peer_id).is_err());
}

#[test]
fn store_cluster_id_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    assert!(store.get_local_cluster_id().unwrap().is_none());

    let cluster_id = vec![7u8; 32];
    store.set_local_cluster_id(&cluster_id).unwrap();
    assert_eq!(store.get_local_cluster_id().unwrap().unwrap(), cluster_id);
}

// ── Exclusive cluster binding tests ─────────────────────────────

#[tokio::test]
async fn bucket_bind_exclusive_to_one_cluster() {
    // Use zero cluster so bucket starts unbound.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let client = Arc::new(LocalClient::new(
        store,
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        b"peer-1".to_vec(),
        vec![0u8; 32],
    ));
    client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]));
    let bucket_id = client
        .bucket_create(
            "exclusive",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    let cluster_a = memvault_core::ClusterId([1u8; 32]);
    let cluster_b = memvault_core::ClusterId([2u8; 32]);

    // Bind to cluster A succeeds
    client
        .bucket_bind(&bucket_id, &cluster_a)
        .await
        .unwrap();

    // Rebind to same cluster A is idempotent
    client
        .bucket_bind(&bucket_id, &cluster_a)
        .await
        .unwrap();

    // Bind to different cluster B fails
    let result = client.bucket_bind(&bucket_id, &cluster_b).await;
    assert!(
        result.is_err(),
        "should refuse rebinding to a different cluster"
    );
}

#[tokio::test]
async fn bucket_bind_idempotent_same_cluster() {
    // Use zero cluster so bucket starts unbound.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let client = Arc::new(LocalClient::new(
        store,
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        b"peer-1".to_vec(),
        vec![0u8; 32],
    ));
    client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]));
    let bucket_id = client
        .bucket_create(
            "idem",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    let cluster = memvault_core::ClusterId([5u8; 32]);

    // Bind as non-default
    client
        .bucket_bind(&bucket_id, &cluster)
        .await
        .unwrap();
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert_eq!(info.cluster_id, Some(cluster));
}

#[test]
fn store_bind_unbound_buckets() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    // Create 3 buckets in the store directly
    for i in 0..3u8 {
        let bucket_id = [i + 10; 32];
        let decl_cid = [i + 100; 32];
        store.put_bucket(&bucket_id, &decl_cid).unwrap();
    }

    // Bind one to a cluster
    let cluster_id = [1u8; 32];
    store.bind_bucket(&[10; 32], &cluster_id).unwrap();

    // bind_unbound_buckets should bind the other 2
    let count = store.bind_unbound_buckets(&cluster_id).unwrap();
    assert_eq!(count, 2);

    // Now all 3 should be bound
    for i in 0..3u8 {
        let bucket_id = [i + 10; 32];
        assert!(store.get_bucket_cluster(&bucket_id).unwrap().is_some());
    }

    // Running again should bind 0
    let count = store.bind_unbound_buckets(&cluster_id).unwrap();
    assert_eq!(count, 0);
}

// ── Share decide tests ──────────────────────────────────────────

#[tokio::test]
async fn share_inbox_initially_empty() {
    let (_dir, client) = make_client();
    let inbox = client.share_inbox().await.unwrap();
    assert!(inbox.is_empty());
}

// ── Auth validation tests ───────────────────────────────────────

#[test]
fn agent_identity_requires_all_files() {
    let dir = tempfile::tempdir().unwrap();
    let identity_dir = dir.path().join("incomplete-agent");
    std::fs::create_dir_all(&identity_dir).unwrap();

    // Missing files should fail to load
    assert!(!memvault_api::agent_identity::AgentIdentity::exists(
        &identity_dir
    ));

    let result = memvault_api::agent_identity::AgentIdentity::load(&identity_dir);
    assert!(result.is_err());
}

#[test]
fn join_token_roundtrip_with_verify() {
    use ed25519_dalek::{Signer, SigningKey};
    use memvault_auth::{
        AgentRole, JoinToken, TokenRole, decode_token_string, encode_token_string,
    };
    use memvault_core::{ClusterId, PeerId};

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();
    let peer_id = PeerId(vk.as_bytes().to_vec());
    let cluster_id = ClusterId::random();

    let token = JoinToken {
        issuer: peer_id.clone(),
        cluster_id: cluster_id.clone(),
        role: TokenRole::Agent(AgentRole::AgentHost),
        initial_grants: vec![],
        not_before_ns: 0,
        not_after_ns: u64::MAX,
        max_uses: 5,
        nonce: [42u8; 16],
        label: Some("test".into()),
        admin_genesis: None,
        issuer_addrs: vec![],
        signature: [0u8; 64],
    };

    // Sign
    let signing_bytes = token.signing_bytes().unwrap();
    let sig = sk.sign(&signing_bytes);
    let signed_token = JoinToken {
        signature: sig.to_bytes(),
        ..token
    };

    // Encode + decode
    let encoded = encode_token_string(&signed_token).unwrap();
    assert!(encoded.starts_with("mvjoin1:"));

    let decoded = decode_token_string(&encoded).unwrap();
    assert_eq!(decoded.max_uses, 5);
    assert_eq!(decoded.label, Some("test".into()));

    // Verify
    decoded.verify_signature(&vk).unwrap();
    decoded.verify_time_bounds(1000).unwrap();

    // Expired token fails
    let expired = JoinToken {
        not_after_ns: 500,
        ..decoded
    };
    assert!(expired.verify_time_bounds(1000).is_err());
}

// ── Envelope v1/v2 roundtrip tests ──────────────────────────────

#[test]
fn envelope_v1_no_bucket_roundtrip() {
    use memvault_core::tags::Tag;
    use memvault_core::{BucketId, PeerId, Signed, Visibility};

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    let envelope = Signed::sign(
        "v1 content".to_string(),
        &sk,
        PeerId(vk.as_bytes().to_vec()),
        vec![],
        vec![],
        vec![Tag::new("classification", "internal")],
        Visibility::Internal,
        1,
        1000,
        None,
        None, // no bucket = v1
        None, // no node_attestation
        None, // no agent_attestation
        None, // no agent co-signer
    )
    .unwrap();

    assert_eq!(envelope.version, 1);
    assert!(envelope.bucket_id.is_none());
    envelope.verify(&vk).unwrap();
}

#[test]
fn envelope_v2_with_bucket_roundtrip() {
    use memvault_core::tags::Tag;
    use memvault_core::{BucketId, PeerId, Signed, Visibility};

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();
    let bucket = BucketId::random();

    let envelope = Signed::sign(
        "v2 content".to_string(),
        &sk,
        PeerId(vk.as_bytes().to_vec()),
        vec![],
        vec![],
        vec![Tag::new("classification", "internal")],
        Visibility::Internal,
        1,
        1000,
        None,
        Some(bucket.clone()),
        None, // no node_attestation
        None, // no agent_attestation
        None, // no agent co-signer
    )
    .unwrap();

    assert_eq!(envelope.version, 2);
    assert_eq!(envelope.bucket_id, Some(bucket));
    envelope.verify(&vk).unwrap();
}

#[test]
fn envelope_v2_tampered_bucket_fails_verify() {
    use memvault_core::tags::Tag;
    use memvault_core::{BucketId, PeerId, Signed, Visibility};

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    let mut envelope = Signed::sign(
        "tamper test".to_string(),
        &sk,
        PeerId(vk.as_bytes().to_vec()),
        vec![],
        vec![],
        vec![Tag::new("classification", "internal")],
        Visibility::Internal,
        1,
        1000,
        None,
        Some(BucketId::random()),
        None, // no node_attestation
        None, // no agent_attestation
        None, // no agent co-signer
    )
    .unwrap();

    // Tamper with the bucket_id
    envelope.bucket_id = Some(BucketId::random());
    assert!(envelope.verify(&vk).is_err());
}

/// The token's `role` (which now carries admit-as-admin intent via
/// `NodeRole::Admin`) is part of the signed payload, so an attacker can't flip
/// a plain node-join token into an admin-admitting one.
#[test]
fn join_token_role_is_signature_bound() {
    use ed25519_dalek::{Signer, SigningKey};
    use memvault_auth::{JoinToken, NodeRole, TokenRole};
    use memvault_core::{ClusterId, PeerId};

    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();
    let mut token = JoinToken {
        issuer: PeerId(vk.to_bytes().to_vec()),
        cluster_id: ClusterId([1u8; 32]),
        role: TokenRole::Node(NodeRole::Admin),
        initial_grants: vec![],
        not_before_ns: 0,
        not_after_ns: u64::MAX,
        max_uses: 1,
        nonce: [3u8; 16],
        label: None,
        admin_genesis: None,
        issuer_addrs: vec![],
        signature: [0u8; 64],
    };
    token.signature = sk.sign(&token.signing_bytes().unwrap()).to_bytes();
    token.verify_signature(&vk).expect("admin node-join token verifies");
    assert!(token.admits_as_admin());

    // Downgrading the role to a plain node join must invalidate the signature.
    let mut tampered = token.clone();
    tampered.role = TokenRole::Node(NodeRole::Node);
    assert!(
        tampered.verify_signature(&vk).is_err(),
        "flipping the token role must break the signature"
    );
}

// ---------------------------------------------------------------------------
// Keystore-backed key material (admin signing key + genesis pin)
// ---------------------------------------------------------------------------

fn bare_client(dir: &tempfile::TempDir, name: &[u8]) -> Arc<LocalClient> {
    // Each client gets its OWN redb (redb takes a cross-process exclusive
    // lock — the very limitation the shared keystore exists to bypass).
    let redb_name = format!("redb-{}", String::from_utf8_lossy(name));
    let store = Arc::new(MemvaultStore::open(dir.path().join(redb_name)).unwrap());
    let quotas = Arc::new(RwLock::new(QuotaManager::default()));
    let event_bus = Arc::new(EventBus::new(64));
    let mut peer_id = [0u8; 32];
    peer_id[..name.len().min(32)].copy_from_slice(&name[..name.len().min(32)]);
    Arc::new(LocalClient::new(
        store,
        quotas,
        event_bus,
        peer_id.to_vec(),
        vec![0u8; 32],
    ))
}

// All bare_clients built under one tempdir share `store.dir()`, so they
// auto-open the SAME keystore (`<dir>/identity/keystore.mvks`) while keeping
// separate redb files — exactly the daemon + memctl cross-process model.

#[test]
fn admin_key_persists_to_keystore_and_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let seed = [42u8; 32];
    let pubkey = memvault_api::ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();

    // First client installs the admin key (auto-persisted to the keystore).
    let a = bare_client(&dir, b"node-a");
    assert_eq!(a.load_admin_keys_from_keystore(), 0, "empty to start");
    a.set_admin_signing_key(memvault_api::ed25519_dalek::SigningKey::from_bytes(&seed));
    assert!(a.admin_verifying_keys().iter().any(|k| k.to_bytes() == pubkey));

    // A second client (own redb, shared keystore) recovers the admin key —
    // no plaintext admin.key file in play.
    let b = bare_client(&dir, b"node-b");
    assert_eq!(b.load_admin_keys_from_keystore(), 1, "reloaded from keystore");
    assert!(
        b.admin_verifying_keys().iter().any(|k| k.to_bytes() == pubkey),
        "admin pubkey visible across handles"
    );
}

#[test]
fn genesis_pin_round_trips_through_keystore() {
    let dir = tempfile::tempdir().unwrap();
    let blob = b"\xa1\x01\x02 some-cbor-ish-genesis-bytes".to_vec();
    let a = bare_client(&dir, b"g1");
    assert!(a.pinned_admin_genesis_bytes_from_keystore().is_none());
    a.persist_pinned_admin_genesis_bytes(&blob).unwrap();
    let b = bare_client(&dir, b"g2");
    assert_eq!(b.pinned_admin_genesis_bytes_from_keystore(), Some(blob));
}

#[test]
fn encrypted_keystore_open_round_trips_and_hides_plaintext() {
    // The at-rest encryption path used when MEMVAULT_KEYSTORE_PASSPHRASE is
    // set, exercised directly (no global env mutation).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ks.mvks");
    {
        let ks = memvault_api::keystore_open::open_encrypted(&path, b"correct horse").unwrap();
        ks.put(b"adminkey:1", b"super-secret-seed").unwrap();
    }
    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(17).any(|w| w == b"super-secret-seed"),
        "seed leaked to disk under encryption"
    );
    let ks = memvault_api::keystore_open::open_encrypted(&path, b"correct horse").unwrap();
    assert_eq!(ks.get(b"adminkey:1").as_deref(), Some(&b"super-secret-seed"[..]));
}

// ---------------------------------------------------------------------------
// Keystore-backed tokens (issue / list / consume / revoke, cross-process)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_lifecycle_through_keystore_is_cross_process() {
    use memvault_api::MemvaultClient;
    let dir = tempfile::tempdir().unwrap();

    // Issuer (e.g. the daemon): keystore auto-opened beside its store.
    let issuer = bare_client(&dir, b"issuer");
    issuer.set_admin_signing_key(memvault_api::ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]));

    let _tok = issuer
        .issue_token(memvault_auth::TokenRole::Agent(memvault_auth::AgentRole::AgentHost), 3600, 2, Some("k".into()))
        .await
        .unwrap();

    let listed = issuer.list_tokens().await.unwrap();
    assert_eq!(listed.len(), 1, "token visible via keystore");
    let cid = listed[0].cid.clone();
    assert_eq!(listed[0].consumed_count, 0);
    assert!(!listed[0].revoked);

    // A SECOND process (e.g. memctl): own redb, shared keystore.
    let other = bare_client(&dir, b"memctl");
    assert_eq!(other.list_tokens().await.unwrap().len(), 1, "cross-process list");

    // Consume from the issuer; the other process observes the count.
    assert_eq!(issuer.record_token_consumption(&cid, b"agent-x", 1), 1);
    assert_eq!(other.token_consumption_count(&cid), 1, "cross-process count");

    // Revoke from the second process; the issuer observes it.
    other.revoke_token(&cid, "compromised").await.unwrap();
    assert!(issuer.token_is_revoked(&cid), "cross-process revocation");
    let after = issuer.list_tokens().await.unwrap();
    assert!(after[0].revoked);
}

// ---------------------------------------------------------------------------
// Live upgrade: legacy loose identity files migrate into the keystore
// ---------------------------------------------------------------------------

#[test]
fn legacy_identity_files_migrate_to_keystore() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    std::fs::create_dir_all(&identity).unwrap();

    // Lay down the pre-keystore on-disk layout an existing genesis node had:
    // admin.key (raw seed), cluster_admin_genesis.cbor (signed), cluster_id.
    let seed = [77u8; 32];
    let admin_sk = memvault_api::ed25519_dalek::SigningKey::from_bytes(&seed);
    let admin_pubkey = admin_sk.verifying_key().to_bytes();
    let cluster = memvault_core::ClusterId([3u8; 32]);
    let genesis = memvault_auth::sign_admin_genesis(&admin_sk, cluster.clone(), 1_000)
        .expect("sign genesis");
    std::fs::write(identity.join("admin.key"), seed).unwrap();
    std::fs::write(
        identity.join("cluster_admin_genesis.cbor"),
        serde_ipld_dagcbor::to_vec(&genesis).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.path().join("cluster_id"), hex::encode(cluster.0)).unwrap();

    // Boot a client over that data dir and run the one-time upgrade.
    let c = bare_client(&dir, b"upgrade");
    c.migrate_legacy_identity_files(&identity);

    // Files are gone…
    assert!(!identity.join("admin.key").exists(), "admin.key removed");
    assert!(
        !identity.join("cluster_admin_genesis.cbor").exists(),
        "genesis.cbor removed"
    );
    assert!(!dir.path().join("cluster_id").exists(), "cluster_id file removed");

    // …and the values now live in the keystore / store.
    assert_eq!(c.load_admin_keys_from_keystore(), 1, "admin key in keystore");
    assert!(c.admin_verifying_keys().iter().any(|k| k.to_bytes() == admin_pubkey));
    let pinned = c
        .pinned_admin_genesis_bytes_from_keystore()
        .expect("genesis in keystore");
    let decoded: memvault_auth::AdminGenesis =
        serde_ipld_dagcbor::from_slice(&pinned).unwrap();
    assert_eq!(decoded.admin_pubkey, admin_pubkey);
    assert_eq!(
        c.store().get_local_cluster_id().unwrap().as_deref(),
        Some(&cluster.0[..]),
        "cluster_id migrated to store"
    );

    // Idempotent: a second run with no files is a no-op.
    c.migrate_legacy_identity_files(&identity);
}

#[test]
fn admitted_admin_key_activates_live_from_keystore() {
    // Models the co-admin path: a secret lands in the keystore (written by
    // another process / the join thread), and when the admin-key state is
    // rebuilt to include its pubkey, set_admin_key_state loads it live.
    let dir = tempfile::tempdir().unwrap();
    let c = bare_client(&dir, b"coadmin");

    let seed = [55u8; 32];
    let sk = memvault_api::ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey = sk.verifying_key().to_bytes();

    // Secret present in the keystore but NOT yet held in memory.
    c.keystore()
        .put(format!("adminkey:{}", hex::encode(pubkey)).as_bytes(), &seed)
        .unwrap();
    assert!(
        !c.admin_verifying_keys().iter().any(|k| k.to_bytes() == pubkey),
        "not held before the state names it"
    );

    // The admission lands → admin-key state rebuilt to include the pubkey.
    let state = memvault_auth::AdminKeyState::new_with_bootstrap(pubkey, 0);
    c.set_admin_key_state(state);

    // Now it's activated live (held in memory) without a reload/restart.
    assert!(
        c.admin_verifying_keys().iter().any(|k| k.to_bytes() == pubkey),
        "admitted admin key activated from keystore"
    );
}

// ---------------------------------------------------------------------------
// Genesis: identity in the keystore yields tokens that embed the AdminGenesis
// ---------------------------------------------------------------------------

fn client_with_cluster(dir: &tempfile::TempDir, name: &[u8], cluster: &[u8; 32]) -> Arc<LocalClient> {
    let redb_name = format!("redb-{}", String::from_utf8_lossy(name));
    let store = Arc::new(MemvaultStore::open(dir.path().join(redb_name)).unwrap());
    let quotas = Arc::new(RwLock::new(QuotaManager::default()));
    let event_bus = Arc::new(EventBus::new(64));
    let mut peer_id = [0u8; 32];
    peer_id[..name.len().min(32)].copy_from_slice(&name[..name.len().min(32)]);
    Arc::new(LocalClient::new(
        store,
        quotas,
        event_bus,
        peer_id.to_vec(),
        cluster.to_vec(),
    ))
}

#[tokio::test]
async fn genesis_identity_yields_tokens_embedding_genesis() {
    use memvault_api::MemvaultClient;
    let dir = tempfile::tempdir().unwrap();
    let cluster = [7u8; 32];

    // Genesis: generate the admin key + self-signed genesis and persist both
    // into the keystore (what `memctl genesis` now does, no loose files).
    let admin_sk = memvault_api::ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let admin_pubkey = admin_sk.verifying_key().to_bytes();
    let genesis = memvault_auth::sign_admin_genesis(
        &admin_sk,
        memvault_core::ClusterId(cluster),
        1_234,
    )
    .expect("sign genesis");
    {
        let a = client_with_cluster(&dir, b"genesis", &cluster);
        a.set_admin_signing_key(admin_sk.clone());
        a.set_pinned_admin_genesis(genesis.clone());
    }

    // A separate keystore-only issuer (own redb, shared keystore) loads the
    // genesis identity and issues a token — which must embed the AdminGenesis
    // so a joining node can pin cluster trust.
    let issuer = client_with_cluster(&dir, b"issuer", &cluster);
    assert_eq!(issuer.load_admin_keys_from_keystore(), 1, "admin key from keystore");
    let pin = issuer
        .pinned_admin_genesis_bytes_from_keystore()
        .expect("genesis in keystore");
    issuer.set_pinned_admin_genesis(serde_ipld_dagcbor::from_slice(&pin).unwrap());

    let token_str = issuer
        .issue_token(memvault_auth::TokenRole::Agent(memvault_auth::AgentRole::AgentHost), 3600, 1, None)
        .await
        .unwrap();
    let decoded = memvault_auth::decode_token_string(&token_str).unwrap();
    let embedded = decoded.admin_genesis.expect("token embeds AdminGenesis");
    assert_eq!(embedded.admin_pubkey, admin_pubkey, "genesis admin matches");
    embedded.verify_self_signature().expect("embedded genesis self-signature");
    assert_eq!(decoded.cluster_id.0, cluster, "token cluster matches");
}

// ── Scoped queries (scoped-indexes) ────────────────────────────────

#[tokio::test]
async fn scoped_list_spans_multiple_buckets() {
    use memvault_core::QueryScope;

    let (_dir, client) = make_client();

    // Three buckets.
    let mut ids = Vec::new();
    for name in ["alpha", "beta", "gamma"] {
        ids.push(
            client
                .bucket_create(
                    name,
                    None,
                    Visibility::Internal,
                    memvault_core::classification::Classification::Internal,
                    BucketRole::Standard,
                )
                .await
                .unwrap(),
        );
    }

    // One doc per bucket.
    for (i, b) in ids.iter().enumerate() {
        let doc = Document::new(
            DocId::random(),
            format!("shared note {i}"),
            BTreeMap::new(),
        );
        client
            .put_doc(doc, vec![], Visibility::Internal, Some(b))
            .await
            .unwrap();
    }

    // All accessible buckets → 3.
    let all = client
        .list_scoped(&QueryScope::all(), 100)
        .await
        .unwrap();
    assert_eq!(all.len(), 3, "all buckets");

    // Two of three explicitly → 2 (the multi-bucket agent case).
    let scope = QueryScope::all().with_buckets(vec![ids[0].clone(), ids[2].clone()]);
    let two = client.list_scoped(&scope, 100).await.unwrap();
    assert_eq!(two.len(), 2, "two-bucket union");

    // Single bucket → 1.
    let one = client
        .list_scoped(&QueryScope::all().with_bucket(Some(ids[1].clone())), 100)
        .await
        .unwrap();
    assert_eq!(one.len(), 1, "single bucket");

    // Empty explicit set → 0.
    let none = client
        .list_scoped(&QueryScope::all().with_buckets(vec![]), 100)
        .await
        .unwrap();
    assert_eq!(none.len(), 0, "empty bucket set");
}

#[tokio::test]
async fn scoped_search_respects_bucket_set() {
    use memvault_core::QueryScope;

    let (_dir, client) = make_client();
    let a = client
        .bucket_create(
            "a",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    let b = client
        .bucket_create(
            "b",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    client
        .put_doc(
            Document::new(DocId::random(), "kubernetes guide".into(), BTreeMap::new()),
            vec![],
            Visibility::Internal,
            Some(&a),
        )
        .await
        .unwrap();
    client
        .put_doc(
            Document::new(DocId::random(), "kubernetes notes".into(), BTreeMap::new()),
            vec![],
            Visibility::Internal,
            Some(&b),
        )
        .await
        .unwrap();

    let all = client
        .search_scoped(&QueryScope::all(), "kubernetes", 50)
        .await
        .unwrap();
    assert_eq!(all.len(), 2);

    let just_a = client
        .search_scoped(
            &QueryScope::all().with_bucket(Some(a.clone())),
            "kubernetes",
            50,
        )
        .await
        .unwrap();
    assert_eq!(just_a.len(), 1);
}

#[tokio::test]
async fn scoped_retraction_modes_and_count() {
    use memvault_core::{QueryScope, RetractionMode};

    let (_dir, client) = make_client();
    let bucket = client
        .bucket_create(
            "vault",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    let keep = DocId::random();
    let drop = DocId::random();
    client
        .put_doc(
            Document::new(keep.clone(), "keep me".into(), BTreeMap::new()),
            vec![],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();
    client
        .put_doc(
            Document::new(drop.clone(), "drop me".into(), BTreeMap::new()),
            vec![],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();

    let drop_node = format!("doc:{}", hex::encode(drop.0));
    client.retract_node(&drop_node, "test").await.unwrap();

    let scope = QueryScope::all().with_bucket(Some(bucket.clone()));

    // Active only → 1 (keep).
    let active = client.list_scoped(&scope, 100).await.unwrap();
    assert_eq!(active.len(), 1);
    assert!(active.iter().all(|n| !n.retracted));

    // Include retracted → 2.
    let incl = client
        .list_scoped(&scope.clone().with_retraction(RetractionMode::IncludeRetracted), 100)
        .await
        .unwrap();
    assert_eq!(incl.len(), 2);
    assert_eq!(incl.iter().filter(|n| n.retracted).count(), 1);

    // Retracted only → 1 (drop), and it still resolves its label.
    let only = client
        .list_scoped(&scope.clone().with_retraction(RetractionMode::RetractedOnly), 100)
        .await
        .unwrap();
    assert_eq!(only.len(), 1);
    assert!(only[0].retracted);

    // Counts.
    let c = client.count_scoped(&scope.clone().with_retraction(RetractionMode::IncludeRetracted)).await.unwrap();
    assert_eq!(c.active, 1);
    assert_eq!(c.retracted, 1);
    assert_eq!(c.total(), 2);
}

#[tokio::test]
async fn scoped_view_bucket_partition_counts() {
    use memvault_core::{BucketId, QueryScope};
    use memvault_api::View;

    let (_dir, client) = make_client();
    let bucket = client
        .bucket_create(
            "proj",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    // A view requiring tag ("kind","note").
    client
        .create_view(View {
            name: "notes".into(),
            tags: vec![("kind".into(), "note".into())],
            created_ns: 1,
            cid: String::new(),
            bucket_id: None,
        })
        .await
        .unwrap();

    // Two docs match the view, one doesn't.
    for (body, tag_match) in [("note one", true), ("note two", true), ("other", false)] {
        let tags = if tag_match {
            vec![("kind".into(), "note".into())]
        } else {
            vec![("kind".into(), "memo".into())]
        };
        client
            .put_doc(
                Document::new(DocId::random(), body.into(), BTreeMap::new()),
                tags,
                Visibility::Internal,
                Some(&bucket),
            )
            .await
            .unwrap();
    }

    let scope = QueryScope::all()
        .with_view(Some("notes".into()))
        .with_bucket(Some(bucket.clone()));

    let listed = client.list_scoped(&scope, 100).await.unwrap();
    assert_eq!(listed.len(), 2, "only view members in bucket");

    // count_scoped lazily builds the view×bucket partition; should be 2 active.
    let c = client.count_scoped(&scope).await.unwrap();
    assert_eq!(c.active, 2);
    assert_eq!(c.retracted, 0);

    // A later matching doc is maintained into the (now-registered) partition.
    client
        .put_doc(
            Document::new(DocId::random(), "note three".into(), BTreeMap::new()),
            vec![("kind".into(), "note".into())],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();
    let c2 = client.count_scoped(&scope).await.unwrap();
    assert_eq!(c2.active, 3, "live maintenance added the new note");

    // sanity: a bucket id that isn't accessible contributes nothing.
    let bogus = QueryScope::all()
        .with_view(Some("notes".into()))
        .with_bucket(Some(BucketId([99u8; 32])));
    let c3 = client.count_scoped(&bogus).await.unwrap();
    assert_eq!(c3.total(), 0);
}

#[tokio::test]
async fn scoped_list_filters_by_node_kind() {
    use memvault_core::{NodeKind, QueryScope};

    let (_dir, client) = make_client();
    let bucket = client
        .bucket_create(
            "mixed",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    // A doc, an entity, and a file in the same bucket.
    client
        .put_doc(
            Document::new(DocId::random(), "a document".into(), BTreeMap::new()),
            vec![],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();
    client
        .add_entity(
            Entity {
                id: EntityId::random(),
                kind: "person".to_string(),
                props: BTreeMap::new(),
                edges_out: vec![],
            },
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();
    client
        .upload_file(b"hello", Some("f.txt"), "text/plain", vec![], "internal", Some(&bucket))
        .await
        .unwrap();

    let base = QueryScope::all().with_bucket(Some(bucket.clone()));

    let all = client.list_scoped(&base, 100).await.unwrap();
    assert_eq!(all.len(), 3, "all kinds");

    let docs = client
        .list_scoped(&base.clone().with_kind(Some(NodeKind::Document)), 100)
        .await
        .unwrap();
    assert_eq!(docs.len(), 1);
    assert!(docs.iter().all(|n| n.node_type == "doc"));

    let files = client
        .list_scoped(&base.clone().with_kind(Some(NodeKind::File)), 100)
        .await
        .unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].node_type, "file");

    let entities = client
        .list_scoped(&base.clone().with_kind(Some(NodeKind::GraphEntity)), 100)
        .await
        .unwrap();
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].node_type, "entity");

    // Count honours the kind filter.
    let c = client
        .count_scoped(&base.with_kind(Some(NodeKind::Document)))
        .await
        .unwrap();
    assert_eq!(c.active, 1);
}

#[tokio::test]
async fn scoped_list_detail_level_enriches_entries() {
    use memvault_core::{DetailLevel, NodeKind, QueryScope};

    let (_dir, client) = make_client();
    let bucket = client
        .bucket_create(
            "vault",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    let mut fm = BTreeMap::new();
    fm.insert("title".to_string(), serde_json::json!("Titled Doc"));
    client
        .put_doc(
            Document::new(DocId::random(), "body".into(), fm),
            vec![],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();
    client
        .add_entity(
            Entity {
                id: EntityId::random(),
                kind: "person".to_string(),
                props: {
                    let mut p = BTreeMap::new();
                    p.insert("name".to_string(), serde_json::json!("Ada"));
                    p
                },
                edges_out: vec![],
            },
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();

    let base = QueryScope::all().with_bucket(Some(bucket.clone()));

    // Summary: no detail populated.
    let summary = client.list_scoped(&base, 100).await.unwrap();
    assert!(summary.iter().all(|n| n.detail.is_none()));

    // Full + kind=Document: doc entry carries Doc detail with a non-zero mtime.
    let docs = client
        .list_scoped(
            &base
                .clone()
                .with_kind(Some(NodeKind::Document))
                .with_detail(DetailLevel::Full),
            100,
        )
        .await
        .unwrap();
    assert_eq!(docs.len(), 1);
    match docs[0].detail.as_ref().expect("doc detail populated") {
        memvault_api::NodeDetail::Doc { updated_ns, .. } => assert!(*updated_ns > 0),
        other => panic!("expected Doc detail, got {other:?}"),
    }

    // Full + kind=GraphEntity: entity entry carries Entity detail (kind+props).
    let ents = client
        .list_scoped(
            &base
                .clone()
                .with_kind(Some(NodeKind::GraphEntity))
                .with_detail(DetailLevel::Full),
            100,
        )
        .await
        .unwrap();
    assert_eq!(ents.len(), 1);
    match ents[0].detail.as_ref().expect("entity detail populated") {
        memvault_api::NodeDetail::Entity { entity_kind, props } => {
            assert_eq!(entity_kind, "person");
            assert_eq!(props.get("name"), Some(&serde_json::json!("Ada")));
        }
        other => panic!("expected Entity detail, got {other:?}"),
    }
}

#[tokio::test]
async fn scoped_search_finds_bucketed_doc() {
    // A doc created in a bucket must be searchable under Accessible scope and
    // under its own bucket (this is the path the web search page exercises).
    use memvault_core::QueryScope;

    let (_dir, client) = make_client();
    let bucket = client
        .bucket_create(
            "b",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    client
        .put_doc(
            Document::new(DocId::random(), "findme zebra".into(), BTreeMap::new()),
            vec![],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .unwrap();

    // Accessible scope.
    let hits = client
        .search_scoped(&QueryScope::all(), "zebra", 10)
        .await
        .unwrap();
    assert!(
        hits.iter().any(|h| h.node_type == "doc"),
        "bucketed doc must be searchable under Accessible scope"
    );

    // Scoped to its own bucket.
    let scoped = client
        .search_scoped(
            &QueryScope::all().with_bucket(Some(bucket.clone())),
            "zebra",
            10,
        )
        .await
        .unwrap();
    assert!(
        scoped.iter().any(|h| h.node_type == "doc"),
        "doc must be searchable when scoped to its bucket"
    );
}

/// A block that arrives via RBSR sync (or external seeding) — i.e. through
/// `reindex_block`, not an inline-indexing `put_doc` — must still become
/// searchable. The store's index notifier queues it; the next search flushes
/// the queue and indexes it. Regression: synced docs used to land in redb
/// (counts/graph updated) but never reached the Tantivy index, so search and
/// the scoped table view stayed empty.
#[tokio::test]
async fn synced_block_becomes_searchable() {
    let (_dir_a, client_a) = make_client();
    let (_dir_b, client_b) = make_client();

    // Node B bridges synced/seeded blocks into its full-text index.
    client_b.install_sigchain_notifier();

    // Create a doc on A (inline-indexed there only).
    let doc_id = DocId::random();
    let mut fm = BTreeMap::new();
    fm.insert("title".to_string(), serde_json::json!("Synced Note"));
    let doc = Document::new(
        doc_id.clone(),
        "quantum entanglement teleportation".to_string(),
        fm,
    );
    let cid = client_a
        .put_doc(
            doc,
            vec![("ns".into(), "test".into())],
            Visibility::Internal,
            None,
        )
        .await
        .unwrap();

    // B hasn't seen it yet.
    assert!(
        client_b.search("quantum", 10).await.unwrap().is_empty(),
        "node B should not find the doc before sync"
    );

    // Simulate RBSR sync: copy the raw block, then reindex (fires the notifier).
    let block = client_a.store().get_block(&cid).unwrap().unwrap();
    client_b.store().put_block(&cid, &block).unwrap();
    assert!(
        client_b.store().reindex_block(&cid, &block).unwrap(),
        "reindex_block should recognize the envelope"
    );

    // The next search flushes the reindex queue → the synced doc is found.
    let hits = client_b.search("quantum", 10).await.unwrap();
    assert!(
        !hits.is_empty(),
        "synced doc must be searchable on node B after reindex_block"
    );
    assert_eq!(hits[0].doc_id, doc_id, "search must return the synced doc");
}

/// With deferred (batched) index commits enabled, a live write isn't committed
/// inline — but the read path (`search` calls `flush_index`) still lands it, so
/// the doc is searchable. Guards the async-commit mode used by long-running
/// hosts (daemon / web server) via `set_defer_index_commits`.
#[tokio::test]
async fn deferred_commit_is_searchable_after_read() {
    let (_dir, client) = make_client();
    client.set_defer_index_commits(true);

    let doc_id = DocId::random();
    let mut fm = BTreeMap::new();
    fm.insert("title".to_string(), serde_json::json!("Deferred"));
    let doc = Document::new(doc_id.clone(), "holographic interferometry".to_string(), fm);
    client
        .put_doc(doc, vec![], Visibility::Internal, None)
        .await
        .unwrap();

    // The deferred write is flushed by the read path.
    let hits = client.search("holographic", 10).await.unwrap();
    assert!(
        hits.iter().any(|h| h.doc_id == doc_id),
        "deferred write must be searchable after a read flushes it"
    );
}
