//! Integration tests for the memvault-web API.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use memvault_api::{EventBus, MemvaultClient, NodeStatus, RotationInfo, TokenStatus, TraversalHit};
use memvault_auth::node_attestation::{AttestationOrigin, NodeAttestation};
use memvault_auth::{AgentRole, TokenRole};
use memvault_core::{ClusterId, DocId, EdgeId, EntityId, NodeRef, PeerId, Visibility};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::{AppState, build_router};

/// Deterministic test admin + node + agent keys.
/// In the chain model: admin signs the node's NodeAttestation, node
/// signs the agent's AgentAttestation, agent signs the JWT.
fn test_keys() -> (SigningKey, SigningKey, SigningKey) {
    (
        SigningKey::from_bytes(&[0xAAu8; 32]), // admin
        SigningKey::from_bytes(&[0xBBu8; 32]), // node
        SigningKey::from_bytes(&[0xCCu8; 32]), // agent
    )
}

/// Build an admin-signed node attestation.
fn test_node_attestation(admin: &SigningKey, node: &SigningKey) -> NodeAttestation {
    let mut att = NodeAttestation {
        cluster_id: ClusterId([0u8; 32]),
        member: PeerId(node.verifying_key().as_bytes().to_vec()),
        not_after_ns: u64::MAX,
        issued_via: AttestationOrigin::Direct,
        signature: [0u8; 64],
    };
    let signing_bytes = att.signing_bytes().unwrap();
    att.signature = admin.sign(&signing_bytes).to_bytes();
    att
}

/// Admin's verifying key for AppState.
fn test_admin_pubkey() -> VerifyingKey {
    test_keys().0.verifying_key()
}

/// node_trust map for AppState — one Attested entry for the test node.
fn test_node_trust() -> std::sync::Arc<
    std::sync::RwLock<std::collections::HashMap<[u8; 32], memvault_auth::jwt::NodeTrust>>,
> {
    let (admin, node, _) = test_keys();
    let mut map = std::collections::HashMap::new();
    map.insert(
        node.verifying_key().to_bytes(),
        memvault_auth::jwt::NodeTrust::Attested(test_node_attestation(&admin, &node)),
    );
    std::sync::Arc::new(std::sync::RwLock::new(map))
}

/// A valid JWT for the test agent, all scopes, 1h TTL.
fn test_jwt() -> String {
    let (_admin, node, agent) = test_keys();
    let agent_att = memvault_auth::sign_agent_attestation(
        &node,
        memvault_core::AgentName("test-agent".to_string()),
        agent.verifying_key().to_bytes(),
        AgentRole::AgentHost,
        u64::MAX,
    )
    .unwrap();
    let _ = agent_att; // attestation now lives only in the sigchain; the
    // JWT carries just the agent_id label in `iss`.
    memvault_auth::jwt::issue(&agent, "test-agent", "read write admin", 3600).unwrap()
}

/// Mock client that returns canned responses.
struct MockClient {
    doc: tokio::sync::RwLock<Option<Document>>,
}

impl MockClient {
    fn new() -> Self {
        Self {
            doc: tokio::sync::RwLock::new(None),
        }
    }
}

#[async_trait]
impl MemvaultClient for MockClient {
    async fn put_doc(
        &self,
        doc: Document,
        _tags: Vec<(String, String)>,
        _vis: Visibility,
        _bucket: Option<&memvault_core::BucketId>,
    ) -> memvault_api::Result<Vec<u8>> {
        let id = doc.id.0;
        *self.doc.write().await = Some(doc);
        Ok(id.to_vec())
    }

    async fn get_doc(&self, _id: &DocId) -> memvault_api::Result<Option<Document>> {
        Ok(self.doc.read().await.clone())
    }

    async fn edit_doc(&self, _id: &DocId, _patch: TextPatch) -> memvault_api::Result<Vec<u8>> {
        Ok(vec![0u8; 32])
    }

    async fn list_docs(
        &self,
        _tag_filter: Option<(String, String)>,
        _limit: usize,
        _bucket: Option<&memvault_core::BucketId>,
    ) -> memvault_api::Result<Vec<memvault_api::DocSummary>> {
        let guard = self.doc.read().await;
        if let Some(doc) = guard.as_ref() {
            Ok(vec![memvault_api::DocSummary {
                id: doc.id.clone(),
                // DocSummary.cid is a real CID on the wire (cid_str encoding),
                // so the mock must emit valid CID bytes, not raw id bytes.
                cid: memvault_core::cid_from_bytes(&doc.id.0).to_bytes(),
                title: doc
                    .frontmatter
                    .get("title")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                tags: vec![],
                updated_ns: 1000,
                attachment_count: 0,
            }])
        } else {
            Ok(vec![])
        }
    }

    async fn upload_file(
        &self,
        _data: &[u8],
        _filename: Option<&str>,
        _mime_type: &str,
        _tags: Vec<(String, String)>,
        _visibility: &str,
        _bucket: Option<&memvault_core::BucketId>,
    ) -> memvault_api::Result<Vec<u8>> {
        Ok(vec![0xAB; 32])
    }

    async fn read_file(&self, _manifest_cid: &[u8]) -> memvault_api::Result<Vec<u8>> {
        Ok(b"file-content-here".to_vec())
    }

    async fn read_file_range(
        &self,
        _manifest_cid: &[u8],
        _start: u64,
        _end: u64,
    ) -> memvault_api::Result<Vec<u8>> {
        Ok(b"range-data".to_vec())
    }

    async fn read_extracted_text(
        &self,
        _manifest_cid: &[u8],
    ) -> memvault_api::Result<Option<String>> {
        Ok(Some("extracted text".to_string()))
    }

    async fn pin_file(&self, _manifest_cid: &[u8]) -> memvault_api::Result<()> {
        Ok(())
    }

    async fn unpin_file(&self, _manifest_cid: &[u8]) -> memvault_api::Result<()> {
        Ok(())
    }

    async fn list_pinned(&self) -> memvault_api::Result<Vec<(Vec<u8>, String)>> {
        Ok(vec![])
    }

    async fn get_file_manifest(
        &self,
        _manifest_cid: &[u8],
    ) -> memvault_api::Result<Option<Vec<u8>>> {
        Ok(Some(b"{}".to_vec()))
    }

    async fn add_entity_internal(
        &self,
        _entity: Entity,
        _vis: Visibility,
        _bucket: Option<&memvault_core::BucketId>,
    ) -> memvault_api::Result<EntityId> {
        Ok(EntityId::random())
    }

    async fn get_entity(&self, id: &EntityId) -> memvault_api::Result<Option<Entity>> {
        Ok(Some(Entity {
            id: id.clone(),
            kind: "person".into(),
            props: BTreeMap::new(),
            edges_out: vec![],
        }))
    }

    async fn list_entities(
        &self,
        _limit: usize,
        _bucket: Option<&memvault_core::BucketId>,
    ) -> memvault_api::Result<Vec<Entity>> {
        Ok(vec![])
    }

    async fn entity_history(
        &self,
        _id: &EntityId,
    ) -> memvault_api::Result<Vec<memvault_query::AuditRecord>> {
        Ok(vec![])
    }

    async fn add_link(
        &self,
        _source: &NodeRef,
        _edge: Edge,
        _vis: Visibility,
    ) -> memvault_api::Result<EdgeId> {
        Ok(EdgeId::random())
    }

    async fn remove_link_from(
        &self,
        _source: &NodeRef,
        _edge_id: &EdgeId,
    ) -> memvault_api::Result<()> {
        Ok(())
    }

    async fn edges_of(&self, _node: &NodeRef) -> memvault_api::Result<Vec<(NodeRef, Edge)>> {
        Ok(vec![])
    }

    async fn traverse_from(
        &self,
        _from: &NodeRef,
        _relation: Option<&str>,
        _max_depth: usize,
    ) -> memvault_api::Result<Vec<TraversalHit>> {
        Ok(vec![])
    }

    async fn search(&self, query: &str, _limit: usize) -> memvault_api::Result<Vec<SearchHit>> {
        if query == "hello" {
            Ok(vec![SearchHit {
                doc_id: DocId::random(),
                score: 1.0,
                snippet: "hello world".into(),
            }])
        } else {
            Ok(vec![])
        }
    }

    async fn search_unified(
        &self,
        query: &str,
        _limit: usize,
    ) -> memvault_api::Result<Vec<memvault_query::UnifiedHit>> {
        if query == "hello" {
            Ok(vec![memvault_query::UnifiedHit {
                node_id: format!("doc:{}", hex::encode(DocId::random().0)),
                node_type: "doc".into(),
                label: "hello world".into(),
                score: 1.0,
                snippet: "hello world".into(),
                match_contexts: vec![],
            }])
        } else {
            Ok(vec![])
        }
    }

    async fn resolve_label(&self, _node_id: &str) -> memvault_api::Result<Option<String>> {
        Ok(None)
    }

    async fn list_views(&self) -> memvault_api::Result<Vec<memvault_api::View>> {
        Ok(vec![])
    }
    async fn create_view(&self, _view: memvault_api::View) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn update_view(&self, _view: memvault_api::View) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn view_members(&self, _name: &str) -> memvault_api::Result<Vec<String>> {
        Ok(vec![])
    }
    async fn add_tags(
        &self,
        _node_id: &str,
        _tags: Vec<(String, String)>,
    ) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn remove_tags(
        &self,
        _node_id: &str,
        _tags: Vec<(String, String)>,
    ) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn get_tags(&self, _node_id: &str) -> memvault_api::Result<Vec<(String, String)>> {
        Ok(vec![])
    }
    async fn retract_node_internal(&self, _node_id: &str, _reason: &str) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn list_all(
        &self,
        _view: Option<&str>,
        _limit: usize,
        _bucket: Option<&memvault_core::BucketId>,
    ) -> memvault_api::Result<Vec<(String, String, String, Vec<(String, String)>)>> {
        Ok(vec![])
    }
    async fn delete_view(&self, _name: &str) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn get_view(&self, _name: &str) -> memvault_api::Result<Option<memvault_api::View>> {
        Ok(None)
    }

    async fn history_of(&self, _doc_id: &DocId) -> memvault_api::Result<Vec<AuditRecord>> {
        Ok(vec![])
    }

    async fn audit(&self, _query: AuditQuery) -> memvault_api::Result<Vec<AuditRecord>> {
        Ok(vec![])
    }

    async fn retract(&self, _target_cid: &[u8], _reason: &str) -> memvault_api::Result<Vec<u8>> {
        Ok(vec![0u8; 32])
    }

    async fn issue_token_ex(
        &self,
        _role: TokenRole,
        _ttl_secs: u64,
        _max_uses: u32,
        _label: Option<String>,
        _issuer_addrs: Vec<String>,
    ) -> memvault_api::Result<String> {
        Ok("token-abc123".into())
    }

    async fn list_tokens(&self) -> memvault_api::Result<Vec<TokenStatus>> {
        Ok(vec![])
    }

    async fn revoke_token(&self, _token_cid: &[u8], _reason: &str) -> memvault_api::Result<()> {
        Ok(())
    }

    async fn list_rotations(&self) -> memvault_api::Result<Vec<RotationInfo>> {
        Ok(vec![])
    }

    async fn status(&self) -> memvault_api::Result<NodeStatus> {
        Ok(NodeStatus {
            peer_id: vec![1; 32],
            cluster_id: vec![2; 32],
            block_count: 42,
            doc_count: 10,
            peer_count: 3,
            uptime_secs: 3600,
        })
    }

    async fn bucket_create(
        &self,
        _name: &str,
        _description: Option<&str>,
        _vis: memvault_core::Visibility,
        _class: memvault_core::classification::Classification,
        _role: memvault_doc::BucketRole,
    ) -> memvault_api::Result<memvault_core::BucketId> {
        Ok(memvault_core::BucketId([0u8; 32]))
    }
    async fn bucket_list(&self) -> memvault_api::Result<Vec<memvault_api::types::BucketInfo>> {
        Ok(vec![])
    }
    async fn bucket_get(
        &self,
        _id: &memvault_core::BucketId,
    ) -> memvault_api::Result<Option<memvault_api::types::BucketInfo>> {
        Ok(None)
    }
    async fn bucket_rename(
        &self,
        _id: &memvault_core::BucketId,
        _name: &str,
    ) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn skill_rename(
        &self,
        _id: &memvault_core::EntityId,
        _new_name: &str,
    ) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn agent_rename(
        &self,
        _agent_pubkey: &[u8; 32],
        _new_label: &str,
    ) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn bucket_bind(
        &self,
        _bucket: &memvault_core::BucketId,
        _cluster: &memvault_core::ClusterId,
    ) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn bucket_attach(&self, _id: &memvault_core::BucketId) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn bucket_archive(
        &self,
        _id: &memvault_core::BucketId,
        _reason: &str,
    ) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn share_inbox(&self) -> memvault_api::Result<Vec<Vec<u8>>> {
        Ok(vec![])
    }
    async fn share_outbox(&self) -> memvault_api::Result<Vec<Vec<u8>>> {
        Ok(vec![])
    }
    async fn share_get_proposal(
        &self,
        _proposal_cid: &[u8],
    ) -> memvault_api::Result<Option<memvault_api::ShareProposalInfo>> {
        Ok(None)
    }
    async fn share_decide(
        &self,
        _cid: &[u8],
        _approve: bool,
        _reason: Option<&str>,
    ) -> memvault_api::Result<()> {
        Ok(())
    }
    async fn bucket_grants_list(
        &self,
        _bucket_id: &memvault_core::BucketId,
    ) -> memvault_api::Result<Vec<memvault_api::GrantInfo>> {
        Ok(vec![])
    }

    async fn legacy_bucket_id(&self) -> memvault_api::Result<memvault_core::BucketId> {
        Ok(memvault_core::BucketId([0u8; 32]))
    }

    async fn ensure_agent_bucket(
        &self,
        _agent_id: &str,
    ) -> memvault_api::Result<memvault_core::BucketId> {
        Ok(memvault_core::BucketId([0u8; 32]))
    }
    async fn ensure_agent_bucket_for_pubkey(
        &self,
        _agent_pubkey: &[u8],
        _name_hint: &str,
    ) -> memvault_api::Result<memvault_core::BucketId> {
        Ok(memvault_core::BucketId([0u8; 32]))
    }

    async fn bucket_grant(
        &self,
        _bucket_id: &memvault_core::BucketId,
        _audience: memvault_auth::GrantAudience,
        _actions: Vec<memvault_auth::Action>,
        _ttl_secs: u64,
    ) -> memvault_api::Result<Vec<u8>> {
        Ok(vec![0u8; 32])
    }

    async fn revoke_grant(
        &self,
        _grant_cid: &[u8],
        _reason: &str,
    ) -> memvault_api::Result<Vec<u8>> {
        Ok(vec![0u8; 32])
    }
}

/// Build the test agent's AgentAttestation. The JWT verifier calls our
/// injected lookup with the agent pubkey; we just return this attestation
/// when it matches.
fn test_agent_attestation() -> memvault_auth::AgentAttestation {
    let (_admin, node, agent) = test_keys();
    memvault_auth::sign_agent_attestation(
        &node,
        memvault_core::AgentName("test-agent".to_string()),
        agent.verifying_key().to_bytes(),
        AgentRole::AgentHost,
        u64::MAX,
    )
    .expect("sign_agent_attestation")
}

/// Stub agent-attestation lookup. Returns the test agent's attestation
/// when asked about its pubkey; anything else gets `None`. Lets tests
/// run without a full `LocalClient` installed.
fn test_agent_lookup()
-> Arc<dyn Fn(&[u8; 32]) -> Option<memvault_auth::AgentAttestation> + Send + Sync> {
    let att = test_agent_attestation();
    Arc::new(move |agent_pk: &[u8; 32]| {
        if *agent_pk == att.agent_pubkey {
            Some(att.clone())
        } else {
            None
        }
    })
}

/// Point the lazily-initialized global `LocalClient` (used by ACL helpers
/// like `enforce_doc_action` / `filter_readable`) at a throwaway temp redb,
/// set once per test process. Without this the helpers open the *real*
/// `~/.local/share/memvault/blocks.redb`, which (a) lock-conflicts with a
/// running daemon and (b) makes results depend on machine state — the source
/// of flaky 500s. Hermetic temp DB = deterministic tests.
fn ensure_test_env() {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("memvault-web-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        // SAFETY: set once, at the start of the test process, before any
        // server function triggers the global client's lazy init.
        unsafe {
            std::env::set_var("MEMVAULT_DATA_DIR", &dir);
            std::env::set_var("MEMVAULT_DB", dir.join("blocks.redb"));
        }
    });
}

fn test_app_state(client: Arc<dyn MemvaultClient>) -> Arc<AppState> {
    test_app_state_with(client, Vec::new())
}

fn test_app_state_with(
    client: Arc<dyn MemvaultClient>,
    allowed_origins: Vec<String>,
) -> Arc<AppState> {
    ensure_test_env();
    Arc::new(AppState {
        client,
        event_bus: Arc::new(EventBus::new(16)),
        admin_pubkey: Some(test_admin_pubkey()),
        node_trust: test_node_trust(),
        revoked_agents: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        revoked_nodes: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        metrics: Arc::new(memvault_api::metrics::Metrics::new()),
        agent_attestation_lookup: Some(test_agent_lookup()),
        allowed_origins,
    })
}

fn make_app() -> axum::Router {
    build_router(test_app_state(Arc::new(MockClient::new())))
}

#[tokio::test]
async fn test_unauthorized_without_token() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/docs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_unauthorized_with_bad_token() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/docs")
                .header("authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// The 5 tests below were broken in cd0bd54b ("drop JWT attestation
// embed + HTTP agent enrollment"), which moved verify_bearer from
// looking up agent attestations on the AppState client to requiring a
// concrete LocalClient via `ui::state::local_client()`. They are now
// fixed by routing the lookup through `AppState.agent_attestation_lookup`
// when set, so tests can install a stub without a full LocalClient.

#[tokio::test]
async fn test_create_and_list_docs() {
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);

    // Create a doc
    let create_body = serde_json::json!({
        "body": "Hello, world!",
        "tags": [["ns", "val"]],
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/docs")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["body"], "Hello, world!");
    assert!(!doc["id"].as_str().unwrap().is_empty());

    // List docs
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/docs")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let docs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(docs.len(), 1);
}

#[tokio::test]
async fn test_skill_publish_and_list_routes() {
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);

    // Publish a skill: the route is wired, authorized, and returns an
    // "entity:<hex>" id (the publish path threads through the client).
    let create_body = serde_json::json!({
        "name": "Code Review",
        "description": "Review a diff",
        "instruction_body": "# Code Review\nRun the linter.",
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/skills")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        v["id"].as_str().unwrap().starts_with("entity:"),
        "publish returns an entity id, got {:?}",
        v["id"]
    );

    // List skills: route exists and is authorized (200 with a JSON array).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/skills")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let _skills: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    // Unauthorized access is rejected.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/skills")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_reserved_kind_rejected_on_generic_entity_create() {
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);

    // Managed kinds can't be created through the generic /entities API — it
    // routes through the validated client add_entity (skills/VFS have their
    // own endpoints).
    for kind in ["skill", "vfs:dir"] {
        let body = serde_json::json!({ "kind": kind });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/entities")
                    .header("authorization", format!("Bearer {}", test_jwt()))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "kind {kind:?} must be rejected by the generic entity API"
        );
    }

    // An ordinary kind still creates fine.
    let body = serde_json::json!({ "kind": "person" });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/entities")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}


#[tokio::test]
async fn test_get_doc() {
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);

    // Create a doc first
    let create_body = serde_json::json!({
        "body": "Test doc body",
        "tags": [],
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/docs")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let doc_id = created["id"].as_str().unwrap();

    // Get doc by ID
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/docs/{doc_id}"))
                .header("authorization", format!("Bearer {}", test_jwt()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["body"], "Test doc body");
}

#[tokio::test]
async fn test_search() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/search?q=hello&limit=10")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let hits: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["snippet"], "hello world");
}

#[tokio::test]
async fn test_admin_status() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/status")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["block_count"], 42);
    assert_eq!(status["doc_count"], 10);
    assert_eq!(status["peer_count"], 3);
    assert_eq!(status["uptime_secs"], 3600);
}

#[tokio::test]
async fn test_download_attachment() {
    let app = make_app();
    let cid_hex = hex::encode([0xABu8; 32]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/attachments/{cid_hex}"))
                .header("authorization", format!("Bearer {}", test_jwt()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"file-content-here");
}

// ── Session cookie + CSRF guard ─────────────────────────────────────────
//
// Browser-style auth: the web UI hits the API with the `memvault_session`
// cookie instead of `Authorization: Bearer …`, and state-changing requests
// must carry a matching `Origin` header so cross-origin pages can't ride the
// cookie. Bearer-only clients (memctl, curl) keep working because they don't
// set Origin or the cookie.

#[tokio::test]
async fn test_session_cookie_authorizes_reads() {
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/docs")
                .header(
                    "cookie",
                    format!("{}={}", crate::api::auth::SESSION_COOKIE, test_jwt()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_session_cookie_with_matching_origin_authorizes_writes() {
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);
    let body = serde_json::json!({ "body": "via cookie", "tags": [] });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/docs")
                .header(
                    "cookie",
                    format!("{}={}", crate::api::auth::SESSION_COOKIE, test_jwt()),
                )
                .header("host", "memvault.local:8401")
                .header("origin", "http://memvault.local:8401")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_csrf_blocks_cross_origin_cookie_write() {
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);
    let body = serde_json::json!({ "body": "csrf attempt", "tags": [] });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/docs")
                .header(
                    "cookie",
                    format!("{}={}", crate::api::auth::SESSION_COOKIE, test_jwt()),
                )
                .header("host", "memvault.local:8401")
                .header("origin", "https://evil.example.com")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_csrf_blocks_cookie_write_without_origin() {
    // No Origin header AND a session cookie present → CSRF-shaped; reject.
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);
    let body = serde_json::json!({ "body": "no-origin", "tags": [] });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/docs")
                .header(
                    "cookie",
                    format!("{}={}", crate::api::auth::SESSION_COOKIE, test_jwt()),
                )
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_bearer_writes_without_origin_still_pass() {
    // memctl / curl callers: no cookie, no Origin — must keep working.
    let state = test_app_state(Arc::new(MockClient::new()));
    let app = build_router(state);
    let body = serde_json::json!({ "body": "from cli", "tags": [] });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/docs")
                .header("authorization", format!("Bearer {}", test_jwt()))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_allowed_origins_list_admits_proxy_host() {
    // Reverse-proxy case: the browser sees the proxy URL as the Origin
    // but `Host` (as seen by the daemon) is `127.0.0.1:8401`. Same-origin
    // would refuse; the explicit allow-list admits it.
    let state = test_app_state_with(
        Arc::new(MockClient::new()),
        vec!["https://memvault.example.com".into()],
    );
    let app = build_router(state);
    let body = serde_json::json!({ "body": "via proxy", "tags": [] });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/docs")
                .header(
                    "cookie",
                    format!("{}={}", crate::api::auth::SESSION_COOKIE, test_jwt()),
                )
                .header("host", "127.0.0.1:8401")
                .header("origin", "https://memvault.example.com")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}
