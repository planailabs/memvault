//! Integration tests for the memvault-web API.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use memvault_api::{EventBus, MemvaultClient, NodeStatus, RotationInfo, TokenStatus, TraversalHit};
use memvault_core::{DocId, EdgeId, EntityId, Visibility};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit};
use memvault_auth::Role;

use crate::{build_router, AppState};

const TEST_TOKEN: &str = "test-secret-token";

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
    ) -> memvault_api::Result<Vec<memvault_api::DocSummary>> {
        let guard = self.doc.read().await;
        if let Some(doc) = guard.as_ref() {
            Ok(vec![memvault_api::DocSummary {
                id: doc.id.clone(),
                cid: doc.id.0.to_vec(),
                title: doc.frontmatter.get("title").and_then(|v| v.as_str()).map(String::from),
                tags: vec![],
                updated_ns: 1000,
                attachment_count: 0,
            }])
        } else {
            Ok(vec![])
        }
    }

    async fn attach_file(
        &self,
        _data: &[u8],
        _filename: Option<&str>,
        _mime_type: &str,
        _tags: Vec<(String, String)>,
        _visibility: &str,
    ) -> memvault_api::Result<Vec<u8>> {
        Ok(vec![0xAB; 32])
    }

    async fn read_attachment(&self, _manifest_cid: &[u8]) -> memvault_api::Result<Vec<u8>> {
        Ok(b"file-content-here".to_vec())
    }

    async fn read_attachment_range(&self, _manifest_cid: &[u8], _start: u64, _end: u64) -> memvault_api::Result<Vec<u8>> {
        Ok(b"range-data".to_vec())
    }

    async fn read_extracted_text(&self, _manifest_cid: &[u8]) -> memvault_api::Result<Option<String>> {
        Ok(Some("extracted text".to_string()))
    }

    async fn pin_attachment(&self, _manifest_cid: &[u8]) -> memvault_api::Result<()> {
        Ok(())
    }

    async fn unpin_attachment(&self, _manifest_cid: &[u8]) -> memvault_api::Result<()> {
        Ok(())
    }

    async fn list_pinned(&self) -> memvault_api::Result<Vec<(Vec<u8>, String)>> {
        Ok(vec![])
    }

    async fn get_attachment_manifest(&self, _manifest_cid: &[u8]) -> memvault_api::Result<Option<Vec<u8>>> {
        Ok(Some(b"{}".to_vec()))
    }

    async fn add_entity(
        &self,
        _entity: Entity,
        _vis: Visibility,
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

    async fn list_entities(&self, _limit: usize) -> memvault_api::Result<Vec<Entity>> {
        Ok(vec![])
    }

    async fn entity_history(&self, _id: &EntityId) -> memvault_api::Result<Vec<memvault_query::AuditRecord>> {
        Ok(vec![])
    }

    async fn add_edge(
        &self,
        _source: &EntityId,
        _edge: Edge,
        _vis: Visibility,
    ) -> memvault_api::Result<EdgeId> {
        Ok(EdgeId::random())
    }

    async fn remove_edge(
        &self,
        _source: &EntityId,
        _edge_id: &EdgeId,
    ) -> memvault_api::Result<()> {
        Ok(())
    }

    async fn traverse(
        &self,
        _from: &EntityId,
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

    async fn history_of(&self, _doc_id: &DocId) -> memvault_api::Result<Vec<AuditRecord>> {
        Ok(vec![])
    }

    async fn audit(&self, _query: AuditQuery) -> memvault_api::Result<Vec<AuditRecord>> {
        Ok(vec![])
    }

    async fn retract(&self, _target_cid: &[u8], _reason: &str) -> memvault_api::Result<Vec<u8>> {
        Ok(vec![0u8; 32])
    }

    async fn issue_token(
        &self,
        _role: Role,
        _ttl_secs: u64,
        _max_uses: u32,
        _label: Option<String>,
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
}

fn make_app() -> axum::Router {
    let state = Arc::new(AppState {
        client: Arc::new(MockClient::new()),
        event_bus: Arc::new(EventBus::new(16)),
        auth_token: TEST_TOKEN.to_string(),
        metrics: Arc::new(memvault_api::metrics::Metrics::new()),
    });
    build_router(state)
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

#[tokio::test]
async fn test_create_and_list_docs() {
    let state = Arc::new(AppState {
        client: Arc::new(MockClient::new()),
        event_bus: Arc::new(EventBus::new(16)),
        auth_token: TEST_TOKEN.to_string(),
        metrics: Arc::new(memvault_api::metrics::Metrics::new()),
    });
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
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
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
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
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
async fn test_get_doc() {
    let state = Arc::new(AppState {
        client: Arc::new(MockClient::new()),
        event_bus: Arc::new(EventBus::new(16)),
        auth_token: TEST_TOKEN.to_string(),
        metrics: Arc::new(memvault_api::metrics::Metrics::new()),
    });
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
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
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
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
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
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
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
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
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
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"file-content-here");
}
