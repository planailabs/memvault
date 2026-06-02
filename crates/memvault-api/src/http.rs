//! HTTP client implementing MemvaultClient — talks to the daemon's REST API.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use memvault_auth::TokenRole;
use memvault_core::{BucketId, DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit};

use crate::agent_identity::AgentIdentity;
use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};
use crate::types::{
    BucketInfo, DocSummary, GrantInfo, NodeStatus, RotationInfo, ShareProposalInfo, TokenStatus,
    TraversalHit, View,
};

/// JWT TTL for auto-issued tokens. 1h is plenty for typical CLI/MCP sessions
/// and bounds the blast radius if a token is stolen.
const TOKEN_TTL_SECS: u64 = 3600;
/// Renew this many seconds before expiry — gives in-flight requests headroom.
const TOKEN_RENEW_SLACK_SECS: u64 = 60;

/// Wrapper around `reqwest::Client` that injects a freshly-issued JWT bearer
/// header on every outgoing request. Holds an [`AgentIdentity`] (cheap-to-clone
/// `Arc`) and issues a JWT signed with the agent's private key whenever the
/// cached one is within [`TOKEN_RENEW_SLACK_SECS`] of expiry.
///
/// Existing call sites can keep using `client.get(url)` / `client.post(url)`
/// etc. — they now return a [`reqwest::RequestBuilder`] with the bearer set.
struct AuthClient {
    inner: reqwest::Client,
    identity: Option<Arc<AgentIdentity>>,
    cached: Mutex<Option<(String, u64)>>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl AuthClient {
    fn new(identity: Option<Arc<AgentIdentity>>) -> std::result::Result<Self, anyhow::Error> {
        Ok(Self {
            inner: reqwest::Client::builder().build()?,
            identity,
            cached: Mutex::new(None),
        })
    }

    /// Get a valid bearer token, regenerating if cached one is near expiry.
    /// `None` if no identity is configured (unauthenticated client).
    fn bearer(&self) -> Option<String> {
        let id = self.identity.as_ref()?;
        let now = now_secs();
        let mut cache = self.cached.lock().ok()?;
        if let Some((tok, exp)) = cache.as_ref() {
            if *exp > now + TOKEN_RENEW_SLACK_SECS {
                return Some(tok.clone());
            }
        }
        let tok = id.issue_jwt("read write admin", TOKEN_TTL_SECS).ok()?;
        *cache = Some((tok.clone(), now + TOKEN_TTL_SECS));
        Some(tok)
    }

    fn with_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.bearer() {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    pub fn get(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.with_auth(self.inner.get(url))
    }
    pub fn post(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.with_auth(self.inner.post(url))
    }
    pub fn put(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.with_auth(self.inner.put(url))
    }
    pub fn delete(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.with_auth(self.inner.delete(url))
    }
    pub fn patch(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.with_auth(self.inner.patch(url))
    }
}

/// HTTP client that implements MemvaultClient by talking to the daemon's REST API.
pub struct HttpApiClient {
    client: AuthClient,
    base_url: String,
}

impl HttpApiClient {
    /// Construct an HTTP client that authenticates with JWTs issued from the
    /// given agent identity. Pass `None` for an unauthenticated client (will
    /// only succeed against endpoints that don't require auth).
    ///
    /// JWTs are auto-renewed before expiry — long-lived sessions stay valid.
    pub fn new(
        base_url: &str,
        identity: Option<Arc<AgentIdentity>>,
    ) -> std::result::Result<Self, anyhow::Error> {
        Ok(Self {
            client: AuthClient::new(identity)?,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.base_url)
    }
}

fn urlencoded(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => write!(out, "%{b:02X}").unwrap(),
        }
    }
    out
}

fn map_reqwest(e: reqwest::Error) -> ApiError {
    ApiError::Other(e.to_string())
}

/// Canonical CID-string path segment for a CID byte slice (falls back to hex
/// for any non-CID bytes). The server accepts both forms; we emit the
/// canonical one. See `standards/api-wire-conventions.md` §1b.
fn cid_path(cid: &[u8]) -> String {
    memvault_core::cid_string_from_bytes(cid).unwrap_or_else(|_| hex::encode(cid))
}

/// Decode a hex string into a fixed 32-byte array, if well-formed.
fn hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Reconstruct an [`AuditRecord`] from the server's `/audit` and
/// `/docs/{id}/history` JSON (hex-encoded byte fields; `op_kind` in canonical
/// snake_case serde form). Fields absent on a given endpoint default to empty.
fn parse_audit_record(v: &serde_json::Value) -> AuditRecord {
    // CID-valued fields are CID strings; key/opaque-id fields are hex.
    let hexvec = |key: &str| v[key].as_str().and_then(|s| hex::decode(s).ok());
    let cidvec = |key: &str| v[key].as_str().and_then(|s| memvault_core::cid_bytes_lenient(s).ok());
    AuditRecord {
        cid: cidvec("cid").unwrap_or_default(),
        op_kind: v
            .get("op_kind")
            .and_then(|x| serde_json::from_value(x.clone()).ok())
            .unwrap_or(memvault_query::OpKind::DocCreate),
        author: hexvec("author").unwrap_or_default(),
        agent_attestation: cidvec("agent_attestation"),
        wall_ns: v["wall_ns"].as_u64().unwrap_or(0),
        doc_id: v["doc_id"].as_str().and_then(hex32).map(DocId),
        entity_id: hexvec("entity_id"),
        attachment_cid: cidvec("attachment_cid"),
        tags: v
            .get("tags")
            .and_then(|t| serde_json::from_value(t.clone()).ok())
            .unwrap_or_default(),
    }
}

#[async_trait]
impl MemvaultClient for HttpApiClient {
    // -- Documents --

    async fn put_doc(
        &self,
        doc: Document,
        tags: Vec<(String, String)>,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        let mut body = serde_json::json!({
            "body": doc.body,
            "frontmatter": doc.frontmatter,
            "tags": tags,
            "visibility": format!("{vis:?}").to_lowercase(),
        });
        if let Some(b) = bucket {
            body["bucket"] = serde_json::Value::String(hex::encode(b.0));
        }
        let resp: serde_json::Value = self
            .client
            .post(self.url("/docs"))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let cid_hex = resp["cid"].as_str().unwrap_or("");
        Ok(hex::decode(cid_hex).unwrap_or_default())
    }

    async fn get_doc(&self, id: &DocId) -> Result<Option<Document>> {
        let id_hex = hex::encode(id.0);
        let resp = self
            .client
            .get(self.url(&format!("/docs/{id_hex}")))
            .send()
            .await
            .map_err(map_reqwest)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let val: serde_json::Value = resp
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let body = val["body"].as_str().unwrap_or("").to_string();
        let frontmatter: BTreeMap<String, serde_json::Value> = val
            .get("frontmatter")
            .and_then(|f| serde_json::from_value(f.clone()).ok())
            .unwrap_or_default();
        Ok(Some(Document {
            id: id.clone(),
            body,
            frontmatter,
        }))
    }

    async fn edit_doc(&self, id: &DocId, patch: TextPatch) -> Result<Vec<u8>> {
        let id_hex = hex::encode(id.0);
        let resp: serde_json::Value = self
            .client
            .put(self.url(&format!("/docs/{id_hex}")))
            .json(&serde_json::json!({ "patch": patch }))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let cid_hex = resp["cid"].as_str().unwrap_or("");
        Ok(hex::decode(cid_hex).unwrap_or_default())
    }

    async fn list_docs(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        _bucket: Option<&BucketId>,
    ) -> Result<Vec<DocSummary>> {
        let mut url = format!("{}?limit={limit}", self.url("/docs"));
        if let Some((scope, label)) = &tag_filter {
            url.push_str(&format!(
                "&tag_ns={}&tag_val={}",
                urlencoded(scope),
                urlencoded(label)
            ));
        }
        // `DocSummary` decodes directly (hex id, CID-string cid; see
        // `standards/`). The old hand-parse decoded `id` as bare hex while the
        // server sent a `doc:<hex>` label, silently dropping every row.
        let docs = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(docs)
    }

    // -- Files --

    async fn upload_file(
        &self,
        data: &[u8],
        filename: Option<&str>,
        mime_type: &str,
        _tags: Vec<(String, String)>,
        _visibility: &str,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        let fname = filename.unwrap_or("unnamed");
        let part = reqwest::multipart::Part::bytes(data.to_vec())
            .file_name(fname.to_string())
            .mime_str(mime_type)
            .map_err(|e| ApiError::Other(e.to_string()))?;
        let form = reqwest::multipart::Form::new().part("file", part);
        let mut url = self.url("/files");
        if let Some(b) = bucket {
            url.push_str(&format!("?bucket={}", hex::encode(b.0)));
        }
        let resp: serde_json::Value = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // `cid` is the canonical manifest CID string (accepts a "file:" label
        // or bare hex too, for resilience).
        let raw = resp["cid"].as_str().unwrap_or_default();
        let raw = raw.rsplit(':').next().unwrap_or(raw);
        Ok(memvault_core::cid_bytes_lenient(raw).unwrap_or_default())
    }

    async fn read_file(&self, manifest_cid: &[u8]) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(self.url(&format!("/files/{}", cid_path(manifest_cid))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(resp.bytes().await.map_err(map_reqwest)?.to_vec())
    }

    async fn read_file_range(&self, manifest_cid: &[u8], start: u64, end: u64) -> Result<Vec<u8>> {
        let data = self.read_file(manifest_cid).await?;
        let s = start as usize;
        let e = (end as usize).min(data.len());
        Ok(if s < data.len() {
            data[s..e].to_vec()
        } else {
            vec![]
        })
    }

    async fn read_extracted_text(&self, manifest_cid: &[u8]) -> Result<Option<String>> {
        let resp: serde_json::Value = self
            .client
            .get(self.url(&format!("/files/{}/extracted-text", cid_path(manifest_cid))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(resp["text"].as_str().map(|s| s.to_string()))
    }

    async fn pin_file(&self, manifest_cid: &[u8]) -> Result<()> {
        self.client
            .post(self.url(&format!("/files/{}/pin", cid_path(manifest_cid))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }
    async fn unpin_file(&self, manifest_cid: &[u8]) -> Result<()> {
        self.client
            .delete(self.url(&format!("/files/{}/pin", cid_path(manifest_cid))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }
    async fn list_pinned(&self) -> Result<Vec<(Vec<u8>, String)>> {
        let resp: serde_json::Value = self
            .client
            .get(self.url("/pins"))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let pins = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let cid = memvault_core::cid_bytes_lenient(v["cid"].as_str()?).ok()?;
                        Some((cid, v["name"].as_str().unwrap_or_default().to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(pins)
    }

    async fn get_file_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>> {
        let resp = self
            .client
            .get(self.url(&format!("/files/{}/manifest", cid_path(manifest_cid))))
            .send()
            .await
            .map_err(map_reqwest)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let val: serde_json::Value = resp
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(Some(serde_json::to_vec(&val).unwrap_or_default()))
    }

    // -- Graph --

    async fn add_entity(
        &self,
        entity: Entity,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId> {
        let mut body = serde_json::json!({
            "kind": entity.kind,
            "props": entity.props,
            "visibility": format!("{vis:?}").to_lowercase(),
        });
        if let Some(b) = bucket {
            body["bucket"] = serde_json::Value::String(hex::encode(b.0));
        }
        let resp: serde_json::Value = self
            .client
            .post(self.url("/entities"))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // The server returns the node label "entity:<hex>" (not bare hex), so
        // decode via NodeRef rather than hex-decoding the whole string — the
        // old `hex::decode("entity:…")` always failed and silently yielded a
        // zero EntityId, which is what made `vfs_mkdir`/`resolve("/")` report
        // entity:000…000.
        let id_str = resp["id"].as_str().unwrap_or_default();
        match NodeRef::from_tag_label(id_str) {
            Some(NodeRef::Entity(eid)) => Ok(eid),
            _ => Err(ApiError::Other(format!(
                "create entity: server returned unexpected id {id_str:?}"
            ))),
        }
    }

    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>> {
        let id_hex = hex::encode(id.0);
        let node_id = format!("entity:{id_hex}");
        let resp = self
            .client
            .get(self.url(&format!("/nodes/{}", urlencoded(&node_id))))
            .send()
            .await
            .map_err(map_reqwest)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let val: serde_json::Value = resp
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let kind = val["kind"].as_str().unwrap_or("").to_string();
        let props: BTreeMap<String, serde_json::Value> = val
            .get("props")
            .and_then(|p| serde_json::from_value(p.clone()).ok())
            .unwrap_or_default();
        Ok(Some(Entity {
            id: id.clone(),
            kind,
            props,
            edges_out: vec![],
        }))
    }

    async fn list_entities(&self, limit: usize, bucket: Option<&BucketId>) -> Result<Vec<Entity>> {
        let mut url = format!("{}?limit={limit}", self.url("/entities"));
        if let Some(b) = bucket {
            url.push_str(&format!("&bucket={}", hex::encode(b.0)));
        }
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // Server shape (graph::EntityResponse): [{ id: "entity:<hex>", kind, props, edges }]
        let entities = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let id = match NodeRef::from_tag_label(v["id"].as_str()?)? {
                            NodeRef::Entity(eid) => eid,
                            _ => return None,
                        };
                        Some(Entity {
                            id,
                            kind: v["kind"].as_str().unwrap_or("").to_string(),
                            props: v
                                .get("props")
                                .and_then(|p| serde_json::from_value(p.clone()).ok())
                                .unwrap_or_default(),
                            edges_out: vec![],
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(entities)
    }

    async fn entity_history(&self, _id: &EntityId) -> Result<Vec<AuditRecord>> {
        Ok(vec![])
    }

    // -- Links --

    async fn add_link(&self, source: &NodeRef, edge: Edge, vis: Visibility) -> Result<EdgeId> {
        let body = serde_json::json!({
            "source": source.tag_label(),
            "target": edge.target.tag_label(),
            "relation": edge.relation,
            "weight": edge.weight,
            "props": edge.props,
            "visibility": format!("{vis:?}").to_lowercase(),
        });
        let resp: serde_json::Value = self
            .client
            .post(self.url("/links"))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let edge_hex = resp["edge_id"].as_str().unwrap_or_default();
        let bytes = hex::decode(edge_hex)
            .map_err(|e| ApiError::Other(format!("create link: bad edge_id {edge_hex:?}: {e}")))?;
        if bytes.len() != 32 {
            return Err(ApiError::Other(format!(
                "create link: edge_id must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(EdgeId(arr))
    }

    async fn remove_link_from(&self, source: &NodeRef, edge_id: &EdgeId) -> Result<()> {
        let url = format!(
            "{}?source={}",
            self.url(&format!("/links/{}", hex::encode(edge_id.0))),
            urlencoded(&source.tag_label())
        );
        self.client
            .delete(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    async fn edges_of(&self, node: &NodeRef) -> Result<Vec<(NodeRef, Edge)>> {
        let node_id = node.tag_label();
        let url = format!("{}?node={}", self.url("/links"), urlencoded(&node_id));
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // Server shape (links::LinkResponse):
        //   [{ edge_id, source, target, relation, weight, props }]
        let edges = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let source = NodeRef::from_tag_label(v["source"].as_str()?)?;
                        let target = NodeRef::from_tag_label(v["target"].as_str()?)?;
                        let edge_bytes = hex::decode(v["edge_id"].as_str()?).ok()?;
                        if edge_bytes.len() != 32 {
                            return None;
                        }
                        let mut eid = [0u8; 32];
                        eid.copy_from_slice(&edge_bytes);
                        let props = v
                            .get("props")
                            .and_then(|p| serde_json::from_value(p.clone()).ok())
                            .unwrap_or_default();
                        let edge = Edge {
                            id: EdgeId(eid),
                            relation: v["relation"].as_str().unwrap_or_default().to_string(),
                            target,
                            weight: v.get("weight").and_then(|w| w.as_f64()).map(|w| w as f32),
                            props,
                            provenance: None,
                        };
                        Some((source, edge))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(edges)
    }

    async fn traverse_from(
        &self,
        from: &NodeRef,
        relation: Option<&str>,
        max_depth: usize,
    ) -> Result<Vec<TraversalHit>> {
        let mut url = format!(
            "{}?from={}&max_depth={max_depth}",
            self.url("/traverse"),
            urlencoded(&from.tag_label())
        );
        if let Some(rel) = relation {
            url.push_str(&format!("&relation={}", urlencoded(rel)));
        }
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // Server shape: [{ node: "<label>", depth, path: [[edge_hex, relation], ...] }]
        let hits = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let node = NodeRef::from_tag_label(v["node"].as_str()?)?;
                        let path = v["path"]
                            .as_array()
                            .map(|p| {
                                p.iter()
                                    .filter_map(|step| {
                                        let s = step.as_array()?;
                                        let eid = hex32(s.first()?.as_str()?).map(EdgeId)?;
                                        let rel = s.get(1)?.as_str()?.to_string();
                                        Some((eid, rel))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        Some(TraversalHit {
                            node,
                            depth: v["depth"].as_u64().unwrap_or(0) as usize,
                            path,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(hits)
    }

    // -- Tags --

    async fn add_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.client
            .put(self.url(&format!("/tags/{}", urlencoded(node_id))))
            .json(&serde_json::json!({ "tags": tags }))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    async fn remove_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.client
            .delete(self.url(&format!("/tags/{}", urlencoded(node_id))))
            .json(&serde_json::json!({ "tags": tags }))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    async fn get_tags(&self, node_id: &str) -> Result<Vec<(String, String)>> {
        let resp: serde_json::Value = self
            .client
            .get(self.url(&format!("/tags/{}", urlencoded(node_id))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // Server shape (views::get_tags): { node_id, tags: [[scope, label], ...] }.
        // Accept a bare array too for resilience.
        let arr = resp
            .get("tags")
            .and_then(|t| t.as_array())
            .or_else(|| resp.as_array());
        let tags = arr
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let a = v.as_array()?;
                        Some((
                            a.first()?.as_str()?.to_string(),
                            a.get(1)?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(tags)
    }

    // -- Views --

    async fn list_views(&self) -> Result<Vec<View>> {
        // `View` is serde-clean (no byte-newtype fields), so decode directly.
        let views = self
            .client
            .get(self.url("/views"))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(views)
    }
    async fn create_view(&self, view: View) -> Result<()> {
        self.client
            .post(self.url("/views"))
            .json(&serde_json::json!({ "name": view.name, "tags": view.tags }))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }
    async fn delete_view(&self, name: &str) -> Result<()> {
        self.client
            .delete(self.url(&format!("/views/{}", urlencoded(name))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }
    async fn get_view(&self, name: &str) -> Result<Option<View>> {
        let resp = self
            .client
            .get(self.url(&format!("/views/{}", urlencoded(name))))
            .send()
            .await
            .map_err(map_reqwest)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let view = resp
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(Some(view))
    }
    async fn update_view(&self, view: View) -> Result<()> {
        self.client
            .put(self.url(&format!("/views/{}", urlencoded(&view.name))))
            .json(&serde_json::json!({ "name": view.name, "tags": view.tags }))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    // -- Search --

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let url = format!(
            "{}?q={}&limit={limit}",
            self.url("/search"),
            urlencoded(query)
        );
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // Server shape (search::SearchHitResponse): [{ doc_id, score, snippet }]
        // where doc_id is bare hex.
        let hits = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let doc_id = hex32(v["doc_id"].as_str()?).map(DocId)?;
                        Some(SearchHit {
                            doc_id,
                            score: v["score"].as_f64().unwrap_or(0.0) as f32,
                            snippet: v["snippet"].as_str().unwrap_or_default().to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(hits)
    }

    async fn search_unified(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>> {
        // The server's /search endpoint is doc-only; surface those hits as
        // UnifiedHit so this is not a silent empty stub.
        let url = format!(
            "{}?q={}&limit={limit}",
            self.url("/search"),
            urlencoded(query)
        );
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let hits = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let doc_hex = v["doc_id"].as_str()?;
                        Some(memvault_query::UnifiedHit {
                            node_id: format!("doc:{doc_hex}"),
                            node_type: "doc".to_string(),
                            label: String::new(),
                            score: v["score"].as_f64().unwrap_or(0.0) as f32,
                            snippet: v["snippet"].as_str().unwrap_or_default().to_string(),
                            match_contexts: vec![],
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(hits)
    }

    async fn list_all(
        &self,
        view_name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, String, String, Vec<(String, String)>)>> {
        let mut url = format!("{}?limit={limit}", self.url("/nodes"));
        if let Some(v) = view_name {
            url.push_str(&format!("&view={}", urlencoded(v)));
        }
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // The /nodes handler returns `{count, nodes: [...]}` (not a bare
        // array). Fall back to a bare array for any older / alternate
        // handler shape so this works against both.
        let nodes_array = resp
            .get("nodes")
            .and_then(|v| v.as_array())
            .or_else(|| resp.as_array());
        let nodes = nodes_array
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let node_id = v["node_id"].as_str()?.to_string();
                        // /nodes handler emits `node_type`; older shape used
                        // `type`. Accept either.
                        let node_type = v
                            .get("node_type")
                            .and_then(|x| x.as_str())
                            .or_else(|| v.get("type").and_then(|x| x.as_str()))
                            .unwrap_or("")
                            .to_string();
                        let label = v["label"].as_str().unwrap_or("").to_string();
                        let tags: Vec<(String, String)> = v
                            .get("tags")
                            .and_then(|t| t.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|t| {
                                        let a = t.as_array()?;
                                        Some((
                                            a.first()?.as_str()?.to_string(),
                                            a.get(1)?.as_str()?.to_string(),
                                        ))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        Some((node_id, node_type, label, tags))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(nodes)
    }

    async fn view_members(&self, view_name: &str) -> Result<Vec<String>> {
        let resp: serde_json::Value = self
            .client
            .get(self.url(&format!("/views/{}/members", urlencoded(view_name))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // Server shape: { view, count, members: [node_id, ...] }
        let members = resp
            .get("members")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(members)
    }
    async fn resolve_label(&self, _node_id: &str) -> Result<Option<String>> {
        Ok(None)
    }

    // -- History & Audit --

    async fn history_of(&self, doc_id: &DocId) -> Result<Vec<AuditRecord>> {
        let id_hex = hex::encode(doc_id.0);
        let resp: serde_json::Value = self
            .client
            .get(self.url(&format!("/docs/{id_hex}/history")))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let recs = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| {
                        // history rows omit doc_id; stamp the queried one back in.
                        let mut rec = parse_audit_record(v);
                        if rec.doc_id.is_none() {
                            rec.doc_id = Some(doc_id.clone());
                        }
                        rec
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(recs)
    }

    async fn audit(&self, query: AuditQuery) -> Result<Vec<AuditRecord>> {
        let mut params: Vec<String> = Vec::new();
        if let Some(d) = &query.doc_id {
            params.push(format!("doc_id={}", hex::encode(d.0)));
        }
        if let Some(a) = &query.author {
            params.push(format!("author={}", hex::encode(a)));
        }
        if let Some(k) = &query.op_kind {
            if let Some(s) = serde_json::to_value(k).ok().and_then(|v| v.as_str().map(String::from)) {
                params.push(format!("op_kind={s}"));
            }
        }
        if let Some(n) = query.after_ns {
            params.push(format!("after_ns={n}"));
        }
        if let Some(n) = query.before_ns {
            params.push(format!("before_ns={n}"));
        }
        if let Some(n) = query.limit {
            params.push(format!("limit={n}"));
        }
        let url = if params.is_empty() {
            self.url("/audit")
        } else {
            format!("{}?{}", self.url("/audit"), params.join("&"))
        };
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let recs = resp
            .as_array()
            .map(|arr| arr.iter().map(parse_audit_record).collect())
            .unwrap_or_default();
        Ok(recs)
    }

    async fn retract(&self, target_cid: &[u8], _reason: &str) -> Result<Vec<u8>> {
        let cid_hex = hex::encode(target_cid);
        self.client
            .delete(self.url(&format!("/docs/{cid_hex}")))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(vec![])
    }

    async fn retract_node(&self, node_id: &str, _reason: &str) -> Result<()> {
        self.client
            .delete(self.url(&format!("/nodes/{}", urlencoded(node_id))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    // -- Tokens --

    async fn issue_token_ex(
        &self,
        role: TokenRole,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
        issuer_addrs: Vec<String>,
    ) -> Result<String> {
        let body = serde_json::json!({
            "role": role,
            "ttl_secs": ttl_secs,
            "max_uses": max_uses,
            "label": label,
            "issuer_addrs": issuer_addrs,
        });
        let resp: serde_json::Value = self
            .client
            .post(self.url("/tokens"))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        resp["token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ApiError::Other("missing token in response".into()))
    }

    async fn list_tokens(&self) -> Result<Vec<TokenStatus>> {
        // TokenStatus decodes directly (hex/CID wire encoding; see standards/).
        // Route is /admin/tokens (the old /tokens path 404'd).
        let resp = self
            .client
            .get(self.url("/admin/tokens"))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(resp)
    }

    async fn revoke_token(&self, token_cid: &[u8], reason: &str) -> Result<()> {
        let body = serde_json::json!({ "reason": reason });
        self.client
            .delete(self.url(&format!("/tokens/{}", hex::encode(token_cid))))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    // -- Buckets --

    async fn bucket_create(
        &self,
        name: &str,
        description: Option<&str>,
        default_visibility: memvault_core::Visibility,
        default_classification: memvault_core::classification::Classification,
        role: memvault_doc::BucketRole,
    ) -> Result<memvault_core::BucketId> {
        let body = serde_json::json!({
            "name": name,
            "description": description,
            "default_visibility": default_visibility,
            "default_classification": default_classification,
            "role": role,
        });
        let resp: serde_json::Value = self
            .client
            .post(self.url("/buckets"))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        // Server returns the id as a hex string (CreateBucketResponse), not a
        // byte array.
        let arr = resp["id"]
            .as_str()
            .and_then(hex32)
            .ok_or_else(|| ApiError::Other("create bucket: missing/invalid id".into()))?;
        Ok(memvault_core::BucketId(arr))
    }

    async fn bucket_list(&self) -> Result<Vec<BucketInfo>> {
        // `BucketInfo` decodes directly (hex-id wire shape, see `standards/`).
        let buckets = self
            .client
            .get(self.url("/buckets"))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(buckets)
    }

    async fn bucket_get(&self, id: &memvault_core::BucketId) -> Result<Option<BucketInfo>> {
        let resp = self
            .client
            .get(self.url(&format!("/buckets/{}", hex::encode(id.0))))
            .send()
            .await
            .map_err(map_reqwest)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        // `BucketInfo` decodes directly (hex-id wire shape, see `standards/`).
        let info = resp
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(Some(info))
    }

    async fn bucket_rename(&self, id: &memvault_core::BucketId, new_name: &str) -> Result<()> {
        let body = serde_json::json!({ "name": new_name });
        self.client
            .patch(self.url(&format!("/buckets/{}", hex::encode(id.0))))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    async fn bucket_bind(
        &self,
        bucket_id: &memvault_core::BucketId,
        cluster_id: &memvault_core::ClusterId,
    ) -> Result<()> {
        let body = serde_json::json!({
            "cluster_id": cluster_id.0,
        });
        self.client
            .post(self.url(&format!("/buckets/{}/bind", hex::encode(bucket_id.0))))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    async fn bucket_grants_list(&self, bucket_id: &BucketId) -> Result<Vec<GrantInfo>> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/buckets/{}/grants",
                hex::encode(bucket_id.0)
            )))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        resp.json::<Vec<GrantInfo>>().await.map_err(map_reqwest)
    }

    async fn revoke_grant(&self, grant_cid: &[u8], reason: &str) -> Result<Vec<u8>> {
        #[derive(serde::Deserialize)]
        struct Resp {
            revocation_cid: String,
        }
        let body = serde_json::json!({ "reason": reason });
        let resp = self
            .client
            .post(self.url(&format!(
                "/grants/{}/revoke",
                hex::encode(grant_cid)
            )))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        let parsed: Resp = resp.json().await.map_err(map_reqwest)?;
        hex::decode(parsed.revocation_cid)
            .map_err(|e| ApiError::Other(format!("decode revocation_cid: {e}")))
    }

    async fn bucket_grant(
        &self,
        bucket_id: &BucketId,
        audience: memvault_auth::GrantAudience,
        actions: Vec<memvault_auth::Action>,
        ttl_secs: u64,
    ) -> Result<Vec<u8>> {
        let audience_json = match audience {
            memvault_auth::GrantAudience::Cluster(c) => serde_json::json!({
                "kind": "cluster",
                "cluster_id": hex::encode(c.0),
            }),
            memvault_auth::GrantAudience::Peer(p) => serde_json::json!({
                "kind": "peer",
                "peer_id": hex::encode(&p.0),
            }),
            memvault_auth::GrantAudience::Agent(a) => serde_json::json!({
                "kind": "agent",
                "agent_id": a.0,
            }),
            memvault_auth::GrantAudience::Role(r) => serde_json::json!({
                "kind": "role",
                "role": format!("{r:?}").to_lowercase(),
            }),
        };
        let actions_json: Vec<&str> = actions
            .iter()
            .map(|a| match a {
                memvault_auth::Action::Read => "read",
                memvault_auth::Action::Write => "write",
                memvault_auth::Action::Admin => "admin",
                memvault_auth::Action::Egress => "egress",
            })
            .collect();
        let body = serde_json::json!({
            "audience": audience_json,
            "actions": actions_json,
            "ttl_secs": ttl_secs,
        });
        #[derive(serde::Deserialize)]
        struct Resp {
            grant_cid: String,
        }
        let resp = self
            .client
            .post(self.url(&format!(
                "/buckets/{}/issue-grant",
                hex::encode(bucket_id.0)
            )))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        let parsed: Resp = resp.json().await.map_err(map_reqwest)?;
        hex::decode(parsed.grant_cid)
            .map_err(|e| ApiError::Other(format!("decode grant_cid: {e}")))
    }

    async fn share_get_proposal(
        &self,
        _proposal_cid: &[u8],
    ) -> Result<Option<ShareProposalInfo>> {
        Err(ApiError::Other(
            "share_get_proposal is not available over HTTP".into(),
        ))
    }

    async fn share_inbox(&self) -> Result<Vec<Vec<u8>>> {
        let resp = self
            .client
            .get(self.url("/share/inbox"))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(resp)
    }

    async fn share_outbox(&self) -> Result<Vec<Vec<u8>>> {
        let resp = self
            .client
            .get(self.url("/share/outbox"))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(resp)
    }

    async fn share_decide(
        &self,
        proposal_cid: &[u8],
        approve: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        let body = serde_json::json!({
            "approve": approve,
            "reason": reason,
        });
        self.client
            .post(self.url(&format!("/share/decide/{}", hex::encode(proposal_cid))))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    async fn bucket_attach(&self, id: &memvault_core::BucketId) -> Result<()> {
        self.client
            .post(self.url(&format!("/buckets/{}/attach", hex::encode(id.0))))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    async fn bucket_archive(&self, id: &memvault_core::BucketId, reason: &str) -> Result<()> {
        let body = serde_json::json!({ "reason": reason });
        self.client
            .post(self.url(&format!("/buckets/{}/archive", hex::encode(id.0))))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?;
        Ok(())
    }

    // -- Rotation --

    async fn list_rotations(&self) -> Result<Vec<RotationInfo>> {
        // RotationInfo decodes directly (hex wire encoding; see standards/).
        let rotations = self
            .client
            .get(self.url("/admin/rotations"))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(rotations)
    }

    // -- Status --

    async fn status(&self) -> Result<NodeStatus> {
        // NodeStatus decodes directly (hex wire encoding; see standards/). The
        // old hand-parse dropped peer_id/cluster_id entirely.
        let status = self
            .client
            .get(self.url("/admin/status"))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        Ok(status)
    }

    async fn legacy_bucket_id(&self) -> Result<BucketId> {
        let buckets = self.bucket_list().await?;
        if let Some(b) = buckets.first() {
            return Ok(b.id.clone());
        }
        Ok(BucketId([0u8; 32]))
    }

    async fn ensure_agent_bucket(&self, agent_id: &str) -> Result<BucketId> {
        let resp: serde_json::Value = self
            .client
            .post(self.url("/buckets/agent"))
            .json(&serde_json::json!({ "agent_id": agent_id }))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let id_hex = resp["id"]
            .as_str()
            .ok_or_else(|| ApiError::Other("missing id in response".into()))?;
        let bytes =
            hex::decode(id_hex).map_err(|e| ApiError::Other(format!("invalid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(ApiError::Other("bucket id must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(BucketId(arr))
    }

    async fn ensure_agent_bucket_for_pubkey(
        &self,
        _agent_pubkey: &[u8],
        _name_hint: &str,
    ) -> Result<BucketId> {
        // The pubkey-keyed lookup is the server's job — it already has the
        // verified pubkey in `claims.sub`. HTTP callers should use
        // `ensure_agent_bucket(agent_id)` and let the server pick up the
        // pubkey from their JWT.
        Err(ApiError::Other(
            "ensure_agent_bucket_for_pubkey is server-side only; HTTP clients should call \
             ensure_agent_bucket(agent_id) and the server will derive the bucket from the \
             verified JWT pubkey"
                .into(),
        ))
    }
}
