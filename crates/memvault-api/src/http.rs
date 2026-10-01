//! HTTP client implementing MemvaultClient — talks to the daemon's REST API.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use memvault_auth::TokenRole;
use memvault_core::{
    BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef, QueryScope, Visibility,
};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit};

use crate::agent_identity::AgentIdentity;
use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};
use crate::rest::{
    AgentLabelRequest, BindBucketRequest, BucketCreated, BucketMerge, CidReceipt,
    CreateBucketRequest, CreateDocRequest, CreateEntityRequest, CreateLinkRequest, DocWire,
    EdgeCreated, ExtractedText, FileUploaded, GrantIssued, GrantRevoked, IssueGrantRequest,
    IssueTokenRequest, LimitParams, LinkResourceRequest, MergeBucketsRequest, NodeBucket,
    NodeCreated, NodeLabel, PinInfo, PublishSkillRequest, ReasonParams, ReasonRequest,
    RenameRequest, ScopeParams, ShareDecideRequest, TagsRequest, TokenIssued, UploadMeta,
    VfsLinkRequest, VfsMkdirRequest, VfsMvRequest, VfsResolved, VfsTree,
};
use crate::types::{
    BucketInfo, DocSummary, FileManifestInfo, GrantInfo, NodeStatus, NodeSummary, RotationInfo,
    ScopeCount, ShareProposalInfo, SkillBundle, SkillInfo, SkillSpec, TokenStatus, TraversalHit,
    View,
};
use crate::vfs::VfsEntry;
use crate::wire::{AuditRecordWire, CidWire, EntityWire, GrantAudienceWire};

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
    /// A token someone else issued (e.g. the caller of the web UI); sent as
    /// is, never renewed.
    fixed: Option<String>,
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
            // Drop pooled connections before the daemon's server closes them
            // (hyper's 30 s header-read timeout on an idle keep-alive
            // connection): reusing one it just closed fails the request
            // with "connection closed before message completed".
            inner: reqwest::Client::builder()
                .pool_idle_timeout(std::time::Duration::from_secs(20))
                .build()?,
            identity,
            cached: Mutex::new(None),
            fixed: None,
        })
    }

    /// Get a valid bearer token, regenerating if cached one is near expiry.
    /// `None` if no identity is configured (unauthenticated client).
    fn bearer(&self) -> Option<String> {
        if let Some(t) = &self.fixed {
            return Some(t.clone());
        }
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
///
/// Every body is a shared serde type (`crate::rest`, `crate::types`,
/// `crate::wire`) — no hand-built JSON, no `serde_json::Value` field-picking
/// (`standards/wire-dtos.md`) — and every method answers what `LocalClient`
/// answers (`standards/client-parity.md`).
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

    /// A client that acts with a token someone else holds (it isn't
    /// renewed): the daemon's REST API then authorizes every call as that
    /// token's agent.
    pub fn with_token(base_url: &str, token: &str) -> std::result::Result<Self, anyhow::Error> {
        let mut client = AuthClient::new(None)?;
        client.fixed = Some(token.to_string());
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.base_url)
    }

    /// Send, and turn a non-2xx answer into an error.
    async fn send(req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        req.send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)
    }

    /// Send and decode the JSON answer.
    async fn json<T: serde::de::DeserializeOwned>(req: reqwest::RequestBuilder) -> Result<T> {
        Self::send(req).await?.json().await.map_err(map_reqwest)
    }

    /// Send and decode the JSON answer; `None` on a 404.
    async fn json_opt<T: serde::de::DeserializeOwned>(
        req: reqwest::RequestBuilder,
    ) -> Result<Option<T>> {
        let resp = req.send().await.map_err(map_reqwest)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        resp.error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map(Some)
            .map_err(map_reqwest)
    }

    /// Send, expecting no body.
    async fn done(req: reqwest::RequestBuilder) -> Result<()> {
        Self::send(req).await.map(|_| ())
    }

    /// `GET /nodes` with a scope: the listing behind `list_all` and
    /// `list_scoped`.
    async fn fetch_nodes(&self, scope: &ScopeParams, limit: usize) -> Result<Vec<NodeSummary>> {
        Self::json(
            self.client
                .get(self.url("/nodes"))
                .query(scope)
                .query(&LimitParams { limit: Some(limit) }),
        )
        .await
    }

    /// `GET /search` with a scope.
    async fn fetch_hits(
        &self,
        scope: &ScopeParams,
        query: &str,
        limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>> {
        Self::json(self.client.get(self.url("/search")).query(scope).query(
            &crate::rest::SearchParams {
                q: query.to_string(),
                limit: Some(limit),
            },
        ))
        .await
    }

    /// The `?bucket=` of a legacy positional-bucket read.
    fn bucket_param(bucket: Option<&BucketId>) -> Option<String> {
        bucket.map(|b| hex::encode(b.0))
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

/// The error with its causes (reqwest's own message alone is often just
/// "error sending request").
fn map_reqwest(e: reqwest::Error) -> ApiError {
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        msg.push_str(&format!(": {s}"));
        source = s.source();
    }
    ApiError::Other(msg)
}

/// Canonical CID-string path segment for a CID byte slice (hex for bytes that
/// aren't exactly one CID). The server accepts both forms; we emit the
/// canonical one. See `standards/api-wire-conventions.md` §1b.
fn cid_path(cid: &[u8]) -> String {
    crate::wire::cid_string(cid)
}

fn vis_str(vis: Visibility) -> Option<String> {
    Some(format!("{vis:?}").to_lowercase())
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
        let body = CreateDocRequest {
            body: doc.body,
            frontmatter: Some(doc.frontmatter),
            tags,
            visibility: vis_str(vis),
            vfs_path: None,
            bucket: Self::bucket_param(bucket),
            // The caller's id, so the id it hands out is the stored one (an
            // all-zero id means "let the server choose").
            id: (doc.id.0 != [0u8; 32]).then(|| hex::encode(doc.id.0)),
        };
        let made: DocWire = Self::json(self.client.post(self.url("/docs")).json(&body)).await?;
        Ok(made.cid.unwrap_or_default())
    }

    async fn get_doc(&self, id: &DocId) -> Result<Option<Document>> {
        self.get_doc_scoped(id, &QueryScope::all()).await
    }

    async fn get_doc_scoped(&self, id: &DocId, scope: &QueryScope) -> Result<Option<Document>> {
        let doc: Option<DocWire> = Self::json_opt(
            self.client
                .get(self.url(&format!("/docs/{}", hex::encode(id.0))))
                .query(&ScopeParams::from_scope(scope)),
        )
        .await?;
        Ok(doc.map(|d| Document {
            id: id.clone(),
            body: d.body,
            frontmatter: d.frontmatter,
        }))
    }

    async fn edit_doc(&self, id: &DocId, patch: TextPatch) -> Result<Vec<u8>> {
        let receipt: CidReceipt = Self::json(
            self.client
                .put(self.url(&format!("/docs/{}", hex::encode(id.0))))
                .json(&patch),
        )
        .await?;
        Ok(receipt.cid)
    }

    async fn list_docs(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<DocSummary>> {
        self.list_docs_ex(tag_filter, limit, bucket, false).await
    }

    async fn list_docs_ex(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        bucket: Option<&BucketId>,
        include_retracted: bool,
    ) -> Result<Vec<DocSummary>> {
        let (tag_ns, tag_val) = tag_filter.unzip();
        Self::json(
            self.client
                .get(self.url("/docs"))
                .query(&crate::rest::ListDocsParams {
                    tag_ns,
                    tag_val,
                    limit: Some(limit),
                    bucket: Self::bucket_param(bucket),
                    include_retracted: Some(include_retracted),
                }),
        )
        .await
    }

    // -- Files --

    async fn upload_file(
        &self,
        data: &[u8],
        filename: Option<&str>,
        mime_type: &str,
        tags: Vec<(String, String)>,
        visibility: &str,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        let fname = filename.unwrap_or("unnamed");
        let part = reqwest::multipart::Part::bytes(data.to_vec())
            .file_name(fname.to_string())
            .mime_str(mime_type)
            .map_err(|e| ApiError::Other(e.to_string()))?;
        let meta = serde_json::to_string(&UploadMeta {
            tags,
            visibility: Some(visibility.to_string()),
        })
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let form = reqwest::multipart::Form::new()
            .text("meta", meta)
            .part("file", part);
        let mut url = self.url("/files");
        if let Some(b) = bucket {
            url.push_str(&format!("?bucket={}", hex::encode(b.0)));
        }
        let made: FileUploaded = Self::json(self.client.post(&url).multipart(form)).await?;
        Ok(made.cid)
    }

    async fn read_file(&self, manifest_cid: &[u8]) -> Result<Vec<u8>> {
        let resp = Self::send(
            self.client
                .get(self.url(&format!("/files/{}", cid_path(manifest_cid)))),
        )
        .await?;
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
        let t: ExtractedText = Self::json(
            self.client
                .get(self.url(&format!("/files/{}/extracted-text", cid_path(manifest_cid)))),
        )
        .await?;
        Ok(t.text)
    }

    async fn read_extraction(&self, manifest_cid: &[u8]) -> Result<crate::types::ExtractionInfo> {
        Self::json(
            self.client
                .get(self.url(&format!("/files/{}/extraction", cid_path(manifest_cid)))),
        )
        .await
    }

    async fn read_page_render(&self, manifest_cid: &[u8]) -> Result<crate::types::PageRenderInfo> {
        Self::json(
            self.client
                .get(self.url(&format!("/files/{}/pages", cid_path(manifest_cid)))),
        )
        .await
    }

    async fn read_page_image(
        &self,
        manifest_cid: &[u8],
        page_no: u32,
    ) -> Result<Option<(Vec<u8>, String)>> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/files/{}/pages/{page_no}/image",
                cid_path(manifest_cid)
            )))
            .send()
            .await
            .map_err(map_reqwest)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status().map_err(map_reqwest)?;
        let mime = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("image/png")
            .to_string();
        let bytes = resp.bytes().await.map_err(map_reqwest)?;
        Ok(Some((bytes.to_vec(), mime)))
    }

    async fn read_page_text_layer(
        &self,
        manifest_cid: &[u8],
        page_no: u32,
    ) -> Result<Option<crate::types::PageTextLayer>> {
        Self::json_opt(self.client.get(self.url(&format!(
            "/files/{}/pages/{page_no}/text-layer",
            cid_path(manifest_cid)
        ))))
        .await
    }

    async fn pin_file(&self, manifest_cid: &[u8]) -> Result<()> {
        Self::done(
            self.client
                .post(self.url(&format!("/files/{}/pin", cid_path(manifest_cid)))),
        )
        .await
    }

    async fn unpin_file(&self, manifest_cid: &[u8]) -> Result<()> {
        Self::done(
            self.client
                .delete(self.url(&format!("/files/{}/pin", cid_path(manifest_cid)))),
        )
        .await
    }

    async fn list_pinned(&self) -> Result<Vec<(Vec<u8>, String)>> {
        let pins: Vec<PinInfo> = Self::json(self.client.get(self.url("/pins"))).await?;
        Ok(pins.into_iter().map(|p| (p.cid, p.name)).collect())
    }

    async fn get_file_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>> {
        // The manifest travels as `FileManifestInfo`; callers decode the
        // bytes with `memvault_store::deserialize_block`, which reads this
        // JSON as it reads the dag-cbor block locally.
        let info: Option<FileManifestInfo> = Self::json_opt(
            self.client
                .get(self.url(&format!("/files/{}/manifest", cid_path(manifest_cid)))),
        )
        .await?;
        info.map(|i| serde_json::to_vec(&i).map_err(|e| ApiError::Serialization(e.to_string())))
            .transpose()
    }

    // -- Graph --

    async fn add_entity_internal(
        &self,
        entity: Entity,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId> {
        let body = CreateEntityRequest {
            kind: entity.kind,
            props: entity.props,
            visibility: vis_str(vis),
            vfs_path: None,
            bucket: Self::bucket_param(bucket),
        };
        let made: NodeCreated =
            Self::json(self.client.post(self.url("/entities")).json(&body)).await?;
        match NodeRef::from_tag_label(&made.node_id) {
            Some(NodeRef::Entity(eid)) => Ok(eid),
            _ => Err(ApiError::Other(format!(
                "create entity: server returned unexpected node_id {:?}",
                made.node_id
            ))),
        }
    }

    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>> {
        self.get_entity_scoped(id, &QueryScope::all()).await
    }

    async fn get_entity_scoped(&self, id: &EntityId, scope: &QueryScope) -> Result<Option<Entity>> {
        let wire: Option<EntityWire> = Self::json_opt(
            self.client
                .get(self.url(&format!("/entities/{}", hex::encode(id.0))))
                .query(&ScopeParams::from_scope(scope)),
        )
        .await?;
        Ok(wire.and_then(EntityWire::into_entity))
    }

    async fn list_entities(&self, limit: usize, bucket: Option<&BucketId>) -> Result<Vec<Entity>> {
        self.list_entities_ex(limit, bucket, false).await
    }

    async fn list_entities_ex(
        &self,
        limit: usize,
        bucket: Option<&BucketId>,
        include_retracted: bool,
    ) -> Result<Vec<Entity>> {
        let wire: Vec<EntityWire> = Self::json(self.client.get(self.url("/entities")).query(
            &crate::rest::ListEntitiesParams {
                kind: None,
                limit: Some(limit),
                bucket: Self::bucket_param(bucket),
                include_retracted: Some(include_retracted),
            },
        ))
        .await?;
        Ok(wire
            .into_iter()
            .filter_map(EntityWire::into_entity)
            .collect())
    }

    async fn entity_history(&self, id: &EntityId) -> Result<Vec<AuditRecord>> {
        let rows: Vec<AuditRecordWire> = Self::json(
            self.client
                .get(self.url(&format!("/entities/{}/history", hex::encode(id.0)))),
        )
        .await?;
        Ok(rows.into_iter().map(AuditRecord::from).collect())
    }

    async fn node_bucket(&self, node: &NodeRef) -> Result<Option<BucketId>> {
        let b: Option<NodeBucket> = Self::json_opt(
            self.client
                .get(self.url(&format!("/nodes/{}/bucket", urlencoded(&node.tag_label())))),
        )
        .await?;
        Ok(b.and_then(|b| b.bucket_id))
    }

    // -- Links --

    async fn add_link(&self, source: &NodeRef, edge: Edge, vis: Visibility) -> Result<EdgeId> {
        let body = CreateLinkRequest {
            source: source.tag_label(),
            target: edge.target.tag_label(),
            relation: edge.relation,
            weight: edge.weight,
            props: edge.props,
            visibility: vis_str(vis),
        };
        let made: EdgeCreated =
            Self::json(self.client.post(self.url("/links")).json(&body)).await?;
        Ok(made.edge_id)
    }

    async fn remove_link_from(&self, source: &NodeRef, edge_id: &EdgeId) -> Result<()> {
        let url = format!(
            "{}?source={}",
            self.url(&format!("/links/{}", hex::encode(edge_id.0))),
            urlencoded(&source.tag_label())
        );
        Self::done(self.client.delete(&url)).await
    }

    async fn edges_of(&self, node: &NodeRef) -> Result<Vec<(NodeRef, Edge)>> {
        let url = format!(
            "{}?node={}",
            self.url("/links"),
            urlencoded(&node.tag_label())
        );
        let wire: Vec<crate::wire::LinkWire> = Self::json(self.client.get(&url)).await?;
        Ok(wire
            .into_iter()
            .filter_map(|w| w.into_source_edge())
            .collect())
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
        Self::json(self.client.get(&url)).await
    }

    // -- Tags --

    async fn add_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        Self::done(
            self.client
                .put(self.url(&format!("/tags/{}", urlencoded(node_id))))
                .json(&TagsRequest { tags }),
        )
        .await
    }

    async fn remove_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        Self::done(
            self.client
                .delete(self.url(&format!("/tags/{}", urlencoded(node_id))))
                .json(&TagsRequest { tags }),
        )
        .await
    }

    async fn get_tags(&self, node_id: &str) -> Result<Vec<(String, String)>> {
        Self::json(
            self.client
                .get(self.url(&format!("/tags/{}", urlencoded(node_id)))),
        )
        .await
    }

    // -- Views --

    async fn list_views(&self) -> Result<Vec<View>> {
        Self::json(self.client.get(self.url("/views"))).await
    }

    async fn create_view(&self, view: View) -> Result<()> {
        Self::done(self.client.post(self.url("/views")).json(&view)).await
    }

    async fn delete_view(&self, name: &str) -> Result<()> {
        Self::done(
            self.client
                .delete(self.url(&format!("/views/{}", urlencoded(name)))),
        )
        .await
    }

    async fn get_view(&self, name: &str) -> Result<Option<View>> {
        Self::json_opt(
            self.client
                .get(self.url(&format!("/views/{}", urlencoded(name)))),
        )
        .await
    }

    async fn update_view(&self, view: View) -> Result<()> {
        Self::done(
            self.client
                .put(self.url(&format!("/views/{}", urlencoded(&view.name))))
                .json(&view),
        )
        .await
    }

    // -- Search --

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let scope = QueryScope::all().with_kind(Some(memvault_core::NodeKind::Document));
        let hits = self
            .fetch_hits(&ScopeParams::from_scope(&scope), query, limit)
            .await?;
        Ok(hits
            .into_iter()
            .filter_map(|h| match NodeRef::from_tag_label(&h.node_id)? {
                NodeRef::Doc(doc_id) => Some(SearchHit {
                    doc_id,
                    score: h.score,
                    snippet: h.snippet,
                }),
                _ => None,
            })
            .collect())
    }

    async fn search_unified(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>> {
        self.search_scoped(&QueryScope::all(), query, limit).await
    }

    async fn search_scoped(
        &self,
        scope: &QueryScope,
        query: &str,
        limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>> {
        self.fetch_hits(&ScopeParams::from_scope(scope), query, limit)
            .await
    }

    async fn list_all(
        &self,
        view_name: Option<&str>,
        limit: usize,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<(String, String, String, Vec<(String, String)>)>> {
        let scope = QueryScope::all()
            .with_view(view_name.map(String::from))
            .with_bucket(bucket.cloned());
        Ok(self
            .list_scoped(&scope, limit)
            .await?
            .into_iter()
            .map(|n| (n.node_id, n.node_type, n.label, n.tags))
            .collect())
    }

    async fn list_scoped(&self, scope: &QueryScope, limit: usize) -> Result<Vec<NodeSummary>> {
        self.fetch_nodes(&ScopeParams::from_scope(scope), limit)
            .await
    }

    async fn count_scoped(&self, scope: &QueryScope) -> Result<ScopeCount> {
        Self::json(
            self.client
                .get(self.url("/nodes/count"))
                .query(&ScopeParams::from_scope(scope)),
        )
        .await
    }

    async fn view_members(&self, view_name: &str) -> Result<Vec<String>> {
        Self::json(
            self.client
                .get(self.url(&format!("/views/{}/members", urlencoded(view_name)))),
        )
        .await
    }

    async fn resolve_label(&self, node_id: &str) -> Result<Option<String>> {
        self.resolve_label_scoped(node_id, &QueryScope::all()).await
    }

    async fn resolve_label_scoped(
        &self,
        node_id: &str,
        scope: &QueryScope,
    ) -> Result<Option<String>> {
        let l: Option<NodeLabel> = Self::json_opt(
            self.client
                .get(self.url(&format!("/labels/{}", urlencoded(node_id))))
                .query(&ScopeParams::from_scope(scope)),
        )
        .await?;
        Ok(l.and_then(|l| l.label))
    }

    // -- History & Audit --

    async fn history_of(&self, doc_id: &DocId) -> Result<Vec<AuditRecord>> {
        let rows: Vec<AuditRecordWire> = Self::json(
            self.client
                .get(self.url(&format!("/docs/{}/history", hex::encode(doc_id.0)))),
        )
        .await?;
        Ok(rows.into_iter().map(AuditRecord::from).collect())
    }

    async fn audit(&self, query: AuditQuery) -> Result<Vec<AuditRecord>> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(d) = &query.doc_id {
            params.push(("doc_id", hex::encode(d.0)));
        }
        if let Some(a) = &query.author {
            params.push(("author", hex::encode(a)));
        }
        if let Some(k) = &query.op_kind {
            if let Ok(serde_json::Value::String(s)) = serde_json::to_value(k) {
                params.push(("op_kind", s));
            }
        }
        if let Some(n) = query.after_ns {
            params.push(("after_ns", n.to_string()));
        }
        if let Some(n) = query.before_ns {
            params.push(("before_ns", n.to_string()));
        }
        if let Some(n) = query.limit {
            params.push(("limit", n.to_string()));
        }
        if let Some(b) = &query.bucket {
            params.push(("bucket", hex::encode(b.0)));
        }
        let rows: Vec<AuditRecordWire> =
            Self::json(self.client.get(self.url("/audit")).query(&params)).await?;
        Ok(rows.into_iter().map(AuditRecord::from).collect())
    }

    async fn retract(&self, target_cid: &[u8], reason: &str) -> Result<Vec<u8>> {
        // `/docs/{id}` takes a document id (hex) or a block CID.
        let target = if target_cid.len() == 32 {
            hex::encode(target_cid)
        } else {
            cid_path(target_cid)
        };
        let receipt: CidReceipt = Self::json(
            self.client
                .delete(self.url(&format!("/docs/{target}")))
                .query(&ReasonParams {
                    reason: Some(reason.to_string()),
                }),
        )
        .await?;
        Ok(receipt.cid)
    }

    async fn retract_node_internal(&self, node_id: &str, reason: &str) -> Result<()> {
        Self::done(
            self.client
                .delete(self.url(&format!("/nodes/{}", urlencoded(node_id))))
                .query(&ReasonParams {
                    reason: Some(reason.to_string()),
                }),
        )
        .await
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
        let (agent_role, node_role) = IssueTokenRequest::role_fields(role);
        let body = IssueTokenRequest {
            agent_role,
            node_role,
            ttl_secs,
            max_uses,
            label,
            issuer_addrs,
        };
        let made: TokenIssued =
            Self::json(self.client.post(self.url("/admin/tokens")).json(&body)).await?;
        Ok(made.token)
    }

    async fn list_tokens(&self) -> Result<Vec<TokenStatus>> {
        Self::json(self.client.get(self.url("/admin/tokens"))).await
    }

    async fn revoke_token(&self, token_cid: &[u8], reason: &str) -> Result<()> {
        Self::done(
            self.client
                .delete(self.url(&format!("/admin/tokens/{}", cid_path(token_cid))))
                .query(&ReasonParams {
                    reason: Some(reason.to_string()),
                }),
        )
        .await
    }

    // -- Buckets --

    async fn bucket_create(
        &self,
        name: &str,
        description: Option<&str>,
        default_visibility: memvault_core::Visibility,
        default_classification: memvault_core::classification::Classification,
        role: memvault_core::BucketRole,
    ) -> Result<BucketId> {
        let body = CreateBucketRequest {
            name: name.to_string(),
            description: description.map(String::from),
            default_visibility: Some(default_visibility),
            default_classification: Some(default_classification),
            role: Some(role),
        };
        let made: BucketCreated =
            Self::json(self.client.post(self.url("/buckets")).json(&body)).await?;
        Ok(made.bucket_id)
    }

    async fn bucket_list_filtered(&self, include_merged: bool) -> Result<Vec<BucketInfo>> {
        let url = if include_merged {
            self.url("/buckets?include_merged=true")
        } else {
            self.url("/buckets")
        };
        Self::json(self.client.get(url)).await
    }

    async fn bucket_get(&self, id: &BucketId) -> Result<Option<BucketInfo>> {
        Self::json_opt(
            self.client
                .get(self.url(&format!("/buckets/{}", hex::encode(id.0)))),
        )
        .await
    }

    async fn bucket_rename(&self, id: &BucketId, new_name: &str) -> Result<()> {
        Self::done(
            self.client
                .patch(self.url(&format!("/buckets/{}", hex::encode(id.0))))
                .json(&RenameRequest {
                    name: new_name.to_string(),
                }),
        )
        .await
    }

    async fn bucket_merge(&self, sources: &[BucketId], canonical: &BucketId) -> Result<()> {
        Self::done(
            self.client
                .post(self.url("/buckets/merge"))
                .json(&MergeBucketsRequest {
                    sources: sources.to_vec(),
                    canonical: canonical.clone(),
                }),
        )
        .await
    }

    async fn bucket_unmerge(&self, source: &BucketId, canonical: &BucketId) -> Result<()> {
        Self::done(
            self.client
                .post(self.url("/buckets/unmerge"))
                .json(&BucketMerge {
                    source: source.clone(),
                    canonical: canonical.clone(),
                }),
        )
        .await
    }

    async fn bucket_merges(&self) -> Result<Vec<(BucketId, BucketId)>> {
        let rows: Vec<BucketMerge> =
            Self::json(self.client.get(self.url("/buckets/merges"))).await?;
        Ok(rows.into_iter().map(|m| (m.source, m.canonical)).collect())
    }

    async fn agent_rename(&self, agent_pubkey: &[u8; 32], new_label: &str) -> Result<()> {
        Self::done(
            self.client
                .patch(self.url(&format!("/agents/{}", hex::encode(agent_pubkey))))
                .json(&AgentLabelRequest {
                    label: new_label.to_string(),
                }),
        )
        .await
    }

    async fn bucket_bind(&self, bucket_id: &BucketId, cluster_id: &ClusterId) -> Result<()> {
        Self::done(
            self.client
                .post(self.url(&format!("/buckets/{}/bind", hex::encode(bucket_id.0))))
                .json(&BindBucketRequest {
                    cluster_id: cluster_id.clone(),
                }),
        )
        .await
    }

    async fn bucket_attach(&self, id: &BucketId) -> Result<()> {
        Self::done(
            self.client
                .post(self.url(&format!("/buckets/{}/attach", hex::encode(id.0)))),
        )
        .await
    }

    async fn bucket_archive(&self, id: &BucketId, reason: &str) -> Result<()> {
        Self::done(
            self.client
                .post(self.url(&format!("/buckets/{}/archive", hex::encode(id.0))))
                .json(&ReasonRequest {
                    reason: reason.to_string(),
                }),
        )
        .await
    }

    async fn ensure_agent_bucket(&self, _agent_pubkey: &[u8], name_hint: &str) -> Result<BucketId> {
        // The server derives the bucket from the verified JWT pubkey
        // (`claims.sub`), so it can only ever ensure THIS agent's bucket —
        // the passed pubkey is ignored over HTTP. `name_hint` is the display
        // label, sent as `agent_id`.
        let made: BucketCreated = Self::json(self.client.post(self.url("/buckets/agent")).json(
            &crate::rest::EnsureAgentBucketRequest {
                agent_id: name_hint.to_string(),
            },
        ))
        .await?;
        Ok(made.bucket_id)
    }

    async fn legacy_bucket_id(&self) -> Result<BucketId> {
        let buckets = self.bucket_list().await?;
        if let Some(b) = buckets
            .iter()
            .find(|b| b.role == memvault_core::BucketRole::Legacy)
        {
            return Ok(b.id.clone());
        }
        Err(ApiError::Other(
            "no legacy bucket visible to this agent".into(),
        ))
    }

    async fn bucket_grants_list(&self, bucket_id: &BucketId) -> Result<Vec<GrantInfo>> {
        Self::json(
            self.client
                .get(self.url(&format!("/buckets/{}/grants", hex::encode(bucket_id.0)))),
        )
        .await
    }

    async fn bucket_grant(
        &self,
        bucket_id: &BucketId,
        audience: memvault_auth::GrantAudience,
        actions: Vec<memvault_auth::Action>,
        ttl_secs: u64,
    ) -> Result<Vec<u8>> {
        let body = IssueGrantRequest {
            audience: GrantAudienceWire::from(&audience),
            actions,
            ttl_secs,
        };
        let made: GrantIssued = Self::json(
            self.client
                .post(self.url(&format!(
                    "/buckets/{}/issue-grant",
                    hex::encode(bucket_id.0)
                )))
                .json(&body),
        )
        .await?;
        Ok(made.grant_cid)
    }

    async fn revoke_grant(&self, grant_cid: &[u8], reason: &str) -> Result<Vec<u8>> {
        let made: GrantRevoked = Self::json(
            self.client
                .post(self.url(&format!("/grants/{}/revoke", cid_path(grant_cid))))
                .json(&ReasonRequest {
                    reason: reason.to_string(),
                }),
        )
        .await?;
        Ok(made.revocation_cid)
    }

    // -- Sharing --

    async fn share_inbox(&self) -> Result<Vec<Vec<u8>>> {
        let cids: Vec<CidWire> = Self::json(self.client.get(self.url("/share/inbox"))).await?;
        Ok(cids.into_iter().map(|c| c.0).collect())
    }

    async fn share_outbox(&self) -> Result<Vec<Vec<u8>>> {
        let cids: Vec<CidWire> = Self::json(self.client.get(self.url("/share/outbox"))).await?;
        Ok(cids.into_iter().map(|c| c.0).collect())
    }

    async fn share_get_proposal(&self, proposal_cid: &[u8]) -> Result<Option<ShareProposalInfo>> {
        Self::json_opt(
            self.client
                .get(self.url(&format!("/share/proposals/{}", cid_path(proposal_cid)))),
        )
        .await
    }

    async fn share_decide(
        &self,
        proposal_cid: &[u8],
        approve: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        Self::done(
            self.client
                .post(self.url(&format!(
                    "/share/proposals/{}/decide",
                    cid_path(proposal_cid)
                )))
                .json(&ShareDecideRequest {
                    approve,
                    reason: reason.map(String::from),
                }),
        )
        .await
    }

    // -- Skills --

    async fn skill_publish(
        &self,
        spec: SkillSpec,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId> {
        let body = PublishSkillRequest {
            spec,
            visibility: vis_str(vis),
            bucket: Self::bucket_param(bucket),
        };
        let made: NodeCreated =
            Self::json(self.client.post(self.url("/skills")).json(&body)).await?;
        match NodeRef::from_tag_label(&made.node_id) {
            Some(NodeRef::Entity(eid)) => Ok(eid),
            _ => Err(ApiError::Other(format!(
                "publish skill: server returned unexpected node_id {:?}",
                made.node_id
            ))),
        }
    }

    async fn skill_list(&self, limit: usize, bucket: Option<&BucketId>) -> Result<Vec<SkillInfo>> {
        let mut url = format!("{}?limit={limit}", self.url("/skills"));
        if let Some(b) = bucket {
            url.push_str(&format!("&bucket={}", hex::encode(b.0)));
        }
        Self::json(self.client.get(&url)).await
    }

    async fn skill_get(&self, id: &EntityId) -> Result<Option<SkillBundle>> {
        Self::json_opt(
            self.client
                .get(self.url(&format!("/skills/{}", hex::encode(id.0)))),
        )
        .await
    }

    async fn skill_rename(&self, id: &EntityId, new_name: &str) -> Result<()> {
        Self::done(
            self.client
                .patch(self.url(&format!("/skills/{}", hex::encode(id.0))))
                .json(&RenameRequest {
                    name: new_name.to_string(),
                }),
        )
        .await
    }

    async fn skill_delete(&self, id: &EntityId, reason: &str) -> Result<()> {
        Self::done(
            self.client
                .delete(self.url(&format!("/skills/{}", hex::encode(id.0))))
                .query(&ReasonParams {
                    reason: Some(reason.to_string()),
                }),
        )
        .await
    }

    async fn skill_link_resource(
        &self,
        skill_id: &EntityId,
        target: &NodeRef,
        relation: &str,
        path: Option<&str>,
        executable: bool,
        vis: Visibility,
    ) -> Result<EdgeId> {
        let body = LinkResourceRequest {
            node: target.tag_label(),
            relation: relation.to_string(),
            path: path.map(String::from),
            executable,
            visibility: vis_str(vis),
        };
        let made: EdgeCreated = Self::json(
            self.client
                .post(self.url(&format!("/skills/{}/resources", hex::encode(skill_id.0))))
                .json(&body),
        )
        .await?;
        Ok(made.edge_id)
    }

    async fn skill_unlink_resource(&self, skill_id: &EntityId, edge_id: &EdgeId) -> Result<()> {
        Self::done(self.client.delete(self.url(&format!(
            "/skills/{}/resources/{}",
            hex::encode(skill_id.0),
            hex::encode(edge_id.0)
        ))))
        .await
    }

    // -- VFS (threads through to the dedicated /vfs/* endpoints) --

    async fn vfs_mkdir(&self, bucket: &BucketId, path: &str) -> Result<EntityId> {
        let made: NodeCreated = Self::json(self.client.post(self.url("/vfs/mkdir")).json(
            &VfsMkdirRequest {
                path: path.to_string(),
                bucket: bucket.clone(),
            },
        ))
        .await?;
        match NodeRef::from_tag_label(&made.node_id) {
            Some(NodeRef::Entity(eid)) => Ok(eid),
            _ => Err(ApiError::Other(format!(
                "vfs_mkdir: unexpected node_id {:?}",
                made.node_id
            ))),
        }
    }

    async fn vfs_ls(
        &self,
        bucket: &BucketId,
        path: &str,
        recursive: bool,
    ) -> Result<Vec<VfsEntry>> {
        let url = format!(
            "{}?bucket={}&path={}&recursive={}",
            self.url("/vfs"),
            hex::encode(bucket.0),
            urlencoded(path),
            recursive
        );
        Self::json(self.client.get(&url)).await
    }

    async fn vfs_resolve(
        &self,
        bucket: &BucketId,
        path: &str,
    ) -> Result<Option<(NodeRef, Option<EdgeId>)>> {
        let url = format!(
            "{}?bucket={}&path={}",
            self.url("/vfs/resolve"),
            hex::encode(bucket.0),
            urlencoded(path)
        );
        let at: Option<VfsResolved> = Self::json_opt(self.client.get(&url)).await?;
        Ok(at.and_then(|r| Some((NodeRef::from_tag_label(&r.node_id)?, r.edge_id))))
    }

    async fn vfs_link(&self, bucket: &BucketId, path: &str, target: &NodeRef) -> Result<EdgeId> {
        let made: EdgeCreated = Self::json(self.client.post(self.url("/vfs/link")).json(
            &VfsLinkRequest {
                path: path.to_string(),
                target: target.tag_label(),
                bucket: bucket.clone(),
            },
        ))
        .await?;
        Ok(made.edge_id)
    }

    async fn vfs_unlink(&self, bucket: &BucketId, path: &str) -> Result<()> {
        let url = format!(
            "{}?bucket={}&path={}",
            self.url("/vfs"),
            hex::encode(bucket.0),
            urlencoded(path)
        );
        Self::done(self.client.delete(&url)).await
    }

    async fn vfs_mv(&self, bucket: &BucketId, from: &str, to: &str) -> Result<()> {
        Self::done(self.client.post(self.url("/vfs/mv")).json(&VfsMvRequest {
            from: from.to_string(),
            to: to.to_string(),
            bucket: bucket.clone(),
        }))
        .await
    }

    async fn vfs_tree(&self, bucket: &BucketId, path: &str, max_depth: usize) -> Result<String> {
        let url = format!(
            "{}?bucket={}&path={}&max_depth={max_depth}",
            self.url("/vfs/tree"),
            hex::encode(bucket.0),
            urlencoded(path)
        );
        let t: VfsTree = Self::json(self.client.get(&url)).await?;
        Ok(t.tree)
    }

    async fn vfs_find(&self, bucket: &BucketId, target: &NodeRef) -> Result<Vec<String>> {
        let url = format!(
            "{}?bucket={}&target={}",
            self.url("/vfs/find"),
            hex::encode(bucket.0),
            urlencoded(&target.tag_label())
        );
        Self::json(self.client.get(&url)).await
    }

    // -- Rotation & status --

    async fn list_rotations(&self) -> Result<Vec<RotationInfo>> {
        Self::json(self.client.get(self.url("/admin/rotations"))).await
    }

    async fn status(&self) -> Result<NodeStatus> {
        Self::json(self.client.get(self.url("/admin/status"))).await
    }
}
