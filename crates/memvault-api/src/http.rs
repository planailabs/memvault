//! HTTP client implementing MemvaultClient — talks to the daemon's REST API.

use std::collections::BTreeMap;

use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, HeaderValue};

use memvault_auth::Role;
use memvault_core::{BucketId, DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit};

use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};
use crate::types::{
    BucketInfo, DocSummary, NodeStatus, RotationInfo, TokenStatus, TraversalHit, View,
};

/// HTTP client that implements MemvaultClient by talking to the daemon's REST API.
pub struct HttpApiClient {
    client: reqwest::Client,
    base_url: String,
}

impl HttpApiClient {
    pub fn new(base_url: &str, token: &str) -> std::result::Result<Self, anyhow::Error> {
        let mut headers = reqwest::header::HeaderMap::new();
        if !token.is_empty() {
            let auth_value = format!("Bearer {token}");
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_value)
                    .map_err(|e| anyhow::anyhow!("invalid token: {e}"))?,
            );
        }
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;
        Ok(Self {
            client,
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

#[async_trait]
impl MemvaultClient for HttpApiClient {
    // -- Documents --

    async fn put_doc(
        &self,
        doc: Document,
        tags: Vec<(String, String)>,
        vis: Visibility,
        _bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        let resp: serde_json::Value = self
            .client
            .post(self.url("/docs"))
            .json(&serde_json::json!({
                "body": doc.body,
                "frontmatter": doc.frontmatter,
                "tags": tags,
                "visibility": format!("{vis:?}").to_lowercase(),
            }))
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
        let docs = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let id_hex = v["id"].as_str()?;
                        let id_bytes = hex::decode(id_hex).ok()?;
                        if id_bytes.len() != 32 {
                            return None;
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&id_bytes);
                        Some(DocSummary {
                            id: DocId(arr),
                            cid: hex::decode(v["cid"].as_str().unwrap_or("")).unwrap_or_default(),
                            title: v["title"].as_str().map(String::from),
                            tags: vec![],
                            updated_ns: v["updated_ns"].as_u64().unwrap_or(0),
                            attachment_count: 0,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
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
        _bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        let fname = filename.unwrap_or("unnamed");
        let part = reqwest::multipart::Part::bytes(data.to_vec())
            .file_name(fname.to_string())
            .mime_str(mime_type)
            .map_err(|e| ApiError::Other(e.to_string()))?;
        let form = reqwest::multipart::Form::new().part("file", part);
        let resp: serde_json::Value = self
            .client
            .post(self.url("/files"))
            .multipart(form)
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

    async fn read_file(&self, manifest_cid: &[u8]) -> Result<Vec<u8>> {
        let cid_hex = hex::encode(manifest_cid);
        let resp = self
            .client
            .get(self.url(&format!("/files/{cid_hex}")))
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

    async fn read_extracted_text(&self, _manifest_cid: &[u8]) -> Result<Option<String>> {
        Ok(None)
    }

    async fn pin_file(&self, _manifest_cid: &[u8]) -> Result<()> {
        Ok(())
    }
    async fn unpin_file(&self, _manifest_cid: &[u8]) -> Result<()> {
        Ok(())
    }
    async fn list_pinned(&self) -> Result<Vec<(Vec<u8>, String)>> {
        Ok(vec![])
    }

    async fn get_file_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>> {
        let cid_hex = hex::encode(manifest_cid);
        let resp = self
            .client
            .get(self.url(&format!("/files/{cid_hex}/manifest")))
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
        _bucket: Option<&BucketId>,
    ) -> Result<EntityId> {
        let resp: serde_json::Value = self
            .client
            .post(self.url("/entities"))
            .json(&serde_json::json!({
                "kind": entity.kind,
                "props": entity.props,
                "visibility": format!("{vis:?}").to_lowercase(),
            }))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let id_hex = resp["id"].as_str().unwrap_or("");
        let bytes = hex::decode(id_hex).unwrap_or(vec![0u8; 32]);
        let mut arr = [0u8; 32];
        let len = bytes.len().min(32);
        arr[..len].copy_from_slice(&bytes[..len]);
        Ok(EntityId(arr))
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

    async fn list_entities(&self, limit: usize, _bucket: Option<&BucketId>) -> Result<Vec<Entity>> {
        let resp: serde_json::Value = self
            .client
            .get(self.url(&format!("/nodes?limit={limit}&type=entity")))
            .send()
            .await
            .map_err(map_reqwest)?
            .error_for_status()
            .map_err(map_reqwest)?
            .json()
            .await
            .map_err(map_reqwest)?;
        let entities = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let id_hex = v["id"].as_str()?;
                        let bytes = hex::decode(id_hex).ok()?;
                        if bytes.len() != 32 {
                            return None;
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(Entity {
                            id: EntityId(arr),
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

    async fn add_link(&self, _source: &NodeRef, _edge: Edge, _vis: Visibility) -> Result<EdgeId> {
        Ok(EdgeId::random())
    }

    async fn remove_link_from(&self, _source: &NodeRef, _edge_id: &EdgeId) -> Result<()> {
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
        // Parse edges from response — simplified for now
        let _ = resp;
        Ok(vec![])
    }

    async fn traverse_from(
        &self,
        _from: &NodeRef,
        _relation: Option<&str>,
        _max_depth: usize,
    ) -> Result<Vec<TraversalHit>> {
        Ok(vec![])
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
        let tags = resp
            .as_array()
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
        Ok(vec![])
    }
    async fn create_view(&self, _view: View) -> Result<()> {
        Ok(())
    }
    async fn delete_view(&self, _name: &str) -> Result<()> {
        Ok(())
    }
    async fn get_view(&self, _name: &str) -> Result<Option<View>> {
        Ok(None)
    }
    async fn update_view(&self, _view: View) -> Result<()> {
        Ok(())
    }

    // -- Search --

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let url = format!(
            "{}?q={}&limit={limit}",
            self.url("/search"),
            urlencoded(query)
        );
        let _resp: serde_json::Value = self
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
        Ok(vec![])
    }

    async fn search_unified(
        &self,
        _query: &str,
        _limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>> {
        Ok(vec![])
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
        let nodes = resp
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let node_id = v["node_id"].as_str()?.to_string();
                        let node_type = v["type"].as_str().unwrap_or("").to_string();
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

    async fn view_members(&self, _view_name: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }
    async fn resolve_label(&self, _node_id: &str) -> Result<Option<String>> {
        Ok(None)
    }

    // -- History & Audit --

    async fn history_of(&self, doc_id: &DocId) -> Result<Vec<AuditRecord>> {
        let id_hex = hex::encode(doc_id.0);
        let _resp: serde_json::Value = self
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
        Ok(vec![])
    }

    async fn audit(&self, _query: AuditQuery) -> Result<Vec<AuditRecord>> {
        Ok(vec![])
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

    async fn issue_token(
        &self,
        role: Role,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
    ) -> Result<String> {
        let body = serde_json::json!({
            "role": role,
            "ttl_secs": ttl_secs,
            "max_uses": max_uses,
            "label": label,
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
        let resp = self
            .client
            .get(self.url("/tokens"))
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
        let id_bytes: Vec<u8> = serde_json::from_value(resp["id"].clone())
            .map_err(|e| ApiError::Other(format!("missing bucket id: {e}")))?;
        let arr: [u8; 32] = id_bytes
            .try_into()
            .map_err(|_| ApiError::Other("bucket id must be 32 bytes".into()))?;
        Ok(memvault_core::BucketId(arr))
    }

    async fn bucket_list(&self) -> Result<Vec<BucketInfo>> {
        let resp = self
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
        Ok(resp)
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
        Ok(vec![])
    }

    // -- Status --

    async fn status(&self) -> Result<NodeStatus> {
        let resp: serde_json::Value = self
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
        Ok(NodeStatus {
            peer_id: vec![],
            cluster_id: vec![],
            block_count: resp["block_count"].as_u64().unwrap_or(0),
            doc_count: resp["doc_count"].as_u64().unwrap_or(0),
            peer_count: resp["peer_count"].as_u64().unwrap_or(0) as u32,
            uptime_secs: resp["uptime_secs"].as_u64().unwrap_or(0),
        })
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
}
