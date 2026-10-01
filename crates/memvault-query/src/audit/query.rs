//! Audit log query support.

use memvault_core::DocId;
use memvault_store::MemvaultStore;
use serde::{Deserialize, Serialize};

use crate::error::QueryError;

/// What kind of operation was performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    DocCreate,
    DocEdit,
    AttachFile,
    DetachFile,
    EntityCreate,
    EdgeAdd,
    EdgeRemove,
    TagUpdate,
    Extraction,
    Retract,
    BucketCreate,
    BucketRename,
    AgentRename,
    BucketAttach,
    BucketArchive,
    BucketBind,
    BucketMerge,
    BucketUnmerge,
    ViewCreate,
    TokenIssue,
    TokenRedeem,
    SharePropose,
    ShareDecide,
    // Cluster sigchain / membership events (admin-signed security trail).
    ClusterGenesis,
    NodeAttest,
    AgentEnroll,
    AgentRevoke,
    NodeRevoke,
    AdminAdmit,
    AdminRetire,
    GrantRevoke,
    Other(String),
}

/// A single audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub cid: Vec<u8>,
    pub op_kind: OpKind,
    /// Envelope-level author. For Signed<T> envelopes this is the node
    /// pubkey that signed; for legacy raw-JSON envelopes it's whoever the
    /// `effective_author()` was at write time (agent pubkey when an
    /// agent identity was bound, otherwise the node peer_id).
    pub author: Vec<u8>,
    /// CID of the `AgentAttestation` covering the agent that authored
    /// this write, when present. Set on Signed<T> envelopes whenever an
    /// agent identity was bound. UIs should prefer this for "who did
    /// this" attribution.
    #[serde(default)]
    pub agent_attestation: Option<Vec<u8>>,
    pub wall_ns: u64,
    pub doc_id: Option<DocId>,
    pub entity_id: Option<Vec<u8>>,
    pub attachment_cid: Option<Vec<u8>>,
    pub tags: Vec<(String, String)>,
}

/// Query parameters for audit log retrieval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    pub doc_id: Option<DocId>,
    pub author: Option<Vec<u8>>,
    pub op_kind: Option<OpKind>,
    pub after_ns: Option<u64>,
    pub before_ns: Option<u64>,
    pub limit: Option<usize>,
}

/// Query the audit log, newest first.
///
/// The filters (`doc_id`, `op_kind`, `author`, time range) are applied while
/// the index is walked, so `limit` caps the *matching* records: asking for
/// every upload finds them however many other operations are newer. Each
/// visited block is read as an [`AuditHead`] (envelope attribution and the
/// payload's variant and ids), never decoded whole.
pub fn query_audit(
    store: &MemvaultStore,
    query: &AuditQuery,
) -> Result<Vec<AuditRecord>, QueryError> {
    let after = query.after_ns.unwrap_or(0);
    let before = query.before_ns.unwrap_or(u64::MAX);
    let limit = query.limit.unwrap_or(100);
    if limit == 0 {
        return Ok(Vec::new());
    }

    // Sigchain blocks (admin-signed membership/security events: genesis,
    // node/agent attestations, revocations, admin admissions, token
    // redemptions) are NOT generic Signed<T> envelopes — their content has no
    // `payload`/`tags`/`wall_ns`, so the envelope parser would classify every
    // one as Other("unknown"). Every sigchain CID is known from the tag index
    // (no decoding) so the envelope scan skips them all; the typed records
    // are decoded separately and merged in afterwards.
    let sigchain = sigchain_index(store, after)?;
    let sigchain_cids: std::collections::HashSet<&[u8]> =
        sigchain.iter().map(|(_, _, cid)| cid.as_slice()).collect();

    let mut records = Vec::new();
    let mut failure = None;
    let mut visit = |_ts: u64, cid: &[u8]| -> bool {
        if sigchain_cids.contains(cid) {
            return true;
        }
        match store.get_block(cid) {
            Ok(Some(data)) => {
                if let Some(record) = parse_audit_block(cid, &data) {
                    if envelope_matches(query, &record) {
                        records.push(record);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                failure = Some(e);
                return false;
            }
        }
        records.len() < limit
    };
    if let Some(author) = &query.author {
        store.scan_author_desc(author, after, before, &mut visit)?;
    } else if let Some(doc_id) = &query.doc_id {
        // A document's ops are tagged with its id: walk that tag, not the
        // whole log.
        let label = hex::encode(doc_id.0);
        store.scan_tag_desc("doc", &label, after, before, &mut visit)?;
    } else {
        store.scan_time_desc(after, before, &mut visit)?;
    }
    if let Some(e) = failure {
        return Err(e.into());
    }

    // Merge in the typed sigchain records (doc_id never matches these), then
    // sort newest-first and cap to limit so the merged set stays consistent
    // with the scan ordering.
    if query.doc_id.is_none() {
        records.extend(sigchain_records(
            store, &sigchain, query, after, before, limit,
        )?);
    }
    records.sort_by(|a, b| b.wall_ns.cmp(&a.wall_ns));
    records.truncate(limit);

    Ok(records)
}

/// The scan-side filters an envelope record must pass (the author filter is
/// the author index itself).
fn envelope_matches(query: &AuditQuery, record: &AuditRecord) -> bool {
    if let Some(filter_doc) = &query.doc_id {
        if record.doc_id.as_ref() != Some(filter_doc) {
            return false;
        }
    }
    if let Some(filter_kind) = &query.op_kind {
        if &record.op_kind != filter_kind {
            return false;
        }
    }
    true
}

/// The admin-signed sigchain block labels (under tag scope `sigchain`) that
/// represent cluster membership / security events worth surfacing in the
/// audit log. Each maps to a meaningful `OpKind` below.
const SIGCHAIN_LABELS: &[&str] = &[
    "admin_genesis",
    "node_att",
    "agent_att",
    "agent_rev",
    "node_rev",
    "admin_admission",
    "admin_retirement",
    "grant_revocation",
    "bucket_merge",
    "token_redeem",
];

/// Whether a sigchain block under `label` can produce an `op_kind` record.
fn sigchain_label_has_kind(label: &str, op_kind: &OpKind) -> bool {
    match label {
        "token_redeem" => *op_kind == OpKind::TokenRedeem,
        "node_att" => *op_kind == OpKind::NodeAttest,
        "agent_att" => *op_kind == OpKind::AgentEnroll,
        "admin_genesis" => *op_kind == OpKind::ClusterGenesis,
        "agent_rev" => *op_kind == OpKind::AgentRevoke,
        "node_rev" => *op_kind == OpKind::NodeRevoke,
        "admin_admission" => *op_kind == OpKind::AdminAdmit,
        "admin_retirement" => *op_kind == OpKind::AdminRetire,
        "grant_revocation" => *op_kind == OpKind::GrantRevoke,
        "bucket_merge" => matches!(op_kind, OpKind::BucketMerge | OpKind::BucketUnmerge),
        _ => false,
    }
}

/// Every sigchain block since `after` as `(label, index ts, cid)`, newest
/// first. Index only: nothing is decoded, and nothing is capped (the set
/// decides which blocks the envelope scan skips).
fn sigchain_index(
    store: &MemvaultStore,
    after: u64,
) -> Result<Vec<(&'static str, u64, Vec<u8>)>, QueryError> {
    let mut out = Vec::new();
    for &label in SIGCHAIN_LABELS {
        let entries = store
            .query_by_tag_with_ts("sigchain", label, after, usize::MAX)
            .unwrap_or_default();
        out.extend(entries.into_iter().map(|(ts, cid)| (label, ts, cid)));
    }
    out.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(out)
}

/// Decode the sigchain blocks that match `query` into audit rows, newest
/// first, stopping once `limit` have matched. These blocks carry no
/// envelope-style `wall_ns`, so the index timestamp orders them — except a
/// merge record, whose own `created_ns` is authoritative; merge records are
/// therefore always decoded (they are rare). Best-effort: a block that fails
/// to decode is skipped (it won't appear, rather than as "unknown").
fn sigchain_records(
    store: &MemvaultStore,
    index: &[(&'static str, u64, Vec<u8>)],
    query: &AuditQuery,
    after: u64,
    before: u64,
    limit: usize,
) -> Result<Vec<AuditRecord>, QueryError> {
    let mut out = Vec::new();
    let mut matched_by_ts = 0usize;
    for (label, ts, cid) in index {
        let by_created = *label == "bucket_merge";
        if !by_created && (matched_by_ts >= limit || *ts < after || *ts > before) {
            continue;
        }
        if let Some(filter_kind) = &query.op_kind {
            if !sigchain_label_has_kind(label, filter_kind) {
                continue;
            }
        }
        let Some(data) = store.get_block(cid)? else {
            continue;
        };
        let Some(rec) = sigchain_record(store, label, cid.clone(), *ts, &data) else {
            continue;
        };
        if rec.wall_ns < after || rec.wall_ns > before {
            continue;
        }
        if let Some(filter_kind) = &query.op_kind {
            if &rec.op_kind != filter_kind {
                continue;
            }
        }
        if let Some(filter_author) = &query.author {
            if &rec.author != filter_author {
                continue;
            }
        }
        if !by_created {
            matched_by_ts += 1;
        }
        out.push(rec);
    }
    Ok(out)
}

/// Build one audit row for a sigchain block of the given `label`.
fn sigchain_record(
    store: &MemvaultStore,
    label: &str,
    cid: Vec<u8>,
    ts: u64,
    data: &[u8],
) -> Option<AuditRecord> {
    let mk = |op_kind: OpKind, author: Vec<u8>, tags: Vec<(String, String)>| AuditRecord {
        cid: cid.clone(),
        op_kind,
        author,
        agent_attestation: None,
        wall_ns: ts,
        doc_id: None,
        entity_id: None,
        attachment_cid: None,
        tags,
    };
    let role_str = |r: &memvault_auth::AgentRole| format!("{r:?}").to_lowercase();
    match label {
        "token_redeem" => {
            let tc =
                serde_ipld_dagcbor::from_slice::<memvault_auth::TokenConsumption>(data).ok()?;
            let att_cid = tc.issued_attestation.to_bytes();
            // Best-effort: classify the minted attestation for nicer display.
            let att_type = match store.get_block(&att_cid) {
                Ok(Some(b)) => {
                    if serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&b).is_ok()
                    {
                        "node"
                    } else if serde_ipld_dagcbor::from_slice::<memvault_auth::AgentAttestation>(&b)
                        .is_ok()
                    {
                        "agent"
                    } else {
                        "unknown"
                    }
                }
                _ => "unknown",
            };
            Some(mk(
                OpKind::TokenRedeem,
                tc.consumer.0.clone(),
                vec![
                    ("token".to_string(), hex::encode(tc.token_cid.to_bytes())),
                    ("attestation".to_string(), hex::encode(&att_cid)),
                    ("att_type".to_string(), att_type.to_string()),
                ],
            ))
        }
        "node_att" => {
            let na = serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(data).ok()?;
            Some(mk(
                OpKind::NodeAttest,
                na.member.0.clone(),
                vec![("member".to_string(), hex::encode(&na.member.0))],
            ))
        }
        "agent_att" => {
            let aa =
                serde_ipld_dagcbor::from_slice::<memvault_auth::AgentAttestation>(data).ok()?;
            Some(mk(
                OpKind::AgentEnroll,
                aa.agent_pubkey.to_vec(),
                vec![
                    ("agent".to_string(), aa.agent_id.0.clone()),
                    ("role".to_string(), role_str(&aa.role)),
                ],
            ))
        }
        "admin_genesis" => Some(mk(OpKind::ClusterGenesis, Vec::new(), Vec::new())),
        "agent_rev" => Some(mk(OpKind::AgentRevoke, Vec::new(), Vec::new())),
        "node_rev" => Some(mk(OpKind::NodeRevoke, Vec::new(), Vec::new())),
        "admin_admission" => Some(mk(OpKind::AdminAdmit, Vec::new(), Vec::new())),
        "admin_retirement" => Some(mk(OpKind::AdminRetire, Vec::new(), Vec::new())),
        "grant_revocation" => Some(mk(OpKind::GrantRevoke, Vec::new(), Vec::new())),
        "bucket_merge" => {
            let rec =
                serde_ipld_dagcbor::from_slice::<memvault_auth::BucketMergeRecord>(data).ok()?;
            // A retracted merge record is a reversed edge — surface it as
            // BucketUnmerge so the current state is legible; an active record
            // is a BucketMerge. The issuer is the audit author; the record's
            // created_ns is authoritative for ordering.
            let op_kind = if store.is_retracted(&cid).unwrap_or(false) {
                OpKind::BucketUnmerge
            } else {
                OpKind::BucketMerge
            };
            Some(AuditRecord {
                cid: cid.clone(),
                op_kind,
                author: rec.issued_by_pubkey.to_vec(),
                agent_attestation: None,
                wall_ns: rec.created_ns,
                doc_id: None,
                entity_id: None,
                attachment_cid: None,
                tags: vec![
                    ("source".to_string(), hex::encode(rec.source.0)),
                    ("canonical".to_string(), hex::encode(rec.canonical.0)),
                ],
            })
        }
        _ => None,
    }
}

/// Build the audit row for one envelope block from its head alone (see
/// [`AuditHead`]): `None` when the bytes are not an object.
pub fn parse_audit_block(cid: &[u8], data: &[u8]) -> Option<AuditRecord> {
    let head: AuditHead = memvault_store::deserialize_block_as(data)?;
    Some(parse_audit_record(cid, &head.into_value()))
}

/// The envelope fields an audit row shows, at the top level (legacy
/// raw-JSON and Signed<T> attribution) and inside `payload` (Signed<T>
/// kind-specific fields). Everything else — document bodies, patches,
/// extracted text, signatures — is skipped while decoding, not allocated.
#[derive(Default, Deserialize)]
struct AuditHead {
    #[serde(default)]
    author: Option<serde_json::Value>,
    #[serde(default)]
    agent_attestation: Option<serde_json::Value>,
    #[serde(default)]
    wall_ns: Option<serde_json::Value>,
    #[serde(default)]
    tags: Option<serde_json::Value>,
    #[serde(default)]
    kind: Option<serde_json::Value>,
    #[serde(default, rename = "type")]
    ann_type: Option<serde_json::Value>,
    #[serde(default)]
    manifest_cid: Option<serde_json::Value>,
    #[serde(default)]
    payload: PayloadHead,
}

/// Field names [`parse_audit_record`] reads through `EnvelopeView`, which
/// falls back from the top level into `payload`.
const AUDIT_FIELDS: &[&str] = &[
    "author",
    "agent_attestation",
    "wall_ns",
    "tags",
    "kind",
    "type",
    "manifest_cid",
];

/// The `Op` variants [`parse_audit_record`] recognises inside `payload`.
const AUDIT_VARIANTS: &[&str] = &[
    "DocCreate",
    "DocEdit",
    "AttachFile",
    "DetachFile",
    "EntityCreate",
    "EntityUpdate",
    "EntityDelete",
    "EdgeAdd",
    "EdgeRemove",
    "BucketCreate",
    "BucketRename",
    "AgentRename",
    "BucketAttach",
    "BucketArchive",
    "BucketBind",
];

impl AuditHead {
    /// The head as the (small) `Value` [`parse_audit_record`] reads.
    fn into_value(self) -> serde_json::Value {
        let mut top = serde_json::Map::new();
        let fields = [
            ("author", self.author),
            ("agent_attestation", self.agent_attestation),
            ("wall_ns", self.wall_ns),
            ("tags", self.tags),
            ("kind", self.kind),
            ("type", self.ann_type),
            ("manifest_cid", self.manifest_cid),
        ];
        for (name, value) in fields {
            if let Some(v) = value {
                top.insert(name.to_string(), v);
            }
        }
        if let Some(payload) = self.payload.0 {
            top.insert("payload".to_string(), serde_json::Value::Object(payload));
        }
        serde_json::Value::Object(top)
    }
}

/// `payload`, reduced to the audit fields and, per recognised `Op` variant,
/// its ids. A payload that isn't a map is ignored.
#[derive(Default)]
struct PayloadHead(Option<serde_json::Map<String, serde_json::Value>>);

/// One `Op` variant's ids: `doc_id`, `entity_id`, `entity.id`.
#[derive(Default)]
struct VariantIds(serde_json::Map<String, serde_json::Value>);

/// An entity's `id` only.
#[derive(Default)]
struct EntityIdOnly(Option<serde_json::Value>);

/// Implements `Deserialize` for a map-reading head type that reads maps with
/// `$visit_map` and skips any other value (yielding `Default`).
macro_rules! lenient_map_head {
    ($ty:ty, $what:expr, |$map:ident| $visit_map:block) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = $ty;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.write_str($what)
                    }
                    fn visit_map<A: serde::de::MapAccess<'de>>(
                        self,
                        mut $map: A,
                    ) -> Result<$ty, A::Error> {
                        $visit_map
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> Result<$ty, A::Error> {
                        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                        Ok(<$ty>::default())
                    }
                    fn visit_some<D2: serde::Deserializer<'de>>(
                        self,
                        d: D2,
                    ) -> Result<$ty, D2::Error> {
                        <$ty>::deserialize(d)
                    }
                    fn visit_none<E>(self) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_unit<E>(self) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_bool<E>(self, _: bool) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_i64<E>(self, _: i64) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_u64<E>(self, _: u64) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_i128<E>(self, _: i128) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_u128<E>(self, _: u128) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_f64<E>(self, _: f64) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_str<E>(self, _: &str) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                    fn visit_bytes<E>(self, _: &[u8]) -> Result<$ty, E> {
                        Ok(<$ty>::default())
                    }
                }
                d.deserialize_any(V)
            }
        }
    };
}

lenient_map_head!(PayloadHead, "an envelope payload", |map| {
    let mut out = serde_json::Map::new();
    while let Some(key) = map.next_key::<String>()? {
        if AUDIT_VARIANTS.contains(&key.as_str()) {
            let ids: VariantIds = map.next_value()?;
            out.insert(key, serde_json::Value::Object(ids.0));
        } else if AUDIT_FIELDS.contains(&key.as_str()) {
            let v: serde_json::Value = map.next_value()?;
            out.insert(key, v);
        } else {
            map.next_value::<serde::de::IgnoredAny>()?;
        }
    }
    Ok(PayloadHead(Some(out)))
});

lenient_map_head!(VariantIds, "an op variant", |map| {
    let mut out = serde_json::Map::new();
    while let Some(key) = map.next_key::<String>()? {
        match key.as_str() {
            "doc_id" | "entity_id" => {
                let v: serde_json::Value = map.next_value()?;
                out.insert(key, v);
            }
            "entity" => {
                if let EntityIdOnly(Some(id)) = map.next_value()? {
                    out.insert(key, serde_json::json!({ "id": id }));
                }
            }
            _ => {
                map.next_value::<serde::de::IgnoredAny>()?;
            }
        }
    }
    Ok(VariantIds(out))
});

lenient_map_head!(EntityIdOnly, "an entity", |map| {
    let mut id = None;
    while let Some(key) = map.next_key::<String>()? {
        if key == "id" {
            id = Some(map.next_value::<serde_json::Value>()?);
        } else {
            map.next_value::<serde::de::IgnoredAny>()?;
        }
    }
    Ok(EntityIdOnly(id))
});

pub fn parse_audit_record(cid: &[u8], val: &serde_json::Value) -> AuditRecord {
    let view = memvault_store::EnvelopeView::from_value(val.clone());

    let author: Vec<u8> = view.as_ref().map(|v| v.author()).unwrap_or_default();

    let wall_ns = view
        .as_ref()
        .and_then(|v| v.field("wall_ns").and_then(|x| x.as_u64()))
        .unwrap_or(0);

    // Signed<T> envelopes serialize `tags` as a list of `Tag` structs
    // (`[{"scope":"x","label":"y"}, …]`); the unsigned fallback path
    // uses nested arrays (`[["x","y"], …]`). Try the struct shape first,
    // fall back to the tuple shape so both round-trip into the
    // canonical `Vec<(String, String)>` representation.
    let tags: Vec<(String, String)> = view
        .as_ref()
        .and_then(|v| v.field("tags"))
        .and_then(|raw| {
            if let Ok(structured) = serde_json::from_value::<Vec<memvault_core::Tag>>(raw.clone()) {
                Some(structured.into_iter().map(|t| (t.scope, t.label)).collect())
            } else {
                serde_json::from_value::<Vec<(String, String)>>(raw.clone()).ok()
            }
        })
        .unwrap_or_default();

    // First try the Op-variant tags inside `payload` (the Signed<T>
    // shape that put_doc / add_entity / add_link etc. produce). If none
    // matches, FALL THROUGH to the kind/type/tag check below — the
    // previous version hard-returned Other("unknown") here, which made
    // every attachment envelope and every annotation (extraction,
    // tag_update, retraction) come back as Other("unknown") because
    // their payload object lacks any Op variant key.
    let payload_op_kind = val.get("payload").and_then(|p| {
        if p.get("DocCreate").is_some() {
            Some(OpKind::DocCreate)
        } else if p.get("DocEdit").is_some() {
            Some(OpKind::DocEdit)
        } else if p.get("AttachFile").is_some() {
            Some(OpKind::AttachFile)
        } else if p.get("DetachFile").is_some() {
            Some(OpKind::DetachFile)
        } else if p.get("EntityCreate").is_some() {
            Some(OpKind::EntityCreate)
        } else if p.get("EdgeAdd").is_some() {
            Some(OpKind::EdgeAdd)
        } else if p.get("EdgeRemove").is_some() {
            Some(OpKind::EdgeRemove)
        } else if p.get("BucketCreate").is_some() {
            Some(OpKind::BucketCreate)
        } else if p.get("BucketRename").is_some() {
            Some(OpKind::BucketRename)
        } else if p.get("AgentRename").is_some() {
            Some(OpKind::AgentRename)
        } else if p.get("BucketAttach").is_some() {
            Some(OpKind::BucketAttach)
        } else if p.get("BucketArchive").is_some() {
            Some(OpKind::BucketArchive)
        } else if p.get("BucketBind").is_some() {
            Some(OpKind::BucketBind)
        } else {
            None
        }
    });

    let op_kind = if let Some(k) = payload_op_kind {
        k
    } else {
        // EnvelopeView handles the legacy-vs-Signed<T> shape unification,
        // so the same match works whether `kind`/`type` live at the top
        // level (legacy raw JSON) or inside `payload` (Signed<T>).
        let kind = view.as_ref().and_then(|v| v.str_field("kind"));
        let ann_type = view.as_ref().and_then(|v| v.str_field("type"));
        let kind_tag = tags
            .iter()
            .find(|(s, _)| s == "kind")
            .map(|(_, l)| l.as_str());
        match (kind, ann_type, kind_tag) {
            (Some("annotation"), Some("retraction"), _) => OpKind::Retract,
            (Some("annotation"), Some("tag_update"), _) => OpKind::TagUpdate,
            (Some("annotation"), Some("extraction"), _) => OpKind::Extraction,
            (Some("annotation"), Some(t), _) => OpKind::Other(t.into()),
            (Some("attachment"), _, _) => OpKind::AttachFile,
            (Some("node_retraction"), _, _) => OpKind::Retract,
            (Some("tag_update"), _, _) => OpKind::TagUpdate,
            // Bucket ops stored without payload wrapper (legacy).
            (_, _, Some("bucket-decl")) => OpKind::BucketCreate,
            (_, _, Some("bucket-rename")) => OpKind::BucketRename,
            (_, _, Some("agent-rename")) => OpKind::AgentRename,
            (_, _, Some("bucket-archive")) => OpKind::BucketArchive,
            // View and token blocks.
            (_, _, Some("view")) => OpKind::ViewCreate,
            (_, _, Some("join-token")) => OpKind::TokenIssue,
            (_, _, Some("share-proposal")) => OpKind::SharePropose,
            (_, _, Some("share-decision")) => OpKind::ShareDecide,
            (Some(other), _, _) => OpKind::Other(other.into()),
            (None, _, Some(other)) => OpKind::Other(other.into()),
            _ => OpKind::Other("unknown".into()),
        }
    };

    let doc_id = val.get("payload").and_then(|p| {
        for key in ["DocCreate", "DocEdit", "AttachFile", "DetachFile"] {
            if let Some(inner) = p.get(key) {
                if let Some(did) = inner.get("doc_id") {
                    return serde_json::from_value::<DocId>(did.clone()).ok();
                }
            }
        }
        None
    });

    let entity_id = val.get("payload").and_then(|p| {
        for key in [
            "EntityCreate",
            "EntityUpdate",
            "EntityDelete",
            "EdgeAdd",
            "EdgeRemove",
        ] {
            if let Some(inner) = p.get(key) {
                // EntityCreate has entity.id, others have entity_id directly.
                let id_val = inner
                    .get("entity")
                    .and_then(|e| e.get("id"))
                    .or_else(|| inner.get("entity_id"));
                if let Some(id) = id_val {
                    return serde_json::from_value::<Vec<u8>>(id.clone()).ok();
                }
            }
        }
        None
    });

    let attachment_cid: Option<Vec<u8>> = view.as_ref().and_then(|v| v.get_as("manifest_cid"));

    // Agent attribution lives in `agent_attestation` on Signed<T> v3+
    // envelopes. Absent on legacy raw-JSON envelopes (None).
    let agent_attestation: Option<Vec<u8>> = view.as_ref().and_then(|v| v.agent_attestation_cid());

    AuditRecord {
        cid: cid.to_vec(),
        op_kind,
        author,
        agent_attestation,
        wall_ns,
        doc_id,
        entity_id,
        attachment_cid,
        tags,
    }
}
