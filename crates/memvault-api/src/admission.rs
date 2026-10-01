//! Admission of blocks into the store.
//!
//! Every block enters through `MemvaultStore::ingest_block`
//! (`standards/block-ingestion.md`). What differs by provenance is the gate
//! in front of it, and this module is that gate for both sides:
//!
//! - [`classify_record`] is the one place that knows how a bare-struct
//!   sigchain record (`NodeAttestation`, `Grant`, `BucketMergeRecord`,
//!   `TokenConsumption`, …) is verified and indexed. The index metadata is
//!   derived from the record itself — author is the embedded (or verified)
//!   signer, `wall_ns` the record's own timestamp, the bucket the record's
//!   bucket — so a local write, a synced copy and a rebuild produce the
//!   same index entries.
//! - [`SyncGate`] admits blocks from a peer: CID check, signature check of
//!   bare records against the cluster's admin and node keys, ingest, and
//!   the derived-state follow-ups (bucket declaration resolution).

use std::cell::OnceCell;
use std::collections::HashSet;

use memvault_auth::SigchainKind;
use memvault_store::{DeclAuthority, IngestMeta, MemvaultStore};

/// How a bare record that fails verification is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Sync ingress: unverifiable records are dropped.
    Verify,
    /// The record is already ours (local mint, rebuild, uncluster): never
    /// drop; derive what can be derived (an unknown signer leaves the
    /// author empty).
    Trusted,
}

/// Keys bare records are checked against.
#[derive(Debug, Clone, Default)]
pub struct RecordKeys {
    pub cluster_id: [u8; 32],
    /// The pinned admin anchor, if this node has one.
    pub anchor: Option<[u8; 32]>,
    /// Every admin key the admission chain establishes (anchor first).
    pub admin_keys: Vec<[u8; 32]>,
    /// Admin-attested cluster node keys (and this node's own key).
    pub node_keys: Vec<[u8; 32]>,
}

/// Index metadata for an admitted bare record.
#[derive(Debug, Clone)]
pub struct RecordMeta {
    pub kind: SigchainKind,
    /// The signer: embedded in the record, or the key that verified it.
    pub author: Vec<u8>,
    /// The record's own timestamp (0 when it carries none), so every node
    /// files the record under the same time.
    pub wall_ns: u64,
    pub bucket_id: Option<Vec<u8>>,
    /// `("sigchain", <label>)` plus the lookup tags readers query by.
    pub tags: Vec<(String, String)>,
}

impl RecordMeta {
    /// The [`IngestMeta`] for this record. `cluster_id` is the receiving
    /// node's cluster stamp.
    pub fn ingest_meta(&self, cluster_id: Option<Vec<u8>>) -> IngestMeta {
        IngestMeta {
            cluster_id,
            extra_tags: self.tags.clone(),
            author: (!self.author.is_empty()).then(|| self.author.clone()),
            wall_ns: (self.wall_ns != 0).then_some(self.wall_ns),
            bucket_id: self.bucket_id.clone(),
            ..Default::default()
        }
    }
}

/// Outcome of [`classify_record`].
#[derive(Debug)]
pub enum RecordVerdict {
    /// Not a bare sigchain record (an envelope, a chunk, …).
    NotRecord,
    /// A record that failed verification ([`Mode::Verify`] only).
    Drop(&'static str),
    Accept(RecordMeta),
}

fn first_verifying(
    keys: &[[u8; 32]],
    verify: impl Fn(&ed25519_dalek::VerifyingKey) -> bool,
) -> Option<[u8; 32]> {
    keys.iter().copied().find(|k| {
        ed25519_dalek::VerifyingKey::from_bytes(k)
            .map(|vk| verify(&vk))
            .unwrap_or(false)
    })
}

/// Recognise, verify and derive index metadata for a bare sigchain record.
/// The single source of truth for the sync classifier, local writers,
/// `rebuild_store` and `memctl uncluster`.
pub fn classify_record(
    store: &MemvaultStore,
    bytes: &[u8],
    keys: &RecordKeys,
    mode: Mode,
) -> RecordVerdict {
    use RecordVerdict::{Accept, Drop, NotRecord};
    let Some(kind) = memvault_auth::detect_sigchain_shape(bytes) else {
        return NotRecord;
    };
    let verify = mode == Mode::Verify;
    let cluster_ok = |c: &[u8; 32]| !verify || *c == keys.cluster_id;
    let meta = |author: Vec<u8>, wall_ns: u64| RecordMeta {
        kind,
        author,
        wall_ns,
        bucket_id: None,
        tags: vec![("sigchain".to_string(), kind.label().to_string())],
    };
    let decode_failed = Drop("record does not decode");

    match kind {
        SigchainKind::AdminGenesis => {
            let Ok(g) = serde_ipld_dagcbor::from_slice::<memvault_auth::AdminGenesis>(bytes) else {
                return decode_failed;
            };
            if verify {
                if !cluster_ok(&g.cluster_id.0) || g.verify_self_signature().is_err() {
                    return Drop("admin_genesis: foreign cluster or bad self-signature");
                }
                // Only the pinned anchor's genesis is the cluster's; any
                // other self-signed genesis is a rival root of trust.
                if keys.anchor.is_some_and(|a| a != g.admin_pubkey) {
                    return Drop("admin_genesis: not the pinned admin");
                }
            }
            Accept(meta(g.admin_pubkey.to_vec(), g.created_ns))
        }
        SigchainKind::AdminKeyAdmission => {
            let Ok(adm) = serde_ipld_dagcbor::from_slice::<memvault_auth::AdminKeyAdmission>(bytes)
            else {
                return decode_failed;
            };
            // "Admitting key was an admin at admission time" is checked by
            // `admin_key_state_from_store`, which orders the whole chain.
            if verify && (!cluster_ok(&adm.cluster_id.0) || adm.verify().is_err()) {
                return Drop("admin_admission: foreign cluster, bad signature or POP");
            }
            Accept(meta(adm.admitting_pubkey.to_vec(), adm.admitted_at_ns))
        }
        SigchainKind::AdminKeyRetirement => {
            let Ok(ret) =
                serde_ipld_dagcbor::from_slice::<memvault_auth::AdminKeyRetirement>(bytes)
            else {
                return decode_failed;
            };
            if verify
                && (!cluster_ok(&ret.cluster_id.0) || ret.verify_retiring_signature().is_err())
            {
                return Drop("admin_retirement: foreign cluster or bad signature");
            }
            Accept(meta(ret.retiring_pubkey.to_vec(), ret.retired_at_ns))
        }
        SigchainKind::NodeAttestation => {
            let Ok(att) = serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(bytes)
            else {
                return decode_failed;
            };
            if !cluster_ok(&att.cluster_id.0) {
                return Drop("node_att: foreign cluster");
            }
            // Admin-signed: the signer must be the anchor or an admin the
            // admission chain admits. The record names no signer, so the
            // verifying admin is the author.
            let signer = first_verifying(&keys.admin_keys, |vk| att.verify_signature(vk).is_ok());
            if verify && signer.is_none() {
                return Drop("node_att: signed by no known admin");
            }
            Accept(meta(signer.map(|k| k.to_vec()).unwrap_or_default(), 0))
        }
        SigchainKind::AgentAttestation => {
            let Ok(att) = serde_ipld_dagcbor::from_slice::<memvault_auth::AgentAttestation>(bytes)
            else {
                return decode_failed;
            };
            // Node-signed; whether the node is trusted is decided by
            // `scan_trusted_agents` (a record from an untrusted node is
            // inert).
            if verify && att.verify_signature().is_err() {
                return Drop("agent_att: bad node signature");
            }
            Accept(meta(att.node_pubkey.to_vec(), 0))
        }
        SigchainKind::AgentRevocation => {
            let Ok(rev) = serde_ipld_dagcbor::from_slice::<memvault_auth::AgentRevocation>(bytes)
            else {
                return decode_failed;
            };
            if verify && rev.verify_signature().is_err() {
                return Drop("agent_rev: bad node signature");
            }
            Accept(meta(rev.node_pubkey.to_vec(), rev.revoked_at_ns))
        }
        SigchainKind::NodeRevocation => {
            let Ok(rev) = serde_ipld_dagcbor::from_slice::<memvault_auth::NodeRevocation>(bytes)
            else {
                return decode_failed;
            };
            if verify && rev.verify_signature().is_err() {
                return Drop("node_rev: bad self-signature");
            }
            Accept(meta(rev.admin_pubkey.to_vec(), rev.revoked_at_ns))
        }
        SigchainKind::GrantRevocation => {
            let Ok(rev) = serde_ipld_dagcbor::from_slice::<memvault_auth::GrantRevocation>(bytes)
            else {
                return decode_failed;
            };
            if verify && rev.verify_signature().is_err() {
                return Drop("grant_revocation: bad self-signature");
            }
            Accept(meta(rev.admin_pubkey.to_vec(), rev.revoked_at_ns))
        }
        SigchainKind::Grant => {
            let Ok(grant) = serde_ipld_dagcbor::from_slice::<memvault_auth::Grant>(bytes) else {
                return decode_failed;
            };
            // Issuer authority for the bucket is checked per lookup by ACL.
            if verify && grant.verify_admin_signature().is_err() {
                return Drop("grant: unsigned or bad self-signature");
            }
            let mut m = meta(grant.admin_pubkey.to_vec(), grant.not_before_ns);
            m.tags.push(("kind".to_string(), "grant".to_string()));
            // Grants scope exactly one bucket (enforced on issue + submit).
            if let [bid] = grant.bucket_scopes.as_slice() {
                m.tags.push(("grant".to_string(), hex::encode(bid.0)));
                m.bucket_id = Some(bid.0.to_vec());
            }
            Accept(m)
        }
        SigchainKind::BucketMerge => {
            let Ok(rec) = serde_ipld_dagcbor::from_slice::<memvault_auth::BucketMergeRecord>(bytes)
            else {
                return decode_failed;
            };
            if verify && rec.verify_signature().is_err() {
                return Drop("bucket_merge: bad signature");
            }
            let mut m = meta(rec.issued_by_pubkey.to_vec(), rec.created_ns);
            m.tags
                .push(("bucket_merge".to_string(), hex::encode(rec.source.0)));
            m.tags
                .push(("kind".to_string(), "bucket_merge".to_string()));
            // Homed on the canonical, the bucket the record governs.
            m.bucket_id = Some(rec.canonical.0.to_vec());
            Accept(m)
        }
        SigchainKind::TokenConsumption => {
            let Ok(tc) = serde_ipld_dagcbor::from_slice::<memvault_auth::TokenConsumption>(bytes)
            else {
                return decode_failed;
            };
            // Signed by the attesting authority: an admin for a node join,
            // the enrolling node for an agent enrolment (the node that
            // signed the minted AgentAttestation, when we hold it).
            let mut candidates = keys.admin_keys.clone();
            candidates.extend(keys.node_keys.iter().copied());
            if let Ok(Some(att)) = store.get_block(&tc.issued_attestation.to_bytes()) {
                if let Ok(a) =
                    serde_ipld_dagcbor::from_slice::<memvault_auth::AgentAttestation>(&att)
                {
                    candidates.push(a.node_pubkey);
                }
            }
            let signer = first_verifying(&candidates, |vk| tc.verify_signature(vk).is_ok());
            if verify && signer.is_none() {
                return Drop("token_redeem: signed by no known admin or node");
            }
            let mut m = meta(
                signer.map(|k| k.to_vec()).unwrap_or_default(),
                tc.consumed_at_ns,
            );
            m.tags.push((
                "token_redeem".to_string(),
                hex::encode(tc.token_cid.to_bytes()),
            ));
            Accept(m)
        }
        SigchainKind::BucketTrust => {
            let Ok(trust) = serde_ipld_dagcbor::from_slice::<memvault_auth::BucketTrust>(bytes)
            else {
                return decode_failed;
            };
            // Issued by an admin of the approving cluster (this one).
            let signer = first_verifying(&keys.admin_keys, |vk| trust.verify_signature(vk).is_ok());
            if verify && (!cluster_ok(&trust.to_cluster.0) || signer.is_none()) {
                return Drop("bucket_trust: not issued by an admin of this cluster");
            }
            let mut m = meta(signer.map(|k| k.to_vec()).unwrap_or_default(), 0);
            m.tags
                .push(("kind".to_string(), "bucket-trust".to_string()));
            m.bucket_id = Some(trust.bucket_id.0.to_vec());
            Accept(m)
        }
    }
}

/// Admin keys (anchor first) the admission chain in `store` establishes.
pub fn admin_keys_from_store(
    store: &MemvaultStore,
    cluster_id: &[u8],
    anchor: Option<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let Some(anchor) = anchor else {
        return Vec::new();
    };
    let state = crate::sigchain::admin_key_state_from_store(store, cluster_id, anchor)
        .unwrap_or_else(|_| memvault_auth::AdminKeyState::new_with_bootstrap(anchor, 0));
    let mut keys = vec![anchor];
    keys.extend(state.keys.keys().copied().filter(|k| *k != anchor));
    keys
}

/// Node keys named by a `NodeAttestation` that one of `admin_keys` signed.
/// Exhaustive.
pub fn attested_nodes_from_store(
    store: &MemvaultStore,
    cluster_id: &[u8],
    admin_keys: &[[u8; 32]],
) -> HashSet<[u8; 32]> {
    let mut out = HashSet::new();
    if admin_keys.is_empty() {
        return out;
    }
    let Ok(blocks) = crate::sigchain::load_store_blocks_by_label(store, "node_att") else {
        return out;
    };
    for bytes in blocks {
        let Ok(att) = serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&bytes)
        else {
            continue;
        };
        if att.cluster_id.0.as_slice() != cluster_id {
            continue;
        }
        let Ok(member) = <[u8; 32]>::try_from(att.member.0.as_slice()) else {
            continue;
        };
        if first_verifying(admin_keys, |vk| att.verify_signature(vk).is_ok()).is_some() {
            out.insert(member);
        }
    }
    out
}

/// What [`SyncGate::admit`] did with a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// Stored. `record` is the bare-record kind, if it was one.
    Stored { record: Option<SigchainKind> },
    /// Already held; nothing written (re-ingesting would duplicate index
    /// entries for records whose metadata isn't in the bytes).
    AlreadyHeld,
    /// Refused: CID mismatch, failed verification, or a store error.
    Dropped(String),
}

/// The admission gate for blocks received from a peer (block exchange and
/// the join bootstrap bundle). Keys are computed from the store on first
/// use and refreshed after an admission or attestation lands.
pub struct SyncGate<'a> {
    store: &'a MemvaultStore,
    cluster_id: [u8; 32],
    anchor: Option<[u8; 32]>,
    keys: OnceCell<RecordKeys>,
}

impl<'a> SyncGate<'a> {
    pub fn new(store: &'a MemvaultStore, cluster_id: [u8; 32], anchor: Option<[u8; 32]>) -> Self {
        Self {
            store,
            cluster_id,
            anchor,
            keys: OnceCell::new(),
        }
    }

    /// The admin and node keys records are verified against.
    pub fn keys(&self) -> &RecordKeys {
        self.keys.get_or_init(|| {
            let admin_keys = admin_keys_from_store(self.store, &self.cluster_id, self.anchor);
            let node_keys = attested_nodes_from_store(self.store, &self.cluster_id, &admin_keys)
                .into_iter()
                .collect();
            RecordKeys {
                cluster_id: self.cluster_id,
                anchor: self.anchor,
                admin_keys,
                node_keys,
            }
        })
    }

    /// Recompute keys on next use (an admin admission/retirement or node
    /// attestation was just admitted).
    pub fn refresh(&mut self) {
        self.keys = OnceCell::new();
    }

    /// Decide how a synced block is ingested: `Err(reason)` drops it.
    /// Ordinary content (envelopes, chunks) carries its own metadata, so
    /// only the receiving cluster is stamped.
    pub fn vet(&self, bytes: &[u8]) -> Result<(IngestMeta, Option<SigchainKind>), &'static str> {
        match classify_record(self.store, bytes, self.keys(), Mode::Verify) {
            RecordVerdict::NotRecord => Ok((
                IngestMeta {
                    cluster_id: Some(self.cluster_id.to_vec()),
                    ..Default::default()
                },
                None,
            )),
            RecordVerdict::Drop(reason) => Err(reason),
            RecordVerdict::Accept(m) => {
                Ok((m.ingest_meta(Some(self.cluster_id.to_vec())), Some(m.kind)))
            }
        }
    }

    /// Admit one synced block: content-address check, verification, the
    /// single ingest path, then derived-state follow-ups.
    pub fn admit(&mut self, cid: &[u8], bytes: &[u8]) -> Admitted {
        if self.store.has_block(cid).unwrap_or(false) {
            return Admitted::AlreadyHeld;
        }
        if !matches!(memvault_core::verify_cid(cid, bytes), Ok(true)) {
            return Admitted::Dropped("bytes do not hash to the claimed CID".into());
        }
        let (meta, record) = match self.vet(bytes) {
            Ok(v) => v,
            Err(reason) => return Admitted::Dropped(reason.into()),
        };
        if let Err(e) = self.store.ingest_block(cid, bytes, &meta) {
            return Admitted::Dropped(format!("ingest failed: {e}"));
        }
        match record {
            Some(
                SigchainKind::AdminKeyAdmission
                | SigchainKind::AdminKeyRetirement
                | SigchainKind::NodeAttestation,
            ) => {
                // Trust changed: re-verify later records against the new
                // key set, and re-decide every bucket's current decl (a
                // newly trusted node may make its decls authoritative).
                self.refresh();
                let _ = self.store.resolve_all_bucket_decls(&*self);
            }
            Some(_) => {}
            None => {
                // Only a decl (tagged `kind=bucket-decl`) can move a bucket's
                // pointer; skip decoding every other block a second time.
                let maybe_decl = bytes.windows(11).any(|w| w == b"bucket-decl");
                if let Some(c) = maybe_decl
                    .then(|| memvault_store::bucket_decl::parse_decl(self.store, cid, bytes))
                    .flatten()
                {
                    let _ = self.store.resolve_bucket_decl(&c.decl.bucket_id.0, &*self);
                }
            }
        }
        Admitted::Stored { record }
    }
}

impl SyncGate<'_> {
    /// [`Self::admit`] restricted to bare sigchain records — for the join
    /// bootstrap bundle, which must not carry arbitrary content.
    pub fn admit_record(&mut self, cid: &[u8], bytes: &[u8]) -> Admitted {
        if memvault_auth::detect_sigchain_shape(bytes).is_none() {
            return Admitted::Dropped("not a sigchain record".into());
        }
        self.admit(cid, bytes)
    }
}

/// Store a bare record this node minted (e.g. the admin minting a
/// `NodeAttestation` for a join), indexed exactly as a peer receiving it
/// would index it. Idempotent; returns the record's CID.
pub fn ingest_minted_record(
    store: &MemvaultStore,
    bytes: &[u8],
    keys: &RecordKeys,
) -> Result<Vec<u8>, memvault_store::StoreError> {
    let cid = memvault_core::cid_from_bytes(bytes).to_bytes();
    if store.has_block(&cid)? {
        return Ok(cid);
    }
    let RecordVerdict::Accept(meta) = classify_record(store, bytes, keys, Mode::Trusted) else {
        return Err(memvault_store::StoreError::Other(
            "not a recognised sigchain record".into(),
        ));
    };
    store.ingest_block(
        &cid,
        bytes,
        &meta.ingest_meta(Some(keys.cluster_id.to_vec())),
    )?;
    Ok(cid)
}

/// Re-derive the index entries of a block already in the store: a bare
/// sigchain record gets its record-derived metadata, anything else the
/// metadata its bytes carry. Shared by `rebuild_store` and
/// `memctl uncluster`. Returns whether anything was indexed.
pub fn reindex_any_block(
    store: &MemvaultStore,
    cid: &[u8],
    bytes: &[u8],
    keys: &RecordKeys,
) -> bool {
    // Envelopes carry their own metadata (and records carry none, so the
    // plain reindex writes nothing for them).
    if store.reindex_block(cid, bytes).unwrap_or(false) {
        return true;
    }
    let cluster = (keys.cluster_id != [0u8; 32]).then(|| keys.cluster_id.to_vec());
    match classify_record(store, bytes, keys, Mode::Trusted) {
        RecordVerdict::Accept(m) => store
            .reindex_block_with(cid, bytes, &m.ingest_meta(cluster))
            .unwrap_or(false),
        _ => false,
    }
}

/// The time a block carries: an envelope's `wall_ns`, else a bare record's
/// own timestamp, else 0. Never the clock — used to date derived blocks
/// (migrations, repairs) deterministically.
pub fn block_wall_ns(store: &MemvaultStore, bytes: &[u8]) -> u64 {
    if let Some(w) = memvault_store::EnvelopeView::parse(bytes)
        .and_then(|v| v.field("wall_ns").and_then(|w| w.as_u64()))
    {
        return w;
    }
    match classify_record(store, bytes, &RecordKeys::default(), Mode::Trusted) {
        RecordVerdict::Accept(m) => m.wall_ns,
        _ => 0,
    }
}

/// How many times a join token has been redeemed, counted from the signed
/// `TokenConsumption` blocks (`("token_redeem", <token cid>)`) — the
/// cluster-wide record, which syncs. Local counters are a cache over this.
pub fn token_redemptions(store: &MemvaultStore, token_cid: &[u8]) -> u32 {
    let cids = store
        .query_by_tag("token_redeem", &hex::encode(token_cid), 0, usize::MAX)
        .unwrap_or_default();
    let distinct: HashSet<Vec<u8>> = cids.into_iter().collect();
    u32::try_from(distinct.len()).unwrap_or(u32::MAX)
}

impl DeclAuthority for SyncGate<'_> {
    fn may_create(&self, signer: &[u8; 32]) -> bool {
        // Pre-genesis (no anchor) there is no trust root to check against.
        self.anchor.is_none()
            || self.keys().node_keys.contains(signer)
            || self.keys().admin_keys.contains(signer)
    }

    fn is_admin(&self, signer: &[u8; 32], _at_ns: u64) -> bool {
        self.keys().admin_keys.contains(signer)
    }
}

impl crate::LocalClient {
    /// The keys this node verifies bare records against: every admin key
    /// it knows or holds, and every trusted node key including its own.
    pub fn record_keys(&self) -> RecordKeys {
        let cluster_id = <[u8; 32]>::try_from(self.cluster_id()).unwrap_or([0u8; 32]);
        let mut admin_keys: Vec<[u8; 32]> = self
            .admin_verifying_keys()
            .iter()
            .map(|k| k.to_bytes())
            .collect();
        if let Some(k) = self.admin_verifying_key() {
            if !admin_keys.contains(&k.to_bytes()) {
                admin_keys.push(k.to_bytes());
            }
        }
        let mut node_keys: Vec<[u8; 32]> = self
            .node_verifying_key()
            .map(|k| vec![k.to_bytes()])
            .unwrap_or_default();
        node_keys.extend(attested_nodes_from_store(
            self.store(),
            &cluster_id,
            &admin_keys,
        ));
        RecordKeys {
            cluster_id,
            anchor: admin_keys.first().copied(),
            admin_keys,
            node_keys,
        }
    }

    /// Store a bare sigchain record this node minted (or already holds),
    /// indexed exactly as a peer receiving it would index it. Idempotent:
    /// a record already in the store is left alone. Returns its CID.
    pub fn ingest_record(&self, bytes: &[u8]) -> crate::Result<Vec<u8>> {
        let cid = memvault_core::cid_from_bytes(bytes).to_bytes();
        if self.store().has_block(&cid)? {
            return Ok(cid);
        }
        let meta = match classify_record(self.store(), bytes, &self.record_keys(), Mode::Trusted) {
            RecordVerdict::Accept(m) => m,
            _ => {
                return Err(crate::ApiError::Other(
                    "not a recognised sigchain record".into(),
                ));
            }
        };
        self.store().ingest_block(
            &cid,
            bytes,
            &meta.ingest_meta(Some(self.cluster_id().to_vec())),
        )?;
        Ok(cid)
    }

    /// Re-decide the current declaration of `bucket_id` from its decl
    /// blocks (see `memvault_store::bucket_decl`).
    pub fn resolve_bucket_decl(&self, bucket_id: &memvault_core::BucketId) -> crate::Result<()> {
        self.store()
            .resolve_bucket_decl(&bucket_id.0, &ClientDeclAuthority(self))?;
        Ok(())
    }
}

/// [`DeclAuthority`] from a client's live trust state.
pub struct ClientDeclAuthority<'a>(pub &'a crate::LocalClient);

impl DeclAuthority for ClientDeclAuthority<'_> {
    fn may_create(&self, signer: &[u8; 32]) -> bool {
        self.0.is_attesting_node_trusted(signer)
            || self
                .0
                .is_admin_key_valid_at(signer, memvault_core::wall_ns())
    }

    fn is_admin(&self, signer: &[u8; 32], at_ns: u64) -> bool {
        self.0.is_admin_key_valid_at(signer, at_ns)
    }
}
