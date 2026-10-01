//! Which declaration is a bucket's current one.
//!
//! A bucket's metadata (name, owners, attachment, archive marker) is the
//! payload of its latest *authorised* `BucketCreate` declaration. The
//! `BUCKETS` table only caches the pointer; this module decides it from the
//! decl blocks themselves, the same way on every node and independent of
//! the order blocks arrived in:
//!
//! 1. Candidates are every block tagged `("bucket", <id>)` that parses as a
//!    declaration of that bucket, plus the current pointer.
//! 2. A signed decl counts only if its node signature verifies against its
//!    author (and its agent co-signature, when present). A forged or
//!    tampered decl is ignored.
//! 3. Signed decls are ordered by `(wall_ns, cid)`. The first one whose
//!    signer may create buckets ([`DeclAuthority::may_create`]) is the
//!    genesis; each later decl applies only if a signer is an owner
//!    (the genesis signers, or the owner keys the current decl names) or
//!    an admin at that time. The last applied decl is current.
//! 4. A bucket with no authorised signed decl keeps the legacy behaviour:
//!    the current pointer if it is one of its unsigned decls, else the
//!    newest unsigned decl by `(wall_ns, cid)`.

use std::collections::HashSet;

use memvault_core::{BucketDecl, Signed};

use crate::MemvaultStore;
use crate::error::StoreError;

/// Who may declare and update buckets. Implemented by the API client
/// (local trust state) and the sync gate (pinned admin + attested nodes).
pub trait DeclAuthority {
    /// May `signer` (a node or agent pubkey) create a bucket? Typically a
    /// trusted cluster node, this node itself, or an admin.
    fn may_create(&self, signer: &[u8; 32]) -> bool;
    /// Is `signer` a cluster admin at `at_ns`? Admins may update any bucket.
    fn is_admin(&self, signer: &[u8; 32], at_ns: u64) -> bool;
}

/// One parsed declaration of a bucket.
#[derive(Debug, Clone)]
pub struct DeclCandidate {
    pub cid: Vec<u8>,
    pub decl: BucketDecl,
    pub wall_ns: u64,
    /// Keys whose signatures on the decl verified (node author, plus the
    /// agent co-signer when present). Empty for an unsigned legacy decl.
    pub signers: Vec<[u8; 32]>,
}

impl DeclCandidate {
    fn is_signed(&self) -> bool {
        !self.signers.is_empty()
    }
}

/// Parse a block as a bucket declaration. Handles the signed
/// `Signed<{BucketCreate: decl}>` envelope, the unsigned legacy envelope
/// (`payload.BucketCreate` without a signature) and the bare legacy
/// `BucketDecl`. Returns `None` for anything else, and for a signed decl
/// whose signature does not verify.
pub fn parse_decl(store: &MemvaultStore, cid: &[u8], bytes: &[u8]) -> Option<DeclCandidate> {
    if let Some(signed) = crate::deserialize_block_as::<Signed<serde_json::Value>>(bytes) {
        if !signed.signature.is_empty() {
            let decl: BucketDecl =
                serde_json::from_value(signed.payload.get("BucketCreate")?.clone()).ok()?;
            let node = signed.verify_by_author()?;
            let mut signers = vec![node];
            // The agent co-signer counts once its attestation is known; a
            // co-signature that fails against it marks the decl forged.
            // (Until the attestation syncs, the node signature stands alone.)
            if !signed.agent_signature.is_empty() {
                if let Some(agent) = signed
                    .agent_attestation
                    .as_deref()
                    .and_then(|att| agent_pubkey_of(store, att))
                {
                    if !signed.verify_agent_pubkey(&agent) {
                        return None;
                    }
                    signers.push(agent);
                }
            }
            return Some(DeclCandidate {
                cid: cid.to_vec(),
                decl,
                wall_ns: signed.wall_ns,
                signers,
            });
        }
    }
    let val = crate::deserialize_block(bytes)?;
    let (decl_val, wall_ns) = match val.get("payload").and_then(|p| p.get("BucketCreate")) {
        Some(bc) => (
            bc.clone(),
            val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0),
        ),
        None => (val.clone(), 0),
    };
    let decl: BucketDecl = serde_json::from_value(decl_val).ok()?;
    let wall_ns = if wall_ns == 0 {
        decl.created_ns
    } else {
        wall_ns
    };
    Some(DeclCandidate {
        cid: cid.to_vec(),
        decl,
        wall_ns,
        signers: Vec::new(),
    })
}

/// The agent pubkey an `AgentAttestation` block names.
fn agent_pubkey_of(store: &MemvaultStore, attestation_cid: &[u8]) -> Option<[u8; 32]> {
    let bytes = store.get_block(attestation_cid).ok()??;
    let val = crate::deserialize_block(&bytes)?;
    serde_json::from_value(val.get("agent_pubkey")?.clone()).ok()
}

fn owners_of(genesis: &DeclCandidate, current: &DeclCandidate) -> HashSet<[u8; 32]> {
    let mut owners: HashSet<[u8; 32]> = genesis.signers.iter().copied().collect();
    owners.extend(current.decl.owner_agent_pubkey);
    owners.extend(current.decl.owner_node_pubkey);
    owners
}

/// Choose the current declaration among `candidates` (see the module docs).
/// `current` is the pointer the store holds now. Pure and deterministic:
/// the result does not depend on the order of `candidates`.
pub fn choose_decl(
    candidates: &[DeclCandidate],
    current: Option<&[u8]>,
    authority: &dyn DeclAuthority,
) -> Option<Vec<u8>> {
    let mut signed: Vec<&DeclCandidate> = candidates.iter().filter(|c| c.is_signed()).collect();
    signed.sort_by(|a, b| a.wall_ns.cmp(&b.wall_ns).then_with(|| a.cid.cmp(&b.cid)));
    let genesis = signed.iter().position(|c| {
        c.signers
            .iter()
            .any(|s| authority.may_create(s) || authority.is_admin(s, c.wall_ns))
    });
    if let Some(g) = genesis {
        let genesis = signed[g];
        let mut cur = genesis;
        for c in &signed[g + 1..] {
            let owners = owners_of(genesis, cur);
            if c.signers
                .iter()
                .any(|s| owners.contains(s) || authority.is_admin(s, c.wall_ns))
            {
                cur = c;
            }
        }
        return Some(cur.cid.clone());
    }

    let unsigned: Vec<&DeclCandidate> = candidates.iter().filter(|c| !c.is_signed()).collect();
    if let Some(cur) = current {
        if unsigned.iter().any(|c| c.cid == cur) {
            return Some(cur.to_vec());
        }
    }
    if let Some(best) = unsigned
        .iter()
        .max_by(|a, b| a.wall_ns.cmp(&b.wall_ns).then_with(|| a.cid.cmp(&b.cid)))
    {
        return Some(best.cid.clone());
    }
    current.map(|c| c.to_vec())
}

impl MemvaultStore {
    /// Every parseable declaration of `bucket_id` this store holds: blocks
    /// tagged `("bucket", <id>)` plus the current pointer. Exhaustive (the
    /// current decl may be any of them).
    pub fn bucket_decl_candidates(
        &self,
        bucket_id: &[u8; 32],
    ) -> Result<Vec<DeclCandidate>, StoreError> {
        let label = memvault_core::BucketId(*bucket_id).to_string();
        let mut cids = self.query_by_tag("bucket", &label, 0, usize::MAX)?;
        if let Some(cur) = self.get_bucket(bucket_id)? {
            cids.push(cur);
        }
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for cid in cids {
            if !seen.insert(cid.clone()) {
                continue;
            }
            let Some(bytes) = self.get_block(&cid)? else {
                continue;
            };
            if let Some(c) = parse_decl(self, &cid, &bytes) {
                if c.decl.bucket_id.0 == *bucket_id {
                    out.push(c);
                }
            }
        }
        Ok(out)
    }

    /// Recompute which declaration is current for `bucket_id` and move the
    /// `BUCKETS` pointer to it. Returns the current decl CID, if any.
    pub fn resolve_bucket_decl(
        &self,
        bucket_id: &[u8; 32],
        authority: &dyn DeclAuthority,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let candidates = self.bucket_decl_candidates(bucket_id)?;
        let current = self.get_bucket(bucket_id)?;
        let chosen = choose_decl(&candidates, current.as_deref(), authority);
        if let Some(c) = &chosen {
            if current.as_deref() != Some(c.as_slice()) {
                self.put_bucket(bucket_id, c)?;
            }
        }
        Ok(chosen)
    }

    /// [`Self::resolve_bucket_decl`] for every known bucket.
    pub fn resolve_all_bucket_decls(
        &self,
        authority: &dyn DeclAuthority,
    ) -> Result<usize, StoreError> {
        let mut n = 0;
        for (bid, _) in self.list_buckets()? {
            let Ok(bid) = <[u8; 32]>::try_from(bid.as_slice()) else {
                continue;
            };
            self.resolve_bucket_decl(&bid, authority)?;
            n += 1;
        }
        Ok(n)
    }
}
