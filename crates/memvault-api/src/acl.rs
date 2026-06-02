//! Bucket-level access control enforcement.
//!
//! Grants live on the sigchain as signed `Grant` envelopes (see
//! `LocalClient::issue_bucket_grant`). This module reads them and decides
//! whether a caller — identified by their verified ed25519 pubkey — is
//! authorised for a given action on a target bucket.
//!
//! The check is currently invoked from HTTP write handlers. Local-only
//! callers (UI server fns, daemon-internal tasks) bypass it.

use memvault_auth::{Action, GrantAudience};
use memvault_core::BucketId;

use crate::LocalClient;
use crate::error::{ApiError, Result};

/// Authoritative decision: caller `agent_pubkey` may perform `action`
/// on `bucket_id`?
///
/// Returns `Ok(())` when allowed, `Err(ApiError::Forbidden)` when denied.
///
/// Allowed iff one of:
///   * The caller is the bucket's `owner_agent`.
///   * A non-expired grant on the bucket has an audience that matches
///     the caller and includes `action`.
///
/// Audience matching:
///   * `Peer(p)` — `p` equals the caller's pubkey.
///   * `Agent(id)` — `id` equals the caller's `agent_id` (from their
///     on-chain attestation).
///   * `Role(r)` — `r` equals the caller's role.
///   * `Cluster(c)` — `c` equals the cluster the bucket is bound to.
pub fn check_bucket_access(
    client: &LocalClient,
    agent_pubkey: &[u8],
    bucket_id: &BucketId,
    action: Action,
) -> Result<()> {
    let pubkey_arr: [u8; 32] = agent_pubkey
        .try_into()
        .map_err(|_| ApiError::Forbidden("caller pubkey must be 32 bytes".into()))?;

    let attestation = crate::sigchain::find_agent_attestation(client, &pubkey_arr)?
        .ok_or_else(|| {
            ApiError::Forbidden(format!(
                "no agent attestation on chain for pubkey {}",
                hex::encode(pubkey_arr)
            ))
        })?;

    // API admin is ACL-exempt: an `AgentRole::Admin` agent bypasses
    // bucket/grant checks entirely.
    if attestation.role == memvault_auth::AgentRole::Admin {
        return Ok(());
    }

    // Resolve the bucket's owner pubkey once: it gates owner-bypass and
    // the owner/attesting-node grant authorities below.
    let (owner_agent_pubkey, owner_node_pubkey) = match client.bucket_info_sync(bucket_id) {
        Ok(Some(bucket)) => {
            // Owner-bypass: prefer the owner's *pubkey* (collision-free across
            // nodes). Only fall back to the `agent_id` string for legacy
            // buckets that predate `owner_agent_pubkey`, where the pubkey was
            // never recorded — otherwise a different node's same-named agent
            // would wrongly inherit ownership.
            let owner_by_pubkey = bucket
                .owner_agent_pubkey
                .map(|pk| pk.as_slice() == agent_pubkey)
                .unwrap_or(false);
            let owner_by_label = bucket.owner_agent_pubkey.is_none()
                && bucket.owner_agent.as_ref() == Some(&attestation.agent_id);
            if owner_by_pubkey || owner_by_label {
                return Ok(());
            }
            (bucket.owner_agent_pubkey, bucket.owner_node_pubkey)
        }
        _ => (None, None),
    };

    let now_ns = memvault_core::wall_ns();
    let grants = client.list_bucket_grants(bucket_id)?;
    for (cid, grant) in grants {
        // Trust the grant's *signed* bucket scope, not the storage tag it
        // was indexed under. `list_bucket_grants` looks grants up by the
        // `("grant", <bucket_hex>)` tag, which is unsigned metadata — a
        // mis-tagged or sync-injected block could otherwise let a grant
        // scoped to bucket A authorise bucket B. `bucket_scopes` is part
        // of `signing_bytes`, so this is the authoritative scope.
        if !grant.covers_bucket(bucket_id) {
            continue;
        }
        // Temporal validity (both bounds). `not_after` excludes expired;
        // `not_before` excludes not-yet-valid (future-dated) grants.
        if now_ns < grant.not_before_ns || grant.not_after_ns <= now_ns {
            continue;
        }
        // Per-grant revocation (see `LocalClient::revoke_bucket_grant`).
        // Revoked grants stay on the chain for audit but stop conferring
        // access immediately.
        if client.store().is_revoked(&cid).unwrap_or(false) {
            continue;
        }
        // Grant integrity, two independent checks:
        //  (a) the signature is authentic for the embedded issuer pubkey
        //      (stops a peer injecting a forged grant via sync); and
        //  (b) that issuer is *authorised* to grant on this bucket — a
        //      cluster admin, the bucket owner's own agent key, or the
        //      node that attested the owner (host-on-behalf). Authority is
        //      checked at the grant's `not_before_ns`.
        if !client.grant_signature_authentic(&cid, &grant) {
            continue;
        }
        if !client.grant_issuer_authorized(
            &grant.admin_pubkey,
            grant.not_before_ns,
            owner_agent_pubkey.as_ref(),
            owner_node_pubkey.as_ref(),
        ) {
            continue;
        }
        if !grant.actions.contains(&action) {
            continue;
        }
        let matches = match &grant.audience {
            GrantAudience::Peer(p) => p.0.as_slice() == agent_pubkey,
            // Canonical pubkey-addressed grant: match the caller's verified
            // ed25519 key directly (collision-free across nodes).
            GrantAudience::AgentKey(pk) => pk.as_slice() == agent_pubkey,
            // Legacy string-addressed grant. Ambiguous across nodes; kept for
            // back-compat until the v12 blockstore migration drops them.
            GrantAudience::Agent(id) => id == &attestation.agent_id,
            GrantAudience::Role(r) => *r == attestation.role,
            GrantAudience::Cluster(c) => {
                // Allow when the bucket is bound to the same cluster the
                // grant targets. Cross-cluster trust is handled by
                // `BucketTrust`, not by Cluster-audience grants here.
                client.cluster_id() == c.0.as_slice()
            }
        };
        if matches {
            return Ok(());
        }
    }

    Err(ApiError::Forbidden(format!(
        "agent {} not authorised for {:?} on bucket {}",
        attestation.agent_id.0,
        action,
        bucket_id
    )))
}
