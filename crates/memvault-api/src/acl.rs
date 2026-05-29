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

    if let Ok(Some(bucket)) = client.bucket_info_sync(bucket_id) {
        if bucket.owner_agent.as_ref() == Some(&attestation.agent_id) {
            return Ok(());
        }
    }

    let now_ns = memvault_core::wall_ns();
    let grants = client.list_bucket_grants(bucket_id)?;
    for (cid, grant) in grants {
        if grant.not_after_ns <= now_ns {
            continue;
        }
        // Per-grant revocation (see `LocalClient::revoke_bucket_grant`).
        // Revoked grants stay on the chain for audit but stop conferring
        // access immediately.
        if client.store().is_revoked(&cid).unwrap_or(false) {
            continue;
        }
        // Grant integrity: the grant must be signed by a key that was a
        // cluster-valid admin when it was issued. This stops a peer from
        // injecting a forged grant via sync — a fabricated grant won't
        // carry a valid admin signature. (Verdict cached per-CID.)
        if !client.grant_signature_valid(&cid, &grant) {
            continue;
        }
        if !grant.actions.contains(&action) {
            continue;
        }
        let matches = match &grant.audience {
            GrantAudience::Peer(p) => p.0.as_slice() == agent_pubkey,
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
