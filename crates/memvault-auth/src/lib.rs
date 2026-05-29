pub mod admin_genesis;
pub mod admin_keys;
/// Domain-separated signing-bytes helper.
///
/// Prepends a per-type, versioned domain tag to the canonical DAG-CBOR
/// encoding of a signing payload, so a signature over one envelope type
/// can never verify as another (cross-type transplant / CBOR shape
/// confusion). Every `signing_bytes()` in this crate funnels through this
/// with its own `DOMAIN` constant. NB: this is a hard format — signatures
/// produced before domain separation will not verify (intentional; not a
/// dual-verify migration).
pub(crate) fn domain_sign<T: serde::Serialize>(
    domain: &[u8],
    payload: &T,
) -> error::Result<Vec<u8>> {
    let body = serde_ipld_dagcbor::to_vec(payload)
        .map_err(|e| error::AuthError::Codec(e.to_string()))?;
    let mut out = Vec::with_capacity(domain.len() + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&body);
    Ok(out)
}
pub mod agent_attestation;
pub mod sigchain_shape;
pub mod agent_revocation;
pub mod node_attestation;
pub mod enrollment;
pub mod error;
pub mod grant;
pub mod grant_revocation;
pub mod jwt;
pub mod key_state;
pub mod revocation;
pub mod role;
pub mod rotation;
pub mod share;
pub mod token;
pub mod trust;
pub mod verifier;

pub use admin_genesis::{AdminGenesis, pick_earliest as pick_earliest_admin_genesis, sign_admin_genesis};
pub use admin_keys::{
    AdminKeyAdmission, AdminKeyRetirement, admin_pop_signing_bytes, sign_admin_admission,
    sign_admin_pop, sign_admin_retirement, verify_admin_pop,
};
pub use agent_attestation::{AgentAttestation, sign_agent_attestation};
pub use agent_revocation::{
    AgentRevocation, NodeRevocation, sign_agent_revocation, sign_node_revocation,
};
pub use sigchain_shape::{SigchainKind, sigchain_label_for, detect_sigchain_shape};
pub use node_attestation::{AttestationOrigin, NodeAttestation};
pub use enrollment::AgentEnrollment;
pub use error::{AuthError, Result};
pub use grant::{Action, Grant, GrantAudience};
pub use grant_revocation::{GrantRevocation, sign_grant_revocation};
pub use jwt::{AgentTokenClaims, issue as issue_agent_token, scope, verify as verify_agent_token};
pub use key_state::{AdminKeyState, KeyValidity};
pub use revocation::Revocation;
pub use role::Role;
pub use rotation::{AdminKeyRotation, AgentKeyRotation, RotationAborted};
pub use share::{
    BucketTrust, ShareDecision, ShareProposal, ShareRecipient, ShareReply, ShareStatus,
};
pub use token::{JoinToken, TokenConsumption, decode_token_string, encode_token_string};
pub use trust::ClusterTrust;
pub use verifier::{AuthVerifier, RevocationStore};
