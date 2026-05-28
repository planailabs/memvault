//! Shared agent-attestation helpers for the WebUI.
//!
//! Multiple surfaces (audit, notes history, file detail, entity
//! detail) all need to resolve `Signed<T>.agent_attestation` cids to
//! human-readable agent IDs. Building the cid → agent_id map is a
//! small scan of the sigchain; this module centralises it so callers
//! don't reimplement the lookup.

#[cfg(feature = "server")]
pub fn build_agent_id_index(
    local: &memvault_api::LocalClient,
) -> std::collections::HashMap<Vec<u8>, String> {
    let mut out = std::collections::HashMap::new();
    if let Ok(atts) = memvault_api::sigchain::scan_agent_attestations(local) {
        for att in atts {
            if let Ok(bytes) = memvault_core::encode(&att) {
                let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
                out.insert(cid, att.agent_id.0);
            }
        }
    }
    out
}
