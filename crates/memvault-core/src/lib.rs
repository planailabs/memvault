pub mod bucket;
pub mod cid;
pub mod classification;
pub mod codec;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod scope;
pub mod skill;
pub mod tags;
pub mod tags_lint;
pub mod time;
pub mod vfs;
pub mod visibility;

pub use self::cid::{
    cid_bytes_from_string, cid_bytes_lenient, cid_from_bytes, cid_from_string, cid_from_value,
    cid_string_from_bytes, cid_to_string, cid_with_codec, verify_cid,
};
pub use self::cid::codec as cid_codec;
pub use classification::Classification;
pub use codec::{decode, encode};
pub use envelope::Signed;
pub use error::{Error, Result};
pub use bucket::{BucketBinding, BucketDecl, BucketRole};
pub use ids::{
    AgentName, BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef, PeerId, b58_decode, b58_encode,
};
pub use scope::{
    BucketSelector, DetailLevel, NodeKind, QueryScope, RetractionMode, bucket_scope_id,
    view_bucket_scope_id, view_scope_id,
};
pub use skill::{
    SKILL_DESCRIPTION_PROP, SKILL_EXECUTABLE_PROP, SKILL_INSTRUCTION_REL, SKILL_KIND,
    SKILL_NAME_PROP, SKILL_ORDER_PROP, SKILL_PATH_PROP, SKILL_REQUIRES_REL, SKILL_RESOURCE_REL,
    SKILL_TRIGGER_PROP, is_reserved_entity_kind,
};
pub use tags::{Tag, TagPattern};
pub use tags_lint::lint_tags;
pub use time::{LamportClock, wall_ns};
pub use vfs::{VFS_CHILD_REL, VFS_DIR_KIND};
pub use visibility::Visibility;

/// Current blockstore version.  Peers with mismatched versions refuse to
/// sync to prevent cross-version poisoning.  Bump when index structure,
/// adoption logic, or derived-state semantics change.
///
/// v12: drop legacy `GrantAudience::Agent(string)` bucket grants during the
/// rebuild. The string audience can't disambiguate same-named agents across
/// nodes; access now uses `GrantAudience::AgentKey(pubkey)`. The version gate
/// stops un-migrated (v11) peers from re-injecting the dropped grants.
///
/// v13: agent-bucket derivation changed to `deterministic_agent_bucket_id(
/// pubkey)` (cluster_id dropped) so an agent's bucket is stable across
/// genesis/join/re-genesis, plus the bucket-merge alias overlay
/// (`BucketMergeRecord` side blocks, resolved at the read/ACL layer). Both
/// are derived-state semantics changes: a v12 peer wouldn't apply the merge
/// union and would still derive cluster-scoped agent ids, so the version
/// gate keeps v12 and v13 nodes from syncing and diverging. The upgrade
/// rebuild re-derives + auto-aliases legacy agent buckets onto the stable id
/// (agent blocks keep their original signed bucket_id — never re-homed).
/// v14: re-index `BucketMergeRecord` side blocks that synced in untagged before
/// the sync classifier (`validate_sigchain_for_sync`) learned about them — they
/// were stored `AsIs` and the generic reindex couldn't recover tags from the
/// bare struct, so the merge was invisible on the peer. The rebuild re-applies
/// their `("bucket_merge", <source>)` lookup tags. Idempotent and node-agnostic:
/// the tag key is derived from each record's own `created_ns`, so every node
/// converges to the same index regardless of who runs it.
/// v15: backfill syncable retraction blocks for local-only `RETRACTED` entries.
/// Block-level retractions (e.g. unmerge) used to write only the local redb
/// table, so they never propagated — an unmerge stayed local while peers kept
/// applying the merge. Retractions are now published as signed `retraction`
/// sigchain blocks; this migration re-publishes one per existing local-only
/// retraction so already-diverged clusters converge. Idempotent.
pub const BLOCKSTORE_VERSION: u32 = 15;
