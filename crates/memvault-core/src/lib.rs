pub mod bucket;
pub mod cid;
pub mod classification;
pub mod codec;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod scope;
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
    AgentId, BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef, PeerId, b58_decode, b58_encode,
};
pub use scope::{
    BucketSelector, DetailLevel, NodeKind, QueryScope, RetractionMode, bucket_scope_id,
    view_bucket_scope_id, view_scope_id,
};
pub use tags::{Tag, TagPattern};
pub use tags_lint::lint_tags;
pub use time::{LamportClock, wall_ns};
pub use vfs::{VFS_CHILD_REL, VFS_DIR_KIND};
pub use visibility::Visibility;

/// Current blockstore version.  Peers with mismatched versions refuse to
/// sync to prevent cross-version poisoning.  Bump when index structure,
/// adoption logic, or derived-state semantics change.
pub const BLOCKSTORE_VERSION: u32 = 11;
