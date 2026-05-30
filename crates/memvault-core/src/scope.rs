//! The `QueryScope` triplet — `(view, buckets, retracted)` — threaded down the
//! entire read API as a single value.
//!
//! See `knowledge/reference/memvault/design-docs/scoped-indexes.md`.
//!
//! A scope is *what the caller asked for*. It is always intersected with the
//! caller's accessible bucket set by the handler before it reaches the index —
//! scope can only ever narrow visibility, never widen it (ACL is a separate,
//! non-negotiable layer).

use crate::BucketId;

/// Derive the opaque, fixed-width (32-byte) `scope_id` digest for a partition
/// coordinate. The one-byte domain tag keeps the three partition kinds in
/// disjoint key spaces even if a view_cid and bucket_id happened to collide.
fn scope_digest(tag: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[tag]);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

/// `scope_id` for a per-bucket partition.
pub fn bucket_scope_id(bucket_id: &BucketId) -> [u8; 32] {
    scope_digest(b'b', &[&bucket_id.0])
}

/// `scope_id` for a per-view (fan-out across buckets) partition.
/// `view_cid` is the view block's CID bytes (stable identity of the view).
pub fn view_scope_id(view_cid: &[u8]) -> [u8; 32] {
    scope_digest(b'v', &[view_cid])
}

/// `scope_id` for a per-view×bucket partition.
pub fn view_bucket_scope_id(view_cid: &[u8], bucket_id: &BucketId) -> [u8; 32] {
    scope_digest(b'x', &[view_cid, &bucket_id.0])
}

/// Which buckets a query spans.
///
/// We never materialize bucket *subsets*; a query over a set is answered by
/// merging the relevant single-bucket partitions at query time. Adding a bucket
/// to an agent's grant set therefore costs nothing at index time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BucketSelector {
    /// All buckets the caller may see. Resolved to the caller's accessible set
    /// by the handler before hitting the index.
    #[default]
    Accessible,
    /// An explicit set — e.g. the subset of an agent's accessible buckets the
    /// caller chose, or a single bucket from the UI top-bar. ALWAYS intersected
    /// with the accessible set downstream; never widens visibility.
    Only(Vec<BucketId>),
}

impl BucketSelector {
    /// Convenience constructor for a single-bucket selection.
    pub fn one(bucket: BucketId) -> Self {
        BucketSelector::Only(vec![bucket])
    }

    /// The explicit bucket set, if any. `Accessible` returns `None`.
    pub fn explicit(&self) -> Option<&[BucketId]> {
        match self {
            BucketSelector::Accessible => None,
            BucketSelector::Only(v) => Some(v),
        }
    }

    /// True if this selector names zero buckets explicitly (i.e. an empty
    /// `Only(vec![])`), which always resolves to an empty result set.
    pub fn is_empty_set(&self) -> bool {
        matches!(self, BucketSelector::Only(v) if v.is_empty())
    }
}

/// A node-type filter for scoped queries. `None` on the scope means all kinds;
/// a concrete kind restricts results to that node type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Document,
    File,
    GraphEntity,
}

impl NodeKind {
    /// The `node_type` strings (as stored in the index) this kind matches.
    /// Files accept both the modern "file" and legacy "attachment" labels.
    pub fn node_types(self) -> &'static [&'static str] {
        match self {
            NodeKind::Document => &["doc"],
            NodeKind::File => &["file", "attachment"],
            NodeKind::GraphEntity => &["entity"],
        }
    }

    /// Whether the given `node_type` string belongs to this kind.
    pub fn matches(self, node_type: &str) -> bool {
        self.node_types().contains(&node_type)
    }

    /// Map a `node_type` string to its kind, if recognised.
    pub fn from_node_type(node_type: &str) -> Option<NodeKind> {
        match node_type {
            "doc" => Some(NodeKind::Document),
            "file" | "attachment" => Some(NodeKind::File),
            "entity" => Some(NodeKind::GraphEntity),
            _ => None,
        }
    }
}

/// How much per-node detail a scoped listing returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetailLevel {
    /// Lean node summaries only (node_id, type, label, tags, retracted).
    #[default]
    Summary,
    /// Additionally populate each entry's type-specific `detail` (doc mtime +
    /// attachment count, entity kind + props, file name/mime/size). Costs a
    /// per-node lookup, so it's opt-in.
    Full,
}

/// How retracted nodes participate in a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetractionMode {
    /// Exclude retracted nodes (the default for ordinary callers).
    #[default]
    ActiveOnly,
    /// Active + retracted (admin/auditor "show retracted").
    IncludeRetracted,
    /// Only retracted nodes (admin/auditor audit lens).
    RetractedOnly,
}

impl RetractionMode {
    /// Map a legacy `include_retracted: bool` onto a mode.
    pub fn from_include_flag(include_retracted: bool) -> Self {
        if include_retracted {
            RetractionMode::IncludeRetracted
        } else {
            RetractionMode::ActiveOnly
        }
    }

    /// True if active (non-retracted) nodes should be returned.
    pub fn includes_active(self) -> bool {
        matches!(
            self,
            RetractionMode::ActiveOnly | RetractionMode::IncludeRetracted
        )
    }

    /// True if retracted nodes should be returned.
    pub fn includes_retracted(self) -> bool {
        matches!(
            self,
            RetractionMode::IncludeRetracted | RetractionMode::RetractedOnly
        )
    }

    /// Whether a node with the given retracted-state passes this mode's filter.
    pub fn admits(self, is_retracted: bool) -> bool {
        if is_retracted {
            self.includes_retracted()
        } else {
            self.includes_active()
        }
    }
}

/// The query coordinate threaded down the read API.
#[derive(Debug, Clone, Default)]
pub struct QueryScope {
    /// View name; its required tags are resolved at use. `None` = no view filter.
    pub view: Option<String>,
    /// Which buckets the query spans.
    pub buckets: BucketSelector,
    /// How retracted nodes participate.
    pub retraction: RetractionMode,
    /// Restrict to a single node kind (doc / file / entity). `None` = all kinds.
    pub kind: Option<NodeKind>,
    /// How much per-node detail a scoped listing returns.
    pub detail: DetailLevel,
}

impl QueryScope {
    /// An unscoped query: no view, all accessible buckets, active-only.
    pub fn all() -> Self {
        Self::default()
    }

    /// Builder: set the view.
    pub fn with_view(mut self, view: Option<String>) -> Self {
        self.view = view;
        self
    }

    /// Builder: restrict to an explicit bucket set.
    pub fn with_buckets(mut self, buckets: Vec<BucketId>) -> Self {
        self.buckets = BucketSelector::Only(buckets);
        self
    }

    /// Builder: restrict to a single bucket.
    pub fn with_bucket(mut self, bucket: Option<BucketId>) -> Self {
        if let Some(b) = bucket {
            self.buckets = BucketSelector::one(b);
        }
        self
    }

    /// Builder: set the retraction mode.
    pub fn with_retraction(mut self, mode: RetractionMode) -> Self {
        self.retraction = mode;
        self
    }

    /// Builder: set the retraction mode from a legacy boolean.
    pub fn with_include_retracted(mut self, include_retracted: bool) -> Self {
        self.retraction = RetractionMode::from_include_flag(include_retracted);
        self
    }

    /// Builder: restrict to a single node kind.
    pub fn with_kind(mut self, kind: Option<NodeKind>) -> Self {
        self.kind = kind;
        self
    }

    /// Builder: set the detail level.
    pub fn with_detail(mut self, detail: DetailLevel) -> Self {
        self.detail = detail;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retraction_admits() {
        assert!(RetractionMode::ActiveOnly.admits(false));
        assert!(!RetractionMode::ActiveOnly.admits(true));
        assert!(RetractionMode::IncludeRetracted.admits(false));
        assert!(RetractionMode::IncludeRetracted.admits(true));
        assert!(!RetractionMode::RetractedOnly.admits(false));
        assert!(RetractionMode::RetractedOnly.admits(true));
    }

    #[test]
    fn from_include_flag() {
        assert_eq!(
            RetractionMode::from_include_flag(false),
            RetractionMode::ActiveOnly
        );
        assert_eq!(
            RetractionMode::from_include_flag(true),
            RetractionMode::IncludeRetracted
        );
    }

    #[test]
    fn bucket_selector_basics() {
        assert_eq!(BucketSelector::default(), BucketSelector::Accessible);
        let b = BucketId([1u8; 32]);
        let sel = BucketSelector::one(b);
        assert_eq!(sel.explicit().map(|s| s.len()), Some(1));
        assert!(!sel.is_empty_set());
        assert!(BucketSelector::Only(vec![]).is_empty_set());
        assert!(BucketSelector::Accessible.explicit().is_none());
    }

    #[test]
    fn scope_ids_are_disjoint_and_fixed_width() {
        let b = BucketId([3u8; 32]);
        let vcid = b"view-cid-bytes";
        let s_b = bucket_scope_id(&b);
        let s_v = view_scope_id(vcid);
        let s_vb = view_bucket_scope_id(vcid, &b);
        assert_eq!(s_b.len(), 32);
        // All three domains differ for the same inputs.
        assert_ne!(s_b, s_v);
        assert_ne!(s_b, s_vb);
        assert_ne!(s_v, s_vb);
        // Deterministic.
        assert_eq!(s_vb, view_bucket_scope_id(vcid, &b));
        // Different bucket → different id.
        assert_ne!(s_b, bucket_scope_id(&BucketId([4u8; 32])));
    }

    #[test]
    fn scope_builder() {
        let s = QueryScope::all()
            .with_view(Some("inbox".into()))
            .with_bucket(Some(BucketId([2u8; 32])))
            .with_retraction(RetractionMode::RetractedOnly);
        assert_eq!(s.view.as_deref(), Some("inbox"));
        assert_eq!(s.buckets.explicit().map(|s| s.len()), Some(1));
        assert_eq!(s.retraction, RetractionMode::RetractedOnly);
    }
}
