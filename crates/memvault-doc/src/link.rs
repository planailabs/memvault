//! Link-edge provenance and the reconciler that turns parsed links into
//! graph edge ops. The parser itself lives in the extractor pipeline; this
//! module only consumes its output.
//!
//! Provenance is encoded in `Edge.props["provenance"]`:
//! - `"body_markdown"` — extracted from document body; managed by the
//!   reconciler. Replaced/removed when the body changes.
//! - `"frontmatter"` — extracted from frontmatter; same lifecycle.
//! - `"asserted"` — set by an operator/agent via direct graph op. The
//!   reconciler never touches these.
//!
//! The reserved relation allowlist is enforced **here**, not in the
//! extractor — anything outside it is demoted to `"mentions"` with a
//! warning so a misbehaving plugin can't claim arbitrary semantics.

use std::collections::{BTreeMap, HashSet};

use memvault_core::{EdgeId, EntityId, NodeRef};
use serde_json::Value;

use crate::graph::Edge;
use crate::op::Op;

/// Source of an edge, encoded in `Edge.props["provenance"]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkProvenance {
    BodyMarkdown,
    Frontmatter,
    Asserted,
}

impl LinkProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BodyMarkdown => "body_markdown",
            Self::Frontmatter => "frontmatter",
            Self::Asserted => "asserted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "body_markdown" => Some(Self::BodyMarkdown),
            "frontmatter" => Some(Self::Frontmatter),
            "asserted" => Some(Self::Asserted),
            _ => None,
        }
    }

    pub fn of(edge: &Edge) -> Option<Self> {
        edge.props
            .get("provenance")
            .and_then(|v| v.as_str())
            .and_then(Self::parse)
    }
}

/// Relations a body/frontmatter-extracted edge is allowed to assert. Out-of-
/// allowlist values are demoted to `"mentions"`.
pub const ALLOWED_BODY_RELATIONS: &[&str] = &["mentions", "cites", "embeds", "replies-to"];

pub fn demote_relation(rel: &str) -> String {
    for &allowed in ALLOWED_BODY_RELATIONS {
        if rel == allowed {
            return allowed.to_string();
        }
    }
    "mentions".to_string()
}

/// A parsed link, already resolved to a concrete `NodeRef`. The reconciler
/// works at this level — alias resolution and demotion happen before it
/// runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLink {
    pub target: NodeRef,
    pub relation: String,
    pub display_text: Option<String>,
    pub pending_alias: Option<String>,
}

impl ResolvedLink {
    fn dedup_key(&self) -> (NodeRef, String) {
        (self.target.clone(), self.relation.clone())
    }
}

/// Diff a previous and a current resolved-link set for one source node,
/// returning the ops needed to bring the graph into sync. Body-provenance
/// edges only; operator-asserted edges are never touched here.
///
/// `existing_body_edges` is the current body-provenance edge set for the
/// source node, so we can find concrete `EdgeId`s to remove and skip
/// re-adding edges that already exist.
pub fn reconcile(
    source: NodeRef,
    prev: &[ResolvedLink],
    next: &[ResolvedLink],
    provenance: LinkProvenance,
    existing_body_edges: &[Edge],
) -> Vec<Op> {
    let prev_keys: HashSet<(NodeRef, String)> = prev.iter().map(|l| l.dedup_key()).collect();
    let next_keys: HashSet<(NodeRef, String)> = next.iter().map(|l| l.dedup_key()).collect();

    let mut ops = Vec::new();

    // RemoveEdge for keys in prev but not in next, matched against the
    // current body-provenance edge set so we can produce concrete EdgeIds.
    for key in prev_keys.difference(&next_keys) {
        for edge in existing_body_edges {
            if edge.target == key.0 && edge.relation == key.1 {
                ops.push(Op::EdgeRemove {
                    source: source.clone(),
                    edge_id: edge.id.clone(),
                });
            }
        }
    }

    // AddEdge for keys in next but not in prev, only if the same body edge
    // doesn't already exist (idempotent reconciliation). De-dup within the
    // current next set too — two `[[Alice]]`s in one body produce one edge.
    let mut emitted: HashSet<(NodeRef, String)> = HashSet::new();
    for link in next {
        let key = link.dedup_key();
        if prev_keys.contains(&key) {
            continue;
        }
        if emitted.contains(&key) {
            continue;
        }
        if existing_body_edges
            .iter()
            .any(|e| e.target == link.target && e.relation == link.relation)
        {
            continue;
        }
        emitted.insert(key);
        ops.push(Op::EdgeAdd {
            source: source.clone(),
            edge: build_body_edge(link, provenance),
        });
    }

    ops
}

fn build_body_edge(link: &ResolvedLink, provenance: LinkProvenance) -> Edge {
    let mut props: BTreeMap<String, Value> = BTreeMap::new();
    props.insert(
        "provenance".to_string(),
        Value::String(provenance.as_str().to_string()),
    );
    if let Some(alias) = &link.pending_alias {
        props.insert("pending_alias".to_string(), Value::String(alias.clone()));
    }
    if let Some(disp) = &link.display_text {
        props.insert("display_text".to_string(), Value::String(disp.clone()));
    }
    Edge {
        id: EdgeId::random(),
        relation: link.relation.to_string(),
        target: link.target.clone(),
        weight: None,
        props,
        provenance: None,
    }
}

/// Stable placeholder NodeRef for an unresolved alias — `blake3(alias_lower)`
/// truncated to 32 bytes. Same alias → same placeholder, so adding/removing
/// it across body edits is idempotent.
pub fn pending_node_for_alias(alias: &str) -> NodeRef {
    let lower = alias.to_lowercase();
    let hash = blake3::hash(lower.as_bytes());
    NodeRef::Entity(EntityId(*hash.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memvault_core::DocId;

    fn doc_ref(seed: u8) -> NodeRef {
        NodeRef::Doc(DocId([seed; 32]))
    }

    fn link_to(target: NodeRef, rel: &str) -> ResolvedLink {
        ResolvedLink {
            target,
            relation: rel.to_string(),
            display_text: None,
            pending_alias: None,
        }
    }

    #[test]
    fn add_when_target_new() {
        let src = doc_ref(1);
        let next = vec![link_to(doc_ref(2), "mentions")];
        let ops = reconcile(src.clone(), &[], &next, LinkProvenance::BodyMarkdown, &[]);
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            Op::EdgeAdd { source, edge } => {
                assert_eq!(source, &src);
                assert_eq!(edge.target, doc_ref(2));
                assert_eq!(edge.relation, "mentions");
                assert_eq!(
                    edge.props.get("provenance").and_then(|v| v.as_str()),
                    Some("body_markdown")
                );
            }
            _ => panic!("expected EdgeAdd"),
        }
    }

    #[test]
    fn remove_when_target_gone() {
        let src = doc_ref(1);
        let prev = vec![link_to(doc_ref(2), "mentions")];
        let existing = vec![Edge {
            id: EdgeId([7; 32]),
            relation: "mentions".to_string(),
            target: doc_ref(2),
            weight: None,
            props: {
                let mut p = BTreeMap::new();
                p.insert(
                    "provenance".to_string(),
                    Value::String("body_markdown".to_string()),
                );
                p
            },
            provenance: None,
        }];
        let ops = reconcile(
            src.clone(),
            &prev,
            &[],
            LinkProvenance::BodyMarkdown,
            &existing,
        );
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            Op::EdgeRemove { edge_id, .. } => {
                assert_eq!(edge_id, &EdgeId([7; 32]));
            }
            _ => panic!("expected EdgeRemove"),
        }
    }

    #[test]
    fn skip_add_when_edge_already_exists() {
        let src = doc_ref(1);
        let next = vec![link_to(doc_ref(2), "mentions")];
        let existing = vec![Edge {
            id: EdgeId([7; 32]),
            relation: "mentions".to_string(),
            target: doc_ref(2),
            weight: None,
            props: BTreeMap::new(),
            provenance: None,
        }];
        let ops = reconcile(
            src.clone(),
            &[],
            &next,
            LinkProvenance::BodyMarkdown,
            &existing,
        );
        assert!(ops.is_empty());
    }

    #[test]
    fn relation_change_emits_remove_and_add() {
        let src = doc_ref(1);
        let prev = vec![link_to(doc_ref(2), "mentions")];
        let next = vec![link_to(doc_ref(2), "cites")];
        let existing = vec![Edge {
            id: EdgeId([7; 32]),
            relation: "mentions".to_string(),
            target: doc_ref(2),
            weight: None,
            props: BTreeMap::new(),
            provenance: None,
        }];
        let ops = reconcile(
            src.clone(),
            &prev,
            &next,
            LinkProvenance::BodyMarkdown,
            &existing,
        );
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], Op::EdgeRemove { .. }));
        assert!(matches!(&ops[1], Op::EdgeAdd { .. }));
    }

    #[test]
    fn dedup_by_target_relation() {
        let src = doc_ref(1);
        let next = vec![
            link_to(doc_ref(2), "mentions"),
            link_to(doc_ref(2), "mentions"),
        ];
        let ops = reconcile(src, &[], &next, LinkProvenance::BodyMarkdown, &[]);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn pending_alias_is_stable() {
        let a = pending_node_for_alias("Alice");
        let b = pending_node_for_alias("alice");
        assert_eq!(a, b, "alias placeholder is case-insensitive");
        let c = pending_node_for_alias("Bob");
        assert_ne!(a, c);
    }

    #[test]
    fn demote_unknown_relation_to_mentions() {
        assert_eq!(demote_relation("super-secret-rel"), "mentions");
        assert_eq!(demote_relation("cites"), "cites");
        assert_eq!(demote_relation("mentions"), "mentions");
        assert_eq!(demote_relation("replies-to"), "replies-to");
    }
}
