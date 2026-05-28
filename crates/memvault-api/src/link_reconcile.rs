//! Alias index + link-edge reconciler. Wires the cached `ExtractedLink`s
//! produced by the extractor pipeline into actual graph edges with
//! `LinkProvenance::BodyMarkdown`. Operator-asserted edges are never
//! touched here — only body/frontmatter-extracted ones.

use std::collections::HashMap;

use memvault_core::{DocId, EntityId, NodeRef};
use memvault_doc::link::{
    LinkProvenance, ResolvedLink, demote_relation, pending_node_for_alias, reconcile,
};
use memvault_doc::{Edge, Op};
use memvault_extract_abi::{ExtractedLink, LinkTargetKind, ParsedUri, parse_uri};
use memvault_store::MemvaultStore;

use crate::error::Result;

/// Reverse-alias index: lowercase alias → list of candidate `NodeRef`s.
/// Resolves to a concrete target only when there's exactly one candidate;
/// ambiguous aliases stay pending. Built lazily from documents and
/// entities — see [`AliasIndex::build`].
#[derive(Debug, Default, Clone)]
pub struct AliasIndex {
    by_alias: HashMap<String, Vec<NodeRef>>,
}

impl AliasIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, alias: &str, target: NodeRef) {
        if alias.is_empty() {
            return;
        }
        let key = alias.to_lowercase();
        let entry = self.by_alias.entry(key).or_default();
        if !entry.contains(&target) {
            entry.push(target);
        }
    }

    /// Unambiguous resolution. Returns `None` for unknown aliases and for
    /// aliases with more than one candidate (caller treats as pending).
    pub fn resolve(&self, alias: &str) -> Option<NodeRef> {
        let candidates = self.by_alias.get(&alias.to_lowercase())?;
        if candidates.len() == 1 {
            Some(candidates[0].clone())
        } else {
            None
        }
    }

    /// Scan the store and populate the alias index from:
    /// - Document `frontmatter.title` and `frontmatter.aliases`
    /// - Entity `props.aliases` and `props.name`
    pub fn build(store: &MemvaultStore) -> Self {
        let mut index = AliasIndex::new();

        // Documents — walk every unique `doc` tag, fold its ops, read
        // frontmatter from the resulting Document snapshot.
        if let Ok(labels) = store.query_unique_labels("doc", usize::MAX) {
            for label in labels {
                let bytes = match hex::decode(&label) {
                    Ok(b) if b.len() == 32 => b,
                    _ => continue,
                };
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let doc_id = DocId(arr);

                let cids = match store.query_by_tag("doc", &label, 0, usize::MAX) {
                    Ok(c) => c,
                    _ => continue,
                };
                let mut ops: Vec<Op> = Vec::new();
                for cid in &cids {
                    let Ok(Some(data)) = store.get_block(cid) else {
                        continue;
                    };
                    let Some(val) = memvault_store::deserialize_block(&data)
                    else {
                        continue;
                    };
                    if let Some(payload) = val.get("payload") {
                        if let Ok(op) = serde_json::from_value::<Op>(payload.clone()) {
                            ops.push(op);
                        }
                    }
                }
                if let Ok(doc) = memvault_doc::apply::apply_doc_ops(&ops) {
                    let node = NodeRef::Doc(doc_id.clone());
                    if let Some(title) = doc.frontmatter.get("title").and_then(|v| v.as_str()) {
                        index.insert(title, node.clone());
                    }
                    if let Some(arr) = doc.frontmatter.get("aliases").and_then(|v| v.as_array()) {
                        for a in arr {
                            if let Some(s) = a.as_str() {
                                index.insert(s, node.clone());
                            }
                        }
                    }
                }
            }
        }

        // Entities — fold their ops, scan props for aliases.
        if let Ok(labels) = store.query_unique_labels("entity", usize::MAX) {
            for label in labels {
                let bytes = match hex::decode(&label) {
                    Ok(b) if b.len() == 32 => b,
                    _ => continue,
                };
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let entity_id = EntityId(arr);

                let cids = match store.query_by_tag("entity", &label, 0, usize::MAX) {
                    Ok(c) => c,
                    _ => continue,
                };
                let mut ops: Vec<Op> = Vec::new();
                for cid in &cids {
                    let Ok(Some(data)) = store.get_block(cid) else {
                        continue;
                    };
                    let Some(val) = memvault_store::deserialize_block(&data)
                    else {
                        continue;
                    };
                    if let Some(payload) = val.get("payload") {
                        if let Ok(op) = serde_json::from_value::<Op>(payload.clone()) {
                            ops.push(op);
                        }
                    }
                }
                let Ok(state) = memvault_doc::apply::apply_graph_ops(&ops) else {
                    continue;
                };
                let Some(entity) = state.entities.get(&entity_id) else {
                    continue;
                };
                let node = NodeRef::Entity(entity_id.clone());
                if let Some(name) = entity.props.get("name").and_then(|v| v.as_str()) {
                    index.insert(name, node.clone());
                }
                if let Some(arr) = entity.props.get("aliases").and_then(|v| v.as_array()) {
                    for a in arr {
                        if let Some(s) = a.as_str() {
                            index.insert(s, node.clone());
                        }
                    }
                }
            }
        }

        index
    }
}

/// Resolve an `ExtractedLink` URI to a graph-ready `ResolvedLink`. Returns
/// `None` if the URI is malformed. Pending aliases produce a placeholder
/// target via `pending_node_for_alias`.
pub fn resolve_extracted_link(
    link: &ExtractedLink,
    index: &AliasIndex,
) -> Option<ResolvedLink> {
    let parsed: ParsedUri = parse_uri(&link.uri).ok()?;
    let (target, pending_alias) = match parsed.kind {
        LinkTargetKind::Doc => (NodeRef::Doc(DocId(decode_32(&parsed.ident)?)), None),
        LinkTargetKind::Entity => (NodeRef::Entity(EntityId(decode_32(&parsed.ident)?)), None),
        LinkTargetKind::File => {
            let bytes = hex::decode(&parsed.ident).ok()?;
            (NodeRef::Attachment(bytes), None)
        }
        LinkTargetKind::Alias => match index.resolve(&parsed.ident) {
            Some(node) => (node, None),
            None => (
                pending_node_for_alias(&parsed.ident),
                Some(parsed.ident.clone()),
            ),
        },
    };
    let relation = demote_relation(parsed.relation.as_deref().unwrap_or("mentions"));
    Some(ResolvedLink {
        target,
        relation,
        display_text: parsed
            .alias
            .or_else(|| link.display_text.clone()),
        pending_alias,
    })
}

fn decode_32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Inputs to a doc-link reconciliation pass. Separated from the orchestrator
/// in `local.rs` so we can unit-test the diff in isolation.
pub struct ReconcileInput<'a> {
    pub doc_id: &'a DocId,
    pub current_links: &'a [ExtractedLink],
    pub previous_links: &'a [ExtractedLink],
    pub existing_body_edges: &'a [Edge],
    pub alias_index: &'a AliasIndex,
}

/// Compute the ops required to bring graph edges into sync with the
/// current parsed-link set. Pure — no I/O.
pub fn compute_reconcile_ops(input: &ReconcileInput<'_>) -> Vec<Op> {
    let source = NodeRef::Doc(input.doc_id.clone());

    let prev_resolved: Vec<ResolvedLink> = input
        .previous_links
        .iter()
        .filter_map(|l| resolve_extracted_link(l, input.alias_index))
        .collect();

    let next_resolved: Vec<ResolvedLink> = input
        .current_links
        .iter()
        .filter_map(|l| resolve_extracted_link(l, input.alias_index))
        .collect();

    reconcile(
        source,
        &prev_resolved,
        &next_resolved,
        LinkProvenance::BodyMarkdown,
        input.existing_body_edges,
    )
}

/// Filter an edge set down to those produced by body/frontmatter
/// extraction. Used to find the current body-provenance edge state for
/// the diff base.
pub fn filter_body_provenance(edges: Vec<(NodeRef, Edge)>) -> Vec<Edge> {
    edges
        .into_iter()
        .filter_map(|(_, edge)| {
            let prov = LinkProvenance::of(&edge)?;
            match prov {
                LinkProvenance::BodyMarkdown | LinkProvenance::Frontmatter => Some(edge),
                LinkProvenance::Asserted => None,
            }
        })
        .collect()
}

/// Apply ops via the local client's store_op path. Returns `Ok(())` if all
/// ops landed; errors propagate.
pub fn apply_reconcile_ops(client: &crate::LocalClient, ops: &[Op]) -> Result<()> {
    use memvault_core::Visibility;

    for op in ops {
        let source_label = match op {
            Op::EdgeAdd { source, .. } => source.tag_label(),
            Op::EdgeRemove { source, .. } => source.tag_label(),
            _ => continue,
        };
        let target_label = match op {
            Op::EdgeAdd { edge, .. } => Some(edge.target.tag_label()),
            _ => None,
        };
        let mut tags: Vec<(String, String)> = Vec::new();
        tags.push(("edge_source".to_string(), source_label));
        if let Some(tl) = target_label {
            tags.push(("edge_target".to_string(), tl));
        }
        // Body-extracted edges always go through the doc's inferred bucket.
        let bucket = match op {
            Op::EdgeAdd { source, .. } | Op::EdgeRemove { source, .. } => {
                client.inferred_node_bucket_pub(source)
            }
            _ => None,
        };
        let bucket_typed = bucket
            .and_then(|bytes| bytes.try_into().ok())
            .map(memvault_core::BucketId);

        client.store_op_pub(op, &tags, &Visibility::Internal, bucket_typed.as_ref())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memvault_extract_abi::LinkSyntax;

    fn doc_uri(seed: u8) -> ExtractedLink {
        ExtractedLink {
            uri: format!("memvault://doc/{}", hex::encode([seed; 32])),
            display_text: None,
            byte_span: (0, 0),
            syntax: LinkSyntax::Wikilink,
        }
    }

    #[test]
    fn alias_index_basic() {
        let mut idx = AliasIndex::new();
        idx.insert("Alice", NodeRef::Doc(DocId([1; 32])));
        idx.insert("alice", NodeRef::Doc(DocId([1; 32]))); // dedup
        assert_eq!(idx.resolve("ALICE"), Some(NodeRef::Doc(DocId([1; 32]))));
    }

    #[test]
    fn alias_ambiguity_unresolves() {
        let mut idx = AliasIndex::new();
        idx.insert("Bob", NodeRef::Doc(DocId([1; 32])));
        idx.insert("Bob", NodeRef::Doc(DocId([2; 32])));
        assert_eq!(idx.resolve("Bob"), None);
    }

    #[test]
    fn resolve_doc_uri() {
        let idx = AliasIndex::new();
        let link = doc_uri(7);
        let resolved = resolve_extracted_link(&link, &idx).unwrap();
        assert_eq!(resolved.target, NodeRef::Doc(DocId([7; 32])));
        assert_eq!(resolved.relation, "mentions");
        assert!(resolved.pending_alias.is_none());
    }

    #[test]
    fn resolve_alias_resolves_via_index() {
        let mut idx = AliasIndex::new();
        idx.insert("Alice", NodeRef::Doc(DocId([9; 32])));
        let link = ExtractedLink {
            uri: "memvault://alias/Alice".to_string(),
            display_text: None,
            byte_span: (0, 0),
            syntax: LinkSyntax::Wikilink,
        };
        let resolved = resolve_extracted_link(&link, &idx).unwrap();
        assert_eq!(resolved.target, NodeRef::Doc(DocId([9; 32])));
        assert!(resolved.pending_alias.is_none());
    }

    #[test]
    fn resolve_alias_pending_when_unknown() {
        let idx = AliasIndex::new();
        let link = ExtractedLink {
            uri: "memvault://alias/Ghost".to_string(),
            display_text: None,
            byte_span: (0, 0),
            syntax: LinkSyntax::Wikilink,
        };
        let resolved = resolve_extracted_link(&link, &idx).unwrap();
        assert_eq!(resolved.pending_alias.as_deref(), Some("Ghost"));
        // Pending placeholder is stable.
        assert_eq!(resolved.target, pending_node_for_alias("Ghost"));
    }

    #[test]
    fn malformed_uri_is_dropped() {
        let idx = AliasIndex::new();
        let link = ExtractedLink {
            uri: "memvault://doc/not-hex".to_string(),
            display_text: None,
            byte_span: (0, 0),
            syntax: LinkSyntax::Wikilink,
        };
        assert!(resolve_extracted_link(&link, &idx).is_none());
    }

    #[test]
    fn relation_demoted_when_outside_allowlist() {
        let idx = AliasIndex::new();
        let link = ExtractedLink {
            uri: format!(
                "memvault://doc/{}?rel=super-secret",
                hex::encode([3; 32])
            ),
            display_text: None,
            byte_span: (0, 0),
            syntax: LinkSyntax::MarkdownLink,
        };
        let resolved = resolve_extracted_link(&link, &idx).unwrap();
        assert_eq!(resolved.relation, "mentions");
    }

    #[test]
    fn relation_kept_when_in_allowlist() {
        let idx = AliasIndex::new();
        let link = ExtractedLink {
            uri: format!("memvault://doc/{}?rel=cites", hex::encode([3; 32])),
            display_text: None,
            byte_span: (0, 0),
            syntax: LinkSyntax::MarkdownLink,
        };
        let resolved = resolve_extracted_link(&link, &idx).unwrap();
        assert_eq!(resolved.relation, "cites");
    }

    #[test]
    fn reconcile_pure_add_only() {
        let doc_id = DocId([0; 32]);
        let idx = AliasIndex::new();
        let input = ReconcileInput {
            doc_id: &doc_id,
            current_links: &[doc_uri(1), doc_uri(2)],
            previous_links: &[],
            existing_body_edges: &[],
            alias_index: &idx,
        };
        let ops = compute_reconcile_ops(&input);
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|o| matches!(o, Op::EdgeAdd { .. })));
    }
}
