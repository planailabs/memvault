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
    ///
    /// Every op is read as an [`OpNameHead`]: only the naming fields are
    /// decoded, never a document body or patch (a vault of books would
    /// otherwise be decoded whole on every `put_doc`).
    pub fn build(store: &MemvaultStore) -> Self {
        let mut index = AliasIndex::new();

        // Documents — fold the naming fields of each doc's ops in order.
        if let Ok(labels) = store.query_unique_labels("doc", usize::MAX) {
            for label in labels {
                let Some(arr) = decode_32(&label) else {
                    continue;
                };
                let Ok(cids) = store.query_by_tag("doc", &label, 0, usize::MAX) else {
                    continue;
                };
                let Some(names) = fold_doc_names(store, &cids) else {
                    continue;
                };
                names.insert_into(&mut index, &NodeRef::Doc(DocId(arr)));
            }
        }

        // Entities — fold the naming props of each entity's ops in order.
        if let Ok(labels) = store.query_unique_labels("entity", usize::MAX) {
            for label in labels {
                let Some(arr) = decode_32(&label) else {
                    continue;
                };
                let entity_id = EntityId(arr);
                let Ok(cids) = store.query_by_tag("entity", &label, 0, usize::MAX) else {
                    continue;
                };
                let Some(names) = fold_entity_names(store, &entity_id, &cids) else {
                    continue;
                };
                names.insert_into(&mut index, &NodeRef::Entity(entity_id));
            }
        }

        index
    }
}

/// The naming fields of a node: `title`/`name` and `aliases`.
#[derive(Debug, Default, Clone, serde::Deserialize)]
struct NameFields {
    #[serde(default)]
    title: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<serde_json::Value>,
    #[serde(default)]
    aliases: Option<serde_json::Value>,
}

impl NameFields {
    /// Apply one `key = value` update (a `DocSetMeta`/`DocRemoveMeta`);
    /// other keys are ignored.
    fn set(&mut self, key: &str, value: Option<serde_json::Value>) {
        match key {
            "title" => self.title = value,
            "name" => self.name = value,
            "aliases" => self.aliases = value,
            _ => {}
        }
    }

    /// Merge an `EntityUpdate`'s props (keys it carries replace ours).
    fn merge(&mut self, update: NameFields) {
        if update.title.is_some() {
            self.title = update.title;
        }
        if update.name.is_some() {
            self.name = update.name;
        }
        if update.aliases.is_some() {
            self.aliases = update.aliases;
        }
    }

    /// Documents are named by `title`, entities by `name`; both by `aliases`.
    fn insert_into(&self, index: &mut AliasIndex, node: &NodeRef) {
        let primary = match node {
            NodeRef::Entity(_) => &self.name,
            _ => &self.title,
        };
        if let Some(s) = primary.as_ref().and_then(|v| v.as_str()) {
            index.insert(s, node.clone());
        }
        if let Some(arr) = self.aliases.as_ref().and_then(|v| v.as_array()) {
            for a in arr {
                if let Some(s) = a.as_str() {
                    index.insert(s, node.clone());
                }
            }
        }
    }
}

/// An op envelope, decoded only as far as naming goes. The payload is an
/// externally-tagged `Op` (`{"DocCreate": {..}}`); variants and fields not
/// named here (bodies, patches, edges) are skipped, not allocated.
#[derive(Default, serde::Deserialize)]
struct OpNameHead {
    #[serde(default)]
    payload: OpNamePayload,
}

#[derive(Default, serde::Deserialize)]
struct OpNamePayload {
    #[serde(rename = "DocCreate")]
    doc_create: Option<DocCreateNames>,
    #[serde(rename = "DocEdit")]
    doc_edit: Option<serde::de::IgnoredAny>,
    #[serde(rename = "DocSetMeta")]
    doc_set_meta: Option<MetaKeyValue>,
    #[serde(rename = "DocRemoveMeta")]
    doc_remove_meta: Option<MetaKeyValue>,
    #[serde(rename = "EntityCreate")]
    entity_create: Option<EntityCreateNames>,
    #[serde(rename = "EntityUpdate")]
    entity_update: Option<EntityUpdateNames>,
    #[serde(rename = "EntityDelete")]
    entity_delete: Option<EntityDeleteHead>,
}

#[derive(serde::Deserialize)]
struct DocCreateNames {
    #[serde(default)]
    frontmatter: NameFields,
}

#[derive(serde::Deserialize)]
struct MetaKeyValue {
    key: String,
    #[serde(default)]
    value: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct EntityCreateNames {
    entity: EntityNames,
}

#[derive(serde::Deserialize)]
struct EntityNames {
    id: EntityId,
    #[serde(default)]
    props: NameFields,
}

#[derive(serde::Deserialize)]
struct EntityUpdateNames {
    entity_id: EntityId,
    #[serde(default)]
    props: NameFields,
}

#[derive(serde::Deserialize)]
struct EntityDeleteHead {
    entity_id: EntityId,
}

fn read_op_head(store: &MemvaultStore, cid: &[u8]) -> Option<OpNamePayload> {
    let data = store.get_block(cid).ok()??;
    memvault_store::deserialize_block_as::<OpNameHead>(&data).map(|h| h.payload)
}

/// A document's naming fields after its ops, with `apply_doc_ops`'
/// semantics: `DocCreate` resets; a meta or edit op before any create makes
/// the document unreadable (`None`).
fn fold_doc_names(store: &MemvaultStore, cids: &[Vec<u8>]) -> Option<NameFields> {
    let mut names: Option<NameFields> = None;
    for cid in cids {
        let Some(op) = read_op_head(store, cid) else {
            continue;
        };
        if let Some(create) = op.doc_create {
            names = Some(create.frontmatter);
        } else if op.doc_edit.is_some() {
            names.as_ref()?;
        } else if let Some(meta) = op.doc_set_meta {
            names.as_mut()?.set(&meta.key, meta.value);
        } else if let Some(meta) = op.doc_remove_meta {
            names.as_mut()?.set(&meta.key, None);
        }
    }
    names
}

/// An entity's naming props after its ops, with `apply_graph_ops`'
/// semantics for this entity: create replaces, update merges (an update
/// before any create makes the entity unreadable), delete removes.
fn fold_entity_names(
    store: &MemvaultStore,
    entity_id: &EntityId,
    cids: &[Vec<u8>],
) -> Option<NameFields> {
    let mut names: Option<NameFields> = None;
    for cid in cids {
        let Some(op) = read_op_head(store, cid) else {
            continue;
        };
        if let Some(create) = op.entity_create {
            if create.entity.id == *entity_id {
                names = Some(create.entity.props);
            }
        } else if let Some(update) = op.entity_update {
            if update.entity_id == *entity_id {
                names.as_mut()?.merge(update.props);
            }
        } else if let Some(delete) = op.entity_delete {
            if delete.entity_id == *entity_id {
                names = None;
            }
        }
    }
    names
}

/// Resolve an `ExtractedLink` URI to a graph-ready `ResolvedLink`. Returns
/// `None` if the URI is malformed. Pending aliases produce a placeholder
/// target via `pending_node_for_alias`.
pub fn resolve_extracted_link(link: &ExtractedLink, index: &AliasIndex) -> Option<ResolvedLink> {
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
        display_text: parsed.alias.or_else(|| link.display_text.clone()),
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
            uri: format!("memvault://doc/{}?rel=super-secret", hex::encode([3; 32])),
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
