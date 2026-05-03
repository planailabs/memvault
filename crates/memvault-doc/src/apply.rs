use std::collections::BTreeMap;

use memvault_core::{EntityId, NodeRef};

use crate::document::Document;
use crate::error::{DocError, Result};
use crate::graph::{Edge, Entity};
use crate::op::{Op, TextOp, TextPatch};

/// Apply a TextPatch to a string.
pub fn apply_text_patch(text: &str, patch: &TextPatch) -> Result<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut pos: usize = 0;
    let mut result = String::new();

    for op in &patch.ops {
        match op {
            TextOp::Retain(n) => {
                let end = pos + n;
                if end > chars.len() {
                    return Err(DocError::PatchOutOfBounds {
                        pos: end,
                        len: chars.len(),
                    });
                }
                for c in &chars[pos..end] {
                    result.push(*c);
                }
                pos = end;
            }
            TextOp::Insert(s) => {
                result.push_str(s);
            }
            TextOp::Delete(n) => {
                let end = pos + n;
                if end > chars.len() {
                    return Err(DocError::PatchOutOfBounds {
                        pos: end,
                        len: chars.len(),
                    });
                }
                pos = end;
            }
        }
    }

    // Append remaining chars
    for c in &chars[pos..] {
        result.push(*c);
    }

    Ok(result)
}

/// Apply a sequence of operations to build a Document from scratch.
pub fn apply_doc_ops(ops: &[Op]) -> Result<Document> {
    let mut doc: Option<Document> = None;

    for op in ops {
        match op {
            Op::DocCreate {
                doc_id,
                initial_body,
                frontmatter,
            } => {
                doc = Some(Document::new(
                    doc_id.clone(),
                    initial_body.clone(),
                    frontmatter.clone(),
                ));
            }
            Op::DocEdit { doc_id: _, patch } => {
                let d = doc.as_mut().ok_or_else(|| {
                    DocError::InvalidOp("DocEdit before DocCreate".to_string())
                })?;
                d.body = apply_text_patch(&d.body, patch)?;
            }
            Op::DocSetMeta {
                doc_id: _,
                key,
                value,
            } => {
                let d = doc.as_mut().ok_or_else(|| {
                    DocError::InvalidOp("DocSetMeta before DocCreate".to_string())
                })?;
                d.frontmatter.insert(key.clone(), value.clone());
            }
            Op::DocRemoveMeta { doc_id: _, key } => {
                let d = doc.as_mut().ok_or_else(|| {
                    DocError::InvalidOp("DocRemoveMeta before DocCreate".to_string())
                })?;
                d.frontmatter.remove(key);
            }
            // Skip graph ops
            Op::EntityCreate { .. }
            | Op::EntityUpdate { .. }
            | Op::EntityDelete { .. }
            | Op::EdgeAdd { .. }
            | Op::EdgeRemove { .. }
            | Op::EdgeUpdate { .. } => {}
        }
    }

    doc.ok_or_else(|| DocError::InvalidOp("no DocCreate op found".to_string()))
}

/// Result of applying graph operations — entities plus standalone edges from non-entity sources.
pub struct GraphState {
    pub entities: BTreeMap<EntityId, Entity>,
    /// Edges whose source is not an entity (doc or attachment sourced).
    pub standalone_edges: Vec<(NodeRef, Edge)>,
}

/// Apply a sequence of operations to build an Entity set and collect standalone edges.
pub fn apply_graph_ops(ops: &[Op]) -> Result<GraphState> {
    let mut entities: BTreeMap<EntityId, Entity> = BTreeMap::new();
    let mut standalone_edges: Vec<(NodeRef, Edge)> = Vec::new();

    for op in ops {
        match op {
            Op::EntityCreate { entity } => {
                entities.insert(entity.id.clone(), entity.clone());
            }
            Op::EntityUpdate { entity_id, props } => {
                let e = entities.get_mut(entity_id).ok_or_else(|| {
                    DocError::EntityNotFound(format!("{entity_id:?}"))
                })?;
                for (k, v) in props {
                    e.props.insert(k.clone(), v.clone());
                }
            }
            Op::EntityDelete { entity_id } => {
                entities.remove(entity_id);
            }
            Op::EdgeAdd { source, edge } => {
                match source {
                    NodeRef::Entity(entity_id) => {
                        let e = entities.get_mut(entity_id).ok_or_else(|| {
                            DocError::EntityNotFound(format!("{entity_id:?}"))
                        })?;
                        e.edges_out.push(edge.clone());
                    }
                    other => {
                        standalone_edges.push((other.clone(), edge.clone()));
                    }
                }
            }
            Op::EdgeRemove { source, edge_id } => {
                match source {
                    NodeRef::Entity(entity_id) => {
                        let e = entities.get_mut(entity_id).ok_or_else(|| {
                            DocError::EntityNotFound(format!("{entity_id:?}"))
                        })?;
                        e.edges_out.retain(|edge| edge.id != *edge_id);
                    }
                    _ => {
                        standalone_edges.retain(|(_, edge)| edge.id != *edge_id);
                    }
                }
            }
            Op::EdgeUpdate {
                source,
                edge_id,
                props,
            } => {
                match source {
                    NodeRef::Entity(entity_id) => {
                        let e = entities.get_mut(entity_id).ok_or_else(|| {
                            DocError::EntityNotFound(format!("{entity_id:?}"))
                        })?;
                        let edge = e
                            .edges_out
                            .iter_mut()
                            .find(|edge| edge.id == *edge_id)
                            .ok_or_else(|| DocError::EdgeNotFound(format!("{edge_id:?}")))?;
                        for (k, v) in props {
                            edge.props.insert(k.clone(), v.clone());
                        }
                    }
                    _ => {
                        if let Some((_, edge)) = standalone_edges.iter_mut().find(|(_, e)| e.id == *edge_id) {
                            for (k, v) in props {
                                edge.props.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
            }
            // Skip doc ops
            Op::DocCreate { .. }
            | Op::DocEdit { .. }
            | Op::DocSetMeta { .. }
            | Op::DocRemoveMeta { .. } => {}
        }
    }

    Ok(GraphState { entities, standalone_edges })
}
