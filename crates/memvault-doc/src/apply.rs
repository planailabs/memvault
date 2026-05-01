use std::collections::BTreeMap;

use memvault_core::EntityId;

use crate::attachment::AttachmentRef;
use crate::document::Document;
use crate::error::{DocError, Result};
use crate::graph::Entity;
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
            Op::AttachFile {
                doc_id: _,
                attachment,
            } => {
                let d = doc.as_mut().ok_or_else(|| {
                    DocError::InvalidOp("AttachFile before DocCreate".to_string())
                })?;
                let manifest_bytes =
                    serde_ipld_dagcbor::to_vec(attachment).map_err(|e| DocError::Encode(e.to_string()))?;
                let cid = memvault_core::cid::cid_from_bytes(&manifest_bytes);
                d.attachments.push(AttachmentRef {
                    name: attachment.name.clone(),
                    content_type: attachment.content_type.clone(),
                    size: attachment.size,
                    cid: cid.to_bytes(),
                });
            }
            Op::DetachFile {
                doc_id: _,
                attachment_name,
            } => {
                let d = doc.as_mut().ok_or_else(|| {
                    DocError::InvalidOp("DetachFile before DocCreate".to_string())
                })?;
                d.attachments.retain(|a| a.name != *attachment_name);
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

/// Apply a sequence of operations to build an Entity set.
pub fn apply_graph_ops(ops: &[Op]) -> Result<BTreeMap<EntityId, Entity>> {
    let mut entities: BTreeMap<EntityId, Entity> = BTreeMap::new();

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
                let e = entities.get_mut(source).ok_or_else(|| {
                    DocError::EntityNotFound(format!("{source:?}"))
                })?;
                e.edges_out.push(edge.clone());
            }
            Op::EdgeRemove { source, edge_id } => {
                let e = entities.get_mut(source).ok_or_else(|| {
                    DocError::EntityNotFound(format!("{source:?}"))
                })?;
                e.edges_out.retain(|edge| edge.id != *edge_id);
            }
            Op::EdgeUpdate {
                source,
                edge_id,
                props,
            } => {
                let e = entities.get_mut(source).ok_or_else(|| {
                    DocError::EntityNotFound(format!("{source:?}"))
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
            // Skip doc ops
            Op::DocCreate { .. }
            | Op::DocEdit { .. }
            | Op::DocSetMeta { .. }
            | Op::DocRemoveMeta { .. }
            | Op::AttachFile { .. }
            | Op::DetachFile { .. } => {}
        }
    }

    Ok(entities)
}
