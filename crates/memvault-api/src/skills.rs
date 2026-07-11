//! Skill operations as free functions over [`MemvaultClient`].
//!
//! A skill is a graph entity (`kind == SKILL_KIND`) that aggregates its
//! component nodes by typed edges. This module holds the composition logic
//! (mirroring `crate::vfs`): each function is generic over the client and
//! expresses a skill operation in terms of the graph/doc/search primitives, so
//! the logic lives once. The `MemvaultClient::skill_*` trait methods delegate
//! here; `LocalClient` runs them in-process, while the HTTP client overrides
//! the trait methods to thread through the dedicated `/skills` endpoints.
//!
//! `rename` is intentionally absent: it needs an in-place `EntityUpdate`, which
//! has no composable client primitive, so it stays a per-client trait method.
//! Bundle hydration lives in [`crate::skill_hydrate`].

use std::collections::BTreeMap;

use memvault_core::{
    BucketId, DetailLevel, DocId, EdgeId, EntityId, NodeRef, QueryScope, Visibility,
};
use memvault_doc::{Document, Edge, Entity};

use crate::client::MemvaultClient;
use crate::error::Result;
use crate::types::{NodeDetail, SkillBundle, SkillInfo, SkillResource, SkillSpec};

/// Parse an `"entity:<hex>"` node id into an [`EntityId`].
fn parse_entity_node_id(node_id: &str) -> Option<EntityId> {
    let hex_str = node_id.strip_prefix("entity:")?;
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(EntityId(arr))
}

/// Build a [`SkillResource`] from an outgoing skill edge.
fn skill_resource_from_edge(edge: &Edge) -> SkillResource {
    SkillResource {
        edge_id: edge.id.clone(),
        node: edge.target.tag_label(),
        relation: edge.relation.clone(),
        path: edge
            .props
            .get(memvault_core::SKILL_PATH_PROP)
            .and_then(|v| v.as_str())
            .map(str::to_string),
        executable: edge
            .props
            .get(memvault_core::SKILL_EXECUTABLE_PROP)
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        order: edge
            .props
            .get(memvault_core::SKILL_ORDER_PROP)
            .and_then(|v| v.as_i64()),
        label: None,
    }
}

/// Publish a new skill: create the manifest entity and, if an inline body is
/// given, a Document linked as the primary instruction. Returns the skill id.
pub async fn publish<C: MemvaultClient + ?Sized>(
    client: &C,
    spec: SkillSpec,
    vis: Visibility,
    bucket: Option<&BucketId>,
) -> Result<EntityId> {
    let mut props: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    props.insert(
        memvault_core::SKILL_NAME_PROP.to_string(),
        serde_json::Value::String(spec.name.clone()),
    );
    if let Some(d) = &spec.description {
        props.insert(
            memvault_core::SKILL_DESCRIPTION_PROP.to_string(),
            serde_json::Value::String(d.clone()),
        );
    }
    if let Some(t) = &spec.trigger {
        props.insert(
            memvault_core::SKILL_TRIGGER_PROP.to_string(),
            serde_json::Value::String(t.clone()),
        );
    }
    let entity = Entity {
        id: EntityId::random(),
        kind: memvault_core::SKILL_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    let skill_id = client.add_entity_internal(entity, vis, bucket).await?;

    if let Some(body) = spec.instruction_body {
        let doc = Document::new(DocId::random(), body, BTreeMap::new());
        let doc_id = doc.id.clone();
        client.put_doc(doc, vec![], vis, bucket).await?;
        let mut eprops: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        eprops.insert(
            memvault_core::SKILL_ORDER_PROP.to_string(),
            serde_json::Value::from(0),
        );
        let edge = Edge {
            id: EdgeId::random(),
            relation: memvault_core::SKILL_INSTRUCTION_REL.to_string(),
            target: NodeRef::Doc(doc_id),
            weight: None,
            props: eprops,
            provenance: None,
        };
        client
            .add_link(&NodeRef::Entity(skill_id.clone()), edge, vis)
            .await?;
    }
    Ok(skill_id)
}

/// List skills (manifest summaries only). Narrows to `kind == SKILL_KIND` via
/// the scoped query's `entity_kind` filter.
pub async fn list<C: MemvaultClient + ?Sized>(
    client: &C,
    limit: usize,
    bucket: Option<&BucketId>,
) -> Result<Vec<SkillInfo>> {
    let mut scope = QueryScope::all()
        .with_entity_kind(Some(memvault_core::SKILL_KIND.to_string()))
        .with_detail(DetailLevel::Full);
    if let Some(b) = bucket {
        scope = scope.with_bucket(Some(b.clone()));
    }
    let rows = client.list_scoped(&scope, limit).await?;
    let mut out = Vec::new();
    for n in rows {
        let Some(id) = parse_entity_node_id(&n.node_id) else {
            continue;
        };
        let (name, description, trigger) = match &n.detail {
            Some(NodeDetail::Entity { props, .. }) => (
                props
                    .get(memvault_core::SKILL_NAME_PROP)
                    .and_then(|v| v.as_str())
                    .unwrap_or(&n.label)
                    .to_string(),
                props
                    .get(memvault_core::SKILL_DESCRIPTION_PROP)
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                props
                    .get(memvault_core::SKILL_TRIGGER_PROP)
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            ),
            _ => (n.label.clone(), None, None),
        };
        out.push(SkillInfo {
            id,
            name,
            description,
            trigger,
            retracted: n.retracted,
        });
    }
    Ok(out)
}

/// Assemble a skill bundle: the manifest plus its outgoing component edges,
/// grouped by relation. Returns `None` if the id is not a skill entity.
pub async fn get<C: MemvaultClient + ?Sized>(
    client: &C,
    id: &EntityId,
) -> Result<Option<SkillBundle>> {
    let Some(entity) = client.get_entity(id).await? else {
        return Ok(None);
    };
    if entity.kind != memvault_core::SKILL_KIND {
        return Ok(None);
    }
    let info = SkillInfo {
        id: id.clone(),
        name: entity
            .props
            .get(memvault_core::SKILL_NAME_PROP)
            .and_then(|v| v.as_str())
            .unwrap_or(&entity.kind)
            .to_string(),
        description: entity
            .props
            .get(memvault_core::SKILL_DESCRIPTION_PROP)
            .and_then(|v| v.as_str())
            .map(str::to_string),
        trigger: entity
            .props
            .get(memvault_core::SKILL_TRIGGER_PROP)
            .and_then(|v| v.as_str())
            .map(str::to_string),
        retracted: false,
    };
    let skill_ref = NodeRef::Entity(id.clone());
    let edges = client.edges_of(&skill_ref).await?;
    let mut instructions = Vec::new();
    let mut resources = Vec::new();
    let mut requires = Vec::new();
    for (source, edge) in edges {
        // Outgoing edges only (skill → component).
        if source != skill_ref {
            continue;
        }
        let res = skill_resource_from_edge(&edge);
        match edge.relation.as_str() {
            memvault_core::SKILL_INSTRUCTION_REL => instructions.push(res),
            memvault_core::SKILL_RESOURCE_REL => resources.push(res),
            memvault_core::SKILL_REQUIRES_REL => requires.push(res),
            _ => {}
        }
    }
    instructions.sort_by_key(|r| r.order.unwrap_or(0));
    Ok(Some(SkillBundle {
        info,
        instructions,
        resources,
        requires,
    }))
}

/// Retract a skill entity. The linked component docs/files are left intact
/// (they may be shared by other skills).
pub async fn delete<C: MemvaultClient + ?Sized>(
    client: &C,
    id: &EntityId,
    reason: &str,
) -> Result<()> {
    let node_id = format!("entity:{}", hex::encode(id.0));
    client.retract_node_internal(&node_id, reason).await
}

/// Link an existing node (doc/file/entity) to a skill under `relation`,
/// carrying an optional bundle `path` and executable bit. Returns edge id.
pub async fn link_resource<C: MemvaultClient + ?Sized>(
    client: &C,
    skill_id: &EntityId,
    target: &NodeRef,
    relation: &str,
    path: Option<&str>,
    executable: bool,
    vis: Visibility,
) -> Result<EdgeId> {
    let mut props: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    if let Some(p) = path {
        props.insert(
            memvault_core::SKILL_PATH_PROP.to_string(),
            serde_json::Value::String(p.to_string()),
        );
    }
    if executable {
        props.insert(
            memvault_core::SKILL_EXECUTABLE_PROP.to_string(),
            serde_json::Value::Bool(true),
        );
    }
    let edge = Edge {
        id: EdgeId::random(),
        relation: relation.to_string(),
        target: target.clone(),
        weight: None,
        props,
        provenance: None,
    };
    client
        .add_link(&NodeRef::Entity(skill_id.clone()), edge, vis)
        .await
}

/// Remove a resource/instruction/requires edge from a skill.
pub async fn unlink_resource<C: MemvaultClient + ?Sized>(
    client: &C,
    skill_id: &EntityId,
    edge_id: &EdgeId,
) -> Result<()> {
    client
        .remove_link_from(&NodeRef::Entity(skill_id.clone()), edge_id)
        .await
}
