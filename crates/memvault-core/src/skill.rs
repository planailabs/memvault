//! Shared "skill" wire constants.
//!
//! A skill is a first-class graph entity (`kind == SKILL_KIND`) that aggregates
//! its component nodes by typed edges: one-or-more instruction documents, zero
//! or more resource files/docs, and dependencies on other skills. The entity is
//! the manifest; the linked nodes are the content. Kept in `memvault-core` so
//! both the API/server helpers and the WASM web UI can share them without
//! linking the server-only `memvault-api` crate.

/// Entity `kind` marking a node as a skill.
pub const SKILL_KIND: &str = "skill";

/// Edge relation: skill → an instruction document (the SKILL.md prose). A skill
/// may have several, ordered by the [`SKILL_ORDER_PROP`] edge prop.
pub const SKILL_INSTRUCTION_REL: &str = "skill:instruction";

/// Edge relation: skill → a bundled resource (a file or doc — e.g. a script).
pub const SKILL_RESOURCE_REL: &str = "skill:resource";

/// Edge relation: skill → another skill it depends on.
pub const SKILL_REQUIRES_REL: &str = "skill:requires";

/// Edge prop (on a resource edge): the resource's relative path within the
/// hydrated bundle, e.g. `"scripts/analyze.py"`.
pub const SKILL_PATH_PROP: &str = "path";

/// Edge prop (on a resource edge): `true` if the resource should be written
/// with the executable bit set when the bundle is materialized to disk.
pub const SKILL_EXECUTABLE_PROP: &str = "executable";

/// Edge prop (on an instruction edge): integer ordering of instruction docs.
pub const SKILL_ORDER_PROP: &str = "order";

/// Entity prop: the skill's human-readable name.
pub const SKILL_NAME_PROP: &str = "name";

/// Entity prop: a one-line description (used for discovery/search).
pub const SKILL_DESCRIPTION_PROP: &str = "description";

/// Entity prop: when the skill should be used (the trigger text).
pub const SKILL_TRIGGER_PROP: &str = "trigger";

/// True if `kind` is a reserved, managed entity kind (skills, VFS dirs) that
/// must only be created or mutated through its dedicated API — never the
/// generic entity/node API. The generic create/delete paths reject these and
/// the graph view hides them, so their invariants (aggregate edges, bundle
/// structure) can't be bypassed.
pub fn is_reserved_entity_kind(kind: &str) -> bool {
    kind == SKILL_KIND || kind == crate::vfs::VFS_DIR_KIND
}
