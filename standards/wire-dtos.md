# Wire DTOs — transmit existing shapes, minimize custom JSON

## The rule

**A domain type has exactly one wire shape.** The server serializes that shape
with `Json(value)`; the client deserializes it with `resp.json::<T>()`. Neither
side hand-rolls JSON with `serde_json::json!({…})`, and neither side
reconstructs a value by field-picking a `serde_json::Value`.

This was *not* the case historically — the audit found the server hand-building
`json!` per handler and the client hand-parsing each response (`parse_bucket_info`,
`parse_audit_record`, manual `edges_of`/`list_entities` parsing, …). Every such
spot is a place where the two sides can silently drift (and did: the
`vfs_mkdir → entity:000…000` bug, the bucket decode errors, the `get_tags`
empty-result bug all came from server/client shape mismatches).

## How to encode IDs without changing block formats

Core IDs and the graph types (`Entity`, `Edge`, `Document`) are stored in
dag-cbor blocks; their `serde` impls are load-bearing for CIDs and **must not
change**. So we encode IDs as hex *at the field level* using the helpers in
`memvault-api/src/wire.rs`:

```rust
use memvault_api::wire::hex_id;            // [u8; 32] <-> hex string
use memvault_api::wire::hex_id_opt;        // Option<[u8;32]>
use memvault_api::wire::hex_bytes;         // Vec<u8> <-> hex string

#[derive(Serialize, Deserialize)]
pub struct BucketInfo {
    #[serde(with = "hex_id")]
    pub id: BucketId,
    #[serde(with = "hex_id_opt", default)]
    pub cluster_id: Option<ClusterId>,
    // … plain fields serialize normally …
}
```

Two cases:

1. **API return types** (`memvault-api/src/types.rs`: `BucketInfo`,
   `DocSummary`, `GrantInfo`, `NodeStatus`, `RotationInfo`, `TokenStatus`,
   `ShareProposalInfo`, `View`, `TraversalHit`). These are *not* block types,
   so annotate their ID fields with the `hex_*` helpers directly. The type then
   serializes uniformly with hex IDs and is transmitted as-is: server returns
   `Json(bucket_info)`, client decodes `Vec<BucketInfo>`. No DTO, no
   hand-parsing.

2. **Block types** (`Entity`, `Edge`, `Document`, `NodeRef`). Their `serde` is
   frozen, so use a thin wire DTO in `memvault-api/src/wire.rs`
   (`EntityWire`, `EdgeWire`, …) with `From<&Domain>` / `into_domain()`
   conversions. Server returns `Json(EntityWire::from(&e))`; client decodes
   `EntityWire` and calls `.into_domain()`.

`NodeRef` already has its canonical string form (`tag_label` /
`from_tag_label`); wire DTOs use `String` fields for node references and
convert via those.

## Adding a new endpoint (checklist)

1. Is there a domain type for the payload? If yes, **reuse its wire shape** —
   either it's already serde-clean (e.g. `View`) or it carries `hex_*`
   annotations / has a `*Wire` DTO. Do not invent a new per-endpoint struct.
2. Server handler: `Ok(Json(value))` for the typed shape; `201`/`204` per
   [api-wire-conventions.md](api-wire-conventions.md) §2.
3. Client method: `resp.json::<T>()` — no `serde_json::Value`, no `json!`.
4. IDs follow [api-wire-conventions.md](api-wire-conventions.md) §1
   (labels for nodes, bare hex otherwise).
5. Add the round-trip to the MCP HTTP harness
   (`memvault-web/tests/mcp_http_e2e.rs`) and, if it's a new tool, to the
   in-crate tool tests (`memvault-mcp` `server::tool_tests`).

## Migration status

The shared helpers live in `memvault-api/src/wire.rs`. Types are migrated to
the standard incrementally; each migration deletes the corresponding
server-side `json!` builder and client-side hand-parser. Track remaining
non-conforming handlers/methods against the audit in this directory's history.
