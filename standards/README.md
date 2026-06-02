# memvault standards

Uniform conventions for memvault's API and wire surfaces, **derived from the
existing code** (HTTP server in `memvault-web`, the `MemvaultClient` trait +
HTTP client in `memvault-api`, the MCP tools in `memvault-mcp`, and the domain
types in `memvault-core` / `memvault-doc`).

These are the source of truth. When you add or change an endpoint, a client
method, an MCP tool, or a return type, **honour these standards and update them
in the same change if the convention itself evolves.**

| Document | Scope |
|----------|-------|
| [api-wire-conventions.md](api-wire-conventions.md) | How values are encoded on the wire: IDs, node labels, tags, list/get/create/error envelopes, bucket scoping, auth. |
| [wire-dtos.md](wire-dtos.md) | The "transmit existing shapes" rule: one serde shape per domain type, hex-encoded IDs via `memvault_api::wire`, no ad-hoc `json!` on the server and no `serde_json::Value` field-picking on the client. How to add a new endpoint. |
| [bucket-scoping.md](bucket-scoping.md) | Every document/file/graph-entity operation is scoped to a concrete bucket; no implicit all-buckets surface for content reads/writes. |
| [query-scope.md](query-scope.md) | `QueryScope` is the canonical read-query descriptor (bucket + view + retraction + kind + detail), threaded from the API surface to the store. |

## The two rules in one sentence each

1. **One shape per type.** A domain type has exactly one wire shape; the server
   serializes it and the client deserializes it with `serde` — neither side
   hand-rolls JSON.
2. **IDs are strings, never byte arrays.** Node references are `"type:hex"`
   labels; standalone IDs/CIDs are bare lowercase hex. Raw `[u8; 32]` JSON
   arrays must never appear on the wire.
