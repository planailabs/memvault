# API wire conventions

How values are encoded across the HTTP API (`memvault-web`), the HTTP client
(`memvault-api::http`), and the MCP tools (`memvault-mcp`). Derived from the
existing surfaces; divergences found during the audit are called out as
**FIX** items to migrate toward.

## 1. Identifiers

memvault's core ID types are byte newtypes (`memvault-core/src/ids.rs`):
`ClusterId`, `DocId`, `EntityId`, `EdgeId`, `BucketId` = `[u8; 32]`,
`PeerId` = `Vec<u8>`, `AgentId` = `String`. Their **default `serde` emits a
JSON array** (`[255, 12, …]`) and their dag-cbor form is a byte string — that
dag-cbor form is hashed into block CIDs and **must never change**.

Therefore, on the wire:

- **Node references** (anything that can be an entity, doc, or attachment) use
  the `"type:hex"` **label** form, via `NodeRef::tag_label` /
  `NodeRef::from_tag_label` (`memvault-core/src/ids.rs`):
  - `entity:<64-hex>`
  - `doc:<64-hex>`
  - `file:<hex>` (attachment/manifest CID; variable length). `attachment:` is
    accepted on input for back-compat.
- **Standalone IDs and CIDs** (bucket id, cluster id, edge id, doc cid,
  manifest cid, peer id, token cid, grant cid, rotation id) are **bare
  lowercase hex strings** — no prefix, no `0x`.
- **Tags** are `[[scope, label], …]` — an array of 2-element string arrays.
- **Never** serialize a byte-newtype with its default `serde` on the wire.
  Use the helpers in `memvault_api::wire` (see [wire-dtos.md](wire-dtos.md)).

### Consistency rules

- A "create" or "get" of a *node* returns its `"type:hex"` label in a field
  named `node_id`. (e.g. `graph_add`, `vfs_*`.)
- A "create"/"get" of a *non-node resource* returns its bare-hex id in a field
  named after the resource: `cid`, `bucket_id`, `edge_id`, `doc_id`.
- **FIX**: `POST /files` currently returns the manifest under `cid` as a
  `file:<hex>` label while `GET /files/{cid}` expects bare hex — clients must
  strip the prefix. New code: return the bare-hex manifest CID as `cid` and the
  label as `node_id`.
- **FIX**: `file_info` parses the manifest block as JSON, but manifests are
  dag-cbor. Manifest endpoints must return a decoded wire DTO, not the raw
  block bytes.

## 2. Response envelopes

- **List**: a bare JSON array `[ <item>, … ]`. (Not `{items: […]}`.)
  - **FIX**: `GET /nodes` returns `{count, nodes: […]}` and
    `GET /views/{name}/members` returns `{view, count, members: […]}`. Prefer a
    bare array; if a count is genuinely needed, document the wrapper here first.
- **Get one**: the item object, or `404` if absent.
- **Create**: `201` with the created resource's wire shape (or at minimum its
  id field per §1).
- **Mutation with no body** (delete/unlink/pin/archive/rename): `204 No Content`.
- **Error**: non-2xx with the `ApiError` body (`memvault-web/src/error.rs`).
  Clients surface non-2xx via `error_for_status`; never encode errors as a
  `200` with an `{"error": …}` field.

## 3. Bucket scoping

- The VFS and most graph/doc operations are **per-bucket**. Endpoints accept an
  optional `bucket` query/body parameter (bare hex). When omitted, the server
  resolves the caller's agent bucket (auth claims), or — for list/search —
  fans out across accessible buckets.
- A bucket parameter is always bare hex (§1), never a label.

## 4. Auth

- All `/api/v1/*` endpoints require a bearer JWT (`RequireAuth` / `RequireWrite`
  / `RequireAdmin`) except `/health` and `/metrics`.
- The JWT is issued by an enrolled agent identity (`AgentIdentity::issue_jwt`)
  and carries the agent pubkey; the server verifies it against the node-trust
  table + admin pubkey and resolves the agent's attestation.
- The HTTP client (`memvault_api::HttpApiClient`) auto-issues and renews the JWT
  from its `AgentIdentity`; callers never handle tokens directly.

## 5. URL shape

- All routes are under `/api/v1` (`HttpApiClient::url` prepends it).
- Path segments and query values are percent-encoded (`urlencoded`).
- Node labels appear in query params (`?node=entity:<hex>`), not path segments,
  because they contain `:`.
