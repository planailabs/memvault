# API wire conventions

How values are encoded across the HTTP API (`memvault-web`), the HTTP client
(`memvault-api::http`), and the MCP tools (`memvault-mcp`). Derived from the
existing surfaces; divergences found during the audit are called out as
**FIX** items to migrate toward.

## 1. Identifiers

There are **two distinct kinds** of identifier in memvault and they encode
differently on the wire. Getting this wrong is what produced the
`vfs_mkdir → entity:000…000` and bucket-decode bugs.

### 1a. Opaque IDs → bare lowercase hex

`ClusterId`, `DocId`, `EntityId`, `EdgeId`, `BucketId` (`memvault-core/src/ids.rs`)
are **random `[u8; 32]`** values (`::random()`), *not* content hashes. They are
opaque keys. Their parse path is `from_hex` and the node-label path is hex, so:

- **Node references** (entity / doc / attachment) use the `"type:hex"` **label**
  form, via `NodeRef::tag_label` / `NodeRef::from_tag_label`:
  - `entity:<64-hex>`
  - `doc:<64-hex>`
  - `file:<…>` — attachment; see 1b (the payload is a CID, so this should be a
    CID string, **FIX**: `tag_label` currently hex-encodes it).
- **Standalone opaque IDs** (bucket id, cluster id, edge id) are **bare
  lowercase hex** — no prefix, no `0x`.
- The byte-newtype default `serde` (a JSON array `[255, 12, …]`) and the
  `Display` impls (base58) are **not** the wire form. Use the hex helpers in
  `memvault_api::wire` (see [wire-dtos.md](wire-dtos.md)).

### 1b. CIDs / multihashes → canonical multibase string

Content identifiers are **CIDv1 multihashes** (`cid_from_bytes` =
BLAKE3 + dag-cbor; file chunks = raw + SHA2-256). Anything that is the
content-address of a block is a CID: block CIDs, the `cid` field of a stored
doc/entity, manifest CIDs, attachment CIDs, token CIDs, grant CIDs, share
proposal CIDs, rotation IDs. These are stored as `Vec<u8>` (the CID bytes).

- Encode them as the **canonical CID string** via
  `memvault_core::cid_to_string` / `cid_from_string` (e.g. `bafy…`) — **never**
  bare hex of the CID bytes. Use `memvault_api::wire::cid_str` /
  `cid_str_opt`.
- **`PeerId`** is a libp2p peer id, i.e. a multihash of the node pubkey; its
  canonical string is base58btc (`12D3Koo…`). **FIX**: it is currently
  hex-encoded on a few admin endpoints; migrate to the peer-id string.
- **FIX (current state):** much of the existing surface still hex-encodes CIDs
  (`/docs/{id}`, `/files/{cid}`, `GetParams.cid`, `put_doc`/`upload_file`
  returns, the `*Params.manifest_cid` MCP fields). Migrating CIDs to the
  canonical string is a single coordinated change across those fields, params,
  and route segments — do it together so the surface never mixes hex and CID
  strings.

### 1c. Tags

`[[scope, label], …]` — an array of 2-element string arrays.

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
