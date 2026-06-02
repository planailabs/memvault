# Bucket scoping — every doc/file/entity operation is bucketed

memvault content (documents, files, graph entities — and their VFS, tags,
edges, audit) is **per-bucket**. Every operation that reads or writes that
content must be scoped to a concrete bucket. There is no implicit "all
content" surface for these operations.

## The rule

- **Writes** (`put_doc`, `upload_file`, `add_entity`, `add_link`, `tag`,
  `vfs_*`, …) target exactly one bucket. The bucket is explicit (the caller's
  `bucket` argument) or resolved to the caller's **agent bucket**
  (`ensure_agent_bucket`). Never write content without a bucket.
- **Reads** of bucketed content (`list_docs`, `search`, `list_entities`,
  `list_all`, `audit`, VFS resolve/ls/tree) default to a **single concrete
  bucket** — the explicit one, else the agent bucket. They do **not** silently
  fan out across every accessible bucket: that made `memvault_list` return the
  same all-buckets set for different `bucket=` values, and made per-bucket VFS
  roots undiscoverable.
- **Cross-bucket** reads are opt-in and explicit (e.g. an admin aggregation
  like `bucket_grants_list`), and must be documented as such on the call.

## Why

Bucketed reads keep results deterministic and isolated: a query in bucket A
never returns bucket B's content. Two concrete bugs came from violating this —
`list` ignoring the bucket (returned a global set) and `ensure_root` scanning a
global, capped index (dropping a bucket's VFS root). See
[query-scope.md](query-scope.md) for how scoping is expressed.

## How it's applied

- **MCP tools** resolve via `resolve_bucket` (concrete, agent-bucket default)
  for content reads/writes; `resolve_bucket_query` (optional, cross-bucket) is
  reserved for the documented aggregation tools only.
- **Server query methods** (`list_docs_ex`, `list_entities_ex`, the `*_scoped`
  methods) filter by the bucket and must cap the *filtered* result, never the
  pre-filter global scan (capping first drops a bucket's items — the VFS-root
  bug).
- **HTTP** carries the bucket as a `bucket=<hex>` query/body param on every
  content endpoint; the client must forward it (the `list_docs` client once
  dropped it).

## Applied / remaining

**Applied:** writes (`put`/`upload_file`/`graph_add`/`vfs_*`) already resolve a
concrete bucket; the `list_docs_ex`/`list_entities_ex` server queries filter by
bucket and cap the filtered result; the `memvault_list` and
`memvault_list_entities` tools now use `resolve_bucket` (agent-bucket default).

**Remaining (needs a cross-crate signature change, do as a focused pass):**
- `list_all` (`memvault_list_all`, node listing) — bucket must thread through
  the `MemvaultClient::list_all` *required* method, `HttpApiClient`,
  `ListNodesQuery` + `list_nodes` (`.with_bucket`), `LocalClient::list_all`'s
  bucket loop, and the export caller. Server-side it lands as
  `QueryScope::all().with_bucket(..)` (see query-scope.md).
- `audit` (`memvault_audit`) — needs a `bucket` field on
  `memvault_query::AuditQuery` and the store audit query before the tool can
  scope it; currently cross-bucket.
