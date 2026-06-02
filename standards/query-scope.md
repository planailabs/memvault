# QueryScope — the canonical query descriptor

Every read query over memvault content is described by one type,
`memvault_core::QueryScope`, threaded from the API surface down to the store.
Ad-hoc query parameter lists (`(limit, Option<BucketId>)`, a bare bucket, etc.)
are the legacy shape; new code uses `QueryScope`.

## The type

```rust
pub struct QueryScope {
    pub view: Option<String>,        // view filter (its required tags), None = none
    pub buckets: BucketSelector,     // which bucket(s) — see bucket-scoping.md
    pub retraction: RetractionMode,  // how retracted nodes participate
    pub kind: Option<NodeKind>,      // doc / file / entity, None = all
    pub detail: DetailLevel,         // per-node detail in the result
}
```

It composes the two cross-cutting concerns — **what bucket(s)** (see
[bucket-scoping.md](bucket-scoping.md)) and **what view/retraction/kind/detail**
— into a single value, so a query's scope is explicit and uniform instead of
spread across positional args and implicit defaults.

## The rule

- The canonical query methods take a `&QueryScope`: `list_scoped`,
  `search_scoped`, `get_doc_scoped`, `get_entity_scoped`. Prefer these.
- The convenience methods (`list_docs`, `search`, `list_entities`, `get_doc`,
  `get_entity`) are thin shims that build a `QueryScope` and delegate. Their
  bucket argument maps to `QueryScope.buckets`; retraction defaults per the
  caller's `caller_sees_retracted` policy.
- Server handlers build the `QueryScope` from request params (bucket, view,
  retracted visibility) and pass it down — they must not re-implement scoping
  ad hoc.
- `RetractionMode`/`include_retracted` is part of the scope, decided once from
  the auth claims (`caller_sees_retracted`), not sprinkled per call.

## Threading it through

A read flows: MCP tool / HTTP handler → build `QueryScope` (bucket from
`resolve_bucket`, retraction from claims, view/kind as requested) → a
`*_scoped` client method → store query that honours every field. When adding a
read path, thread a `QueryScope`; don't add another positional-arg query method.

## Migration status

`list_scoped`/`search_scoped`/`get_doc_scoped`/`get_entity_scoped` already take
`QueryScope` and the server search/list/get handlers build one. The remaining
convenience methods (`list_docs`/`search`/`list_entities`) still take
`(limit, bucket)` and internally route to the scoped path; they stay as shims
for back-compat. New surfaces should take `QueryScope` directly.
