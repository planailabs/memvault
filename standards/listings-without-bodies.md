# listings without bodies (don't decode what you don't show)

**A listing, summary, label or count must not decode a node's full block.
Decode only the fields it shows.**

A document's block holds its whole body, and a body can be a book. Decoding
it into a `serde_json::Value` to read the title allocates the whole text, per
listed document, per request. glibc keeps freed memory, so the daemon's RSS
stays where the peak was.

## Why this exists

The notes list (`list_docs` → `doc_summary` / `list_docs_scan`) decoded every
listed `DocCreate` block with `deserialize_block`, only to read
`frontmatter.title`, `tags` and `wall_ns`. A bucket of converted books (500 rows
per page) took the daemon from ~400 MB to 7 GB+ and got it OOM-killed. The
graph explorer did the same with `get_doc_scoped`, only to label nodes.

## The rule

- **Read heads, not blocks.** Deserialize into a struct that names only the
  fields you need (`DocHead`, `EnvKind`, `EnvTags`, `EnvWall`,
  `EnvAttribution` in `memvault-api/src/local.rs`; `AuditHead` for audit
  rows; `OpNameHead` for the link-alias index) with
  `memvault_store::deserialize_block_as`.
  serde skips the unnamed fields (the body) without allocating them, for both
  DAG-CBOR and legacy JSON blocks.
- **Labels come from the index.** A node's title is `resolve_label` (HTTP:
  `GET /api/v1/labels/{node_id}`), never `get_doc` for display.
- **Tags are read with `envelope_tags`.** Envelope tags come as `{scope,label}`
  objects or `[scope, label]` pairs; `serde_json::from_value::<Vec<(String,
  String)>>` silently drops the object form.
- **Per-row fetches are bounded and concurrent.** When a list needs one more
  call per row (a file's manifest), run them a few at a time (a semaphore),
  never all at once and never strictly one by one.
- `deserialize_block` (the whole block as a `Value`) is for one node the caller
  asked to *open*, and for small blocks (edges, grants, manifests).

## Checklist when adding a listing

1. Which fields does the row show? Decode exactly those.
2. Is the title/label available from the index? Use it.
3. Does the row need a second call? Bound its concurrency.
4. Try it on a bucket with a few hundred large documents and watch the RSS.
