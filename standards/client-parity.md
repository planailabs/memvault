# client parity (local and HTTP clients answer the same)

**Whatever works through `LocalClient` must work through `HttpApiClient`, with
the same fields filled.** The web UI runs on either: on the local client in
`open` mode, and on an HTTP client with the caller's token in `jwt`/`oidc`
mode (see the README, "Signing in to the web UI").

## Why this exists

In `jwt` mode the Files page was empty, then listed every file as "unnamed,
0 B":

- `/api/v1/audit` had no `attachment_cid`/`entity_id`, so the HTTP client's
  `AuditRecord`s came back without them and the page skipped every upload.
- `/files/{cid}/manifest` sent the raw DAG-CBOR block labelled
  `application/json`; the HTTP client's `.json()` failed and the page used its
  defaults.

Both passed every local-client test.

## The rule

- **Every field of a trait return type travels.** If `AuditRecord` has a
  field, the endpoint's response carries it and the HTTP client parses it
  (better: one shared DTO, see [wire-dtos.md](wire-dtos.md)).
- **The body is what the `Content-Type` says.** JSON endpoints answer
  `Json(..)`; binary goes out as `application/octet-stream` or its real type.
- **Server functions are tested through `HttpApiClient`.** A UI feature gets an
  e2e test in `memvault-web/tests/mcp_http_e2e.rs` that calls the client
  methods it uses over HTTP and checks the fields it shows.
- **Listings never show what the caller may not read.** Content reads are
  scoped to one bucket, the caller's agent bucket by default
  ([bucket-scoping.md](bucket-scoping.md)); the lists that are cross-bucket by
  nature (buckets, search hits, nodes, the audit log) are filtered on the
  server (`filter_readable`, `Readable`, `enforce_bucket_action`). Another
  agent's bucket answers 404, not 403 (`enforce_bucket_action` answers 404,
  with no ids, whenever the caller can't read the bucket), and doesn't appear
  in lists, traversals, edge lists, pins, merges or the event stream.
