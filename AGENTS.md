# Memvault — Agent Instructions

Rules for any AI agent (Claude Code, Copilot, etc.) working on the memvault crates.

## API & wire standards

- **Honour the standards in [`standards/`](standards/).** They define the
  uniform API/wire conventions (ID encoding, response envelopes, bucket
  scoping, auth) and the "one wire shape per type, no ad-hoc JSON" rule. Read
  them before adding or changing an endpoint, a `MemvaultClient` method, an MCP
  tool, or an API return type.
- **Keep the standards current.** If a convention genuinely needs to change,
  update the relevant file in `standards/` in the *same* change — code and
  standard must not drift.
- **Transmit existing shapes; minimize custom JSON.** Serialize the domain type
  (with `memvault_api::wire` hex helpers / `*Wire` DTOs) and deserialize it with
  `serde`. Do not hand-build `serde_json::json!({…})` on the server or
  field-pick a `serde_json::Value` on the client.
- **Keep the README current — this is important.** `README.md` documents the
  user-facing surface: MCP tools (names + count), `memctl` command syntax, CLI
  flags, auth flows, web UI pages, node-ref formats, and the storage layout.
  When a change touches any of those, update the README in the *same* change.
  Verify against the code (clap derives, `#[tool(...)]` attributes), don't
  guess — stale docs have already bitten us (hyphenated commands, `api.token`,
  an 18-tool list when the server had 62).

## CID integrity

- **Never store a block without CID verification.** Use `store.put_block(cid, data)` which checks `cid == hash(data)`. The method `put_block_unchecked` was removed for this reason — do not reintroduce it.
- **Never synthesize a block and store it under a foreign CID.** If you need a placeholder, compute the CID from the actual content. The blockstore is content-addressed: `CID == hash(block_bytes)` is an invariant that sync, verification, and deduplication depend on.
- **Synced blocks must pass CID verification.** The block exchange protocol transfers `(cid, data)` pairs. The receiver calls `put_block` which rejects mismatches. Do not bypass this.

## Backward compatibility

- **All changes must work with legacy data.** Data created before buckets, before envelope v2, and before the current CID scheme must continue to load. Test with `memctl repair-index` on a pre-migration store.
- **Envelope format changes are additive.** New fields use `#[serde(default)]` so old envelopes deserialize correctly. Old envelopes without `bucket_id` or `cluster_id` are valid — they belong to the default bucket.
- **`reindex_block` is the source of truth for migration.** It must handle all historical block formats (legacy raw BucketDecl, envelope-wrapped BucketDecl, annotation blocks, attachment envelopes). When adding a new block type, add detection logic to `reindex_block`.
- **Never modify existing migration files** in `server/migrations/`. Create new ones.
- **Parse bucket decls with `LocalClient::parse_bucket_decl`** which handles both envelope-wrapped (`payload.BucketCreate`) and legacy raw formats.

## Bucket scoping

- **All new data must have a bucket.** Write operations (`store_op`, `upload_file`, `bucket_create`) call `resolve_bucket(bucket)` which falls back to the cluster's default bucket when `None` is passed. Never write data without a bucket_id in the envelope metadata.
- **The envelope JSON must include `bucket_id` and `cluster_id`.** These fields are needed for `reindex_block` to reconstruct the `BY_BUCKET` and `CLUSTER_ORIGIN` indexes after sync. Without them, synced data is invisible to bucket-scoped queries.
- **Bucket binding is exclusive.** A bucket can only be bound to one cluster. `store.bind_bucket` enforces this — rebinding to a different cluster is an error.
- **The default bucket cannot be archived.** `bucket_archive` checks this.
- **VFS is per-bucket.** Each bucket has its own VFS root identified by tags `(vfs, root)` + `(bucket, <hex>)`. There is no global VFS.

## Testing

- **Tests before fixes.** For any bug that has a reproducible failure mode, write a failing test in `memvault-smoke` BEFORE the fix lands. The diff should include: (1) the failing test, (2) the fix, (3) the test now passing. This pattern catches "the fix landed in path A but the same bug lives in path B" — which has bitten us repeatedly (e.g. node-key vs libp2p-key divergence existed in two daemon paths; the join-response storing untagged blocks mirrored the sync-receiver bug). A repro test makes the bug's shape explicit and forces you to find every place that shape exists.
- **Add tests to `memvault-smoke`**, not inline in the crate being modified. The smoke crate has a `TestNode` harness that creates isolated stores with random cluster IDs.
- **Run `cargo test -p memvault-smoke`** before submitting. All 118+ tests must pass.
- **Gossipsub tests are `#[ignore]`** due to timing sensitivity. Run with `--include-ignored` to verify P2P gossip propagation.
- **Test bucket lifecycle:** create → write data → genesis → attach → sync → verify data visible on both nodes.
- **Test legacy compatibility:** create data without bucket fields, run `repair-index`, verify data appears in the default bucket.

## Sync protocol

- **RBSR (range-based set reconciliation)** is used for initial sync. The store's `range_fingerprint(start_ns, end_ns)` computes an XOR fingerprint over CIDs in a time range. Matching windows are skipped — bandwidth is proportional to the diff.
- **Block exchange** uses request-response (not gossipsub) for reliable delivery. Gossipsub is used for ongoing head announcements after mesh formation.
- **Visibility enforcement** happens in the block exchange server: private buckets are not served to remote peers without a valid BlockAccessToken (BAT).
- **The `_manifest` tag** maps manifest CIDs to their attachment envelope CIDs, enabling `get_file_manifest` to find metadata for legacy files without a separate manifest block.

## Build

- `cargo check --workspace` to verify all crates compile.
- `cargo test -p memvault-smoke -p memvault-api` for the full test suite.
- When modifying web UI: run `dx build` to check WASM compilation.
- Feature gate WASM-incompatible deps behind `server` or `daemon` features.
