# state that must sync lives in the blockstore, not just redb

**If an operation's effect must be visible cluster-wide, it must produce a
content-addressed BLOCK in the blockstore. Writing only to a local redb side
table makes the change invisible to every other node.**

## Why

Only **blocks** replicate. RBSR sync exchanges blocks by CID; on ingest a block
is stored, re-tagged, and run through the store notifier → sigchain watcher. The
redb **side tables** — `RETRACTED`, `BY_TAG`, `BY_BUCKET`, `SCOPE_MEMBERS`,
`CONSUMED_TOKENS`, the alias cache, the Tantivy index — are **derived indexes
over the blocks**, rebuilt locally (`rebuild_store`). They are *not* sync units.

So a write that touches only a side table is **local-only**:

- `bucket_unmerge` retracted a `BucketMergeRecord` by writing `record_retraction`
  (the `RETRACTED` table) and nothing else. The unmerge never reached peers —
  they kept applying the merge. Fixed by publishing a signed `retraction` block
  the watcher applies to `RETRACTED` on every node.
- A `BucketMergeRecord`/`Grant` that *was* a block still went invisible on peers
  because the sync classifier didn't re-tag it (the index is derived, and a bare
  struct carries no body tags). Same root cause from the other side: the durable
  thing is the block; the index must be reconstructable from it.

## The rule

For any state change whose effect is cluster-scoped — retraction, merge/unmerge,
grant/revoke, attestation, bucket decl/rename/archive, membership — **emit a
block**:

1. **Emit a block, not just a table write.** Prefer a signed envelope via
   `build_signed_envelope` (tags + bucket live in the *signed body*, so
   `reindex_block` recovers them on the receiver and the store notifier fires —
   no classifier arm needed). A bare signed struct (`BucketMergeRecord`,
   `Grant`) also works but then needs an arm in
   `memvault_api::admission::classify_record` (and a `SigchainKind`) that
   verifies it and derives its tags/author/time from the record — the same
   arm serves local writes, sync and rebuild.
2. **Tag it `("sigchain", <label>)`** if a node must *react* to it on ingest
   (cache invalidation, applying it to a side table). Add a watcher arm
   (`install_sigchain_notifier` → the `<label>` dispatch) that does the local
   apply. The watcher fires for local writes AND synced blocks, so one arm
   covers both.
3. **Side tables are derived, never authoritative.** Anything in a redb side
   table must be reconstructable from blocks by `rebuild_store`. If it can't be,
   it's data that will silently diverge — make it a block.
4. **Heal divergence with a blockstore migration.** When you move state from a
   local table into blocks, bump `BLOCKSTORE_VERSION` and add a `rebuild_store`
   phase that backfills the blocks from the existing table (idempotent,
   node-agnostic — derive any timestamps/keys from the record, not the wall
   clock, so every node converges identically). See `derived-indexes.md` for the
   cache-over-the-store framing and `exhaustive-lookups.md` for the scan.
5. **The converse: BLOCKS holds only blocks.** Every key in BLOCKS is a CID of
   its value (`put_block`/`ingest_block` refuse anything else). Genuinely
   node-local state — attachment pins, health probes — gets its own redb
   table, never a made-up key in BLOCKS, where RBSR would offer it to peers
   and `rebuild_store` would classify it as content.

## Smell test

Before merging a write path, ask: *"if a peer never saw my redb, would it learn
about this?"* If the only artifact is a `*_table.insert(...)`, the answer is no —
emit a block.
