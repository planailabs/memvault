# one block-ingestion path (local and remote converge)

**Every block that enters the store — whether it was just created on this node
or received from a peer over sync — goes through the single
`MemvaultStore::ingest_block` primitive. There is no separate "local" vs
"remote" storage path. Admission control (who is allowed to add this block, and
what synthetic metadata to stamp on a bare-struct block) happens *before* ingest
and feeds that one path; it never forks into a second way of writing a block.**

This is the structural companion to [sign-everything.md](sign-everything.md)
(*verify on ingest, before acting*) and
[blockstore-not-redb.md](blockstore-not-redb.md) (*the block is the sync unit;
redb tables are derived*). Those say *what* must be true of a block and its
indexes; this one says *there is exactly one funnel that makes it true*.

## Why

The store had grown two ways to admit a block:

- locally-created blocks called `insert_envelope(cid, bytes, meta)` — the caller
  knew the full metadata and the store indexed exactly that;
- synced blocks branched: sigchain shapes went through `insert_envelope` with a
  synthesised meta, while content went through `put_block` + `reindex_block`
  (+ a separate `reindex_bucket_decl`), which *extracted* metadata from the
  bytes instead.

Two paths means two chances to disagree. Real bugs lived in that gap: synced
content got no `CLUSTER_ORIGIN` entry, synced grants/merges landed untagged and
became invisible (`list_bucket_grants`/`bucket_merges` returned empty), bucket
binding needed a separate live call, and the two paths used different
transaction boundaries. Anything indexed on one path but not the other diverges
silently between nodes.

## The rule

1. **One store primitive.** All block writes funnel through
   `MemvaultStore::ingest_block(cid, bytes, &IngestMeta)`. It stores the block,
   extracts the canonical indexing metadata from the bytes, layers the
   caller's `IngestMeta`, writes **every** secondary index, reconstructs bucket
   metadata, and fires the index notifier — all in **one** write transaction.
   `insert_envelope` is a thin behaviour-preserving shim over it; prefer
   `ingest_block` directly for new call sites.

2. **The bytes are the source of truth.** Tags, author, `wall_ns`, causal,
   provenance and `bucket_id` are extracted from the block bytes via
   `EnvelopeView` — the same way for a local write and a sync. A locally-created
   envelope and that same envelope arriving on a peer index *identically*; the
   write path does not depend on provenance.

3. **`IngestMeta` only fills what the bytes can't carry.** It is not an
   alternative source of metadata — it is the gap-filler:
   - `cluster_id` — never part of a signed envelope, so the **receiving node**
     always stamps its own cluster (drives `CLUSTER_ORIGIN` and live bucket
     binding, for local and synced blocks alike);
   - `extra_tags` / `author` / `wall_ns` — for **bare-struct sigchain blocks**
     (`AdminKeyAdmission`, `NodeAttestation`, `Grant`, `BucketMergeRecord`, …),
     which are *not* envelopes and carry no such fields. The admission gate
     supplies the synthetic `("sigchain", label)` marker, the signer pubkey, and
     the ingest time so the sigchain index + watcher see the block.

   For an ordinary signed envelope every override is absent or equal to the
   bytes, so the layering is a no-op — which is exactly why one path is safe.

4. **Admission is a gate in front of ingest, not a second path.** The
   provenance-specific work stays *before* `ingest_block` and produces an
   `IngestMeta`:
   - **local writes** sign the envelope (`build_signed_envelope`) and stamp the
     node's own cluster;
   - **synced blocks** verify content-addressing (`verify_cid`) and run the
     signature/shape classifier (`vet_sync_block` → `validate_sigchain_for_sync`)
     to decide `Drop` vs `Ingest(meta)`. A dropped block never reaches ingest;
     an accepted one is ingested through the same primitive as a local write.

5. **`reindex_block` is the offline-rebuild sibling, not a parallel path.** It
   shares `ingest_block`'s `extract_meta` + `write_block_indexes` helpers, so a
   rebuild produces byte-identical indexes; it only skips the block store (the
   block already exists) and reports whether the bytes were an envelope.

## Smell test

When adding code that stores a block, ask: *am I calling `ingest_block` (or its
`insert_envelope` shim), or am I hand-rolling `put_block` + index writes?* If the
latter, you've reopened the second path — fold it back in. If a block needs
metadata the bytes don't carry, that belongs in `IngestMeta`, computed by an
admission gate in front of the one path — never a divergent write.
