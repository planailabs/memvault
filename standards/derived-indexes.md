# derived indexes (don't scan all of it)

**An operation on a hot path must not scan every entity/doc/block to find a few
matching records. Use a scoped store query, or maintain a derived index/cache
table keyed by what you look up.**

This is the performance companion to [exhaustive-lookups.md](exhaustive-lookups.md):
that one says *don't cap a correctness scan*; this one says *don't make it a
full scan in the first place*.

## The choices, in order of preference

1. **Scoped store query.** The blockstore already maintains secondary indexes:
   `query_by_tag(scope, label, …)` (e.g. `edge_source`, `entity`, `doc`,
   `grant`), `query_by_bucket(bucket, …)`, `query_by_author`, `query_by_time`,
   and the `SCOPE_MEMBERS` partitions behind `QueryScope`. Reach for these
   first — they turn "all entities" into "the few that match".
   - VFS child listing is already correct here: `list_children` →
     `edges_of(parent)` → `query_by_tag("edge_source", parent)`, which is
     O(children), not O(entities).

2. **`QueryScope`.** For content reads (docs/entities/search) prefer the
   `QueryScope` path (bucket + view + retraction + kind) — it consults the
   scoped member-sets instead of re-deriving membership by scanning. See
   [query-scope.md](query-scope.md).

3. **A derived index / cache table.** When no existing index answers the
   lookup, add a redb table keyed by the lookup (in `memvault-store/tables.rs`)
   and treat it as a *cache over the blockstore*, not a source of truth:
   - The blockstore (or an exhaustive scan over it) remains authoritative.
   - The table is **populated/repaired on read** from that authoritative scan,
     and may be written on the relevant mutation too.
   - It must be **safe stale or absent**: a miss falls back to the scan, which
     repopulates it; conflicting/duplicate state is reconciled deterministically
     on that path.
   - Example: `VFS_ROOT` (bucket → root entity). `vfs::ensure_root` runs on
     every VFS op; it reads the table (O(1)) and only falls back to the uncapped
     entity scan on a miss, repopulating the table and collapsing any duplicate
     roots to the deterministic (sorted-first) one.

## When a full scan is acceptable

- One-off / cold paths: migrations, rebuilds, audit dumps, admin tooling.
- Genuinely unavoidable cross-cutting reconciliation — but then it must be off
  the per-request hot path (startup, a periodic tick, or a cache-miss repair),
  not run on every call.

## Checklist when adding a lookup

1. Is this on a per-request hot path? If no, a scan may be fine.
2. Does an existing `query_by_*` / `QueryScope` answer it? Use it.
3. If not, add a derived index table — cache over the store, repaired on read,
   safe when stale, reconciled deterministically. Never a source of truth.
4. Combine with [exhaustive-lookups.md](exhaustive-lookups.md): the
   authoritative reconciliation scan behind the cache is uncapped.
