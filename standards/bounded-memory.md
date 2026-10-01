# bounded memory (every cache has a ceiling)

**Everything memvault keeps in memory has a limit, and limits that depend on
the machine are environment knobs documented in the README ("Memory").**

## Why this exists

The daemon grew until earlyoom killed it (11 GB RSS) while a researcher used
it: an unbounded signature cache, redb's default page cache, the search-index
writer's arena and full-body decodes (see
[listings-without-bodies.md](listings-without-bodies.md)) all added up, and a
killed daemon looks to the user like a UI that hangs "only sometimes".

## The rule

- **Caches are capped.** A `HashMap` used as a cache gets a maximum size (the
  grant signature cache clears at `GRANT_SIG_CACHE_MAX`), or an LRU.
- **Storage engines get explicit budgets:** redb's cache
  (`MEMVAULT_CACHE_MB`, default 256) and tantivy's writer
  (`MEMVAULT_INDEX_WRITER_MB`, default 50, at least 15). A new engine or
  buffer comes with its budget and its knob.
- **Knobs have safe floors**, so a typo can't starve the engine, and the
  README lists every knob with its default.
- **Embedders bound the allocator too**: `MALLOC_ARENA_MAX=2` for a long-lived
  daemon (many threads otherwise keep many arenas of freed memory).

## Checklist

1. Does this struct grow with data or requests? Give it a ceiling.
2. Is the ceiling machine-dependent? Make it an env knob with a floor, and
   document it in the README's "Memory" section.
3. Can a request allocate in proportion to the bucket's content? Then it's a
   listing problem: see [listings-without-bodies.md](listings-without-bodies.md).
