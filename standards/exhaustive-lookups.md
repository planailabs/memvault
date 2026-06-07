# exhaustive lookups

**A lookup whose correctness depends on seeing every matching record must not
carry a finite cap. Use `usize::MAX`.**

A magic limit (`500`, `1000`, `4096`, `10`, …) on a store/index scan silently
drops records once the data outgrows it. For *pagination/display* that is fine —
the caller asked for a page. For *resolution, membership, ACL, trust, dedup, and
"find the one canonical record"* it is a latent, data-size-dependent bug: it
passes every test on a small fixture and fails in production once a bucket,
agent set, or grant list grows past the cap.

## Why this exists

`vfs::ensure_root` scanned `list_entities(500, …)` to find the single VFS root
of a bucket. In a bucket with >500 entities the root fell outside the window, so
`ensure_root` minted a *second* root — `mkdir` wrote a directory under one root
while `resolve`/`ls`/`tree` read from another. Symptom: "mkdir says created but
the path is not found; ls/tree 500." Nothing was wrong with the VFS logic; the
cap was.

## The rule

When a query backs any of these, pass `usize::MAX` (no cap):

- **Resolution / uniqueness** — finding the one root, the one canonical bucket,
  the latest decl, etc. Missing it produces duplicates or "not found".
- **Membership tests** — "does this node have *any* CID in this bucket set?"
  The matching CID may be the 11th; a cap of 10 wrongly excludes it.
- **ACL / authorization** — every grant on a bucket must be considered, or
  access is mis-decided (a security bug). Caps here are never acceptable.
- **Trust** — every node/agent attestation and revocation must be seen.
- **Dedup / reconciliation / pruning** — must consider every candidate, or the
  set is left partially processed.

When a cap *is* correct, it is because the caller wants a bounded page for a
human or an external API. In that case:

- the limit comes from the **caller** (a `limit`/`max_depth` parameter), not a
  hardcoded constant buried in an internal helper, and
- the surface is **user-facing** (an MCP tool result, an HTTP list endpoint, a
  UI table) — never an internal correctness step.

## Overflow

Derived caps must not panic. Use `limit.saturating_mul(n)`, never `limit * n`
(a caller passing `usize::MAX` would overflow).

## Checklist when adding a scan

1. Is the result used to *decide* something (resolve, authorize, dedup) or to
   *display* a page? Decide → `usize::MAX`. Display → caller-supplied limit.
2. Never hardcode `500`/`1000`/etc. in an internal helper.
3. Any `limit * n` becomes `limit.saturating_mul(n)`.
