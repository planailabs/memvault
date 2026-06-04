# sign every block that confers trust, authority, or state — and verify on ingest

**Any block whose ingestion changes another node's trust, authority, access, or
visibility must be signed, and the code that acts on it must verify the
signature before acting. An unsigned (or unverified) block must never drive a
security, trust, or visibility decision.**

This is the authenticity companion to [blockstore-not-redb.md](blockstore-not-redb.md)
(*emit a block so it syncs*) — once it's a syncable block, it's attacker-reachable,
so it has to be signed and checked.

## Why

Sync is an open ingress: any peer can hand you a block. If the receiver applies
it without verifying who signed it, a peer can:

- hide arbitrary content (forge a `retraction`),
- grant itself access (forge a `Grant`),
- join the cluster (forge a `NodeAttestation`),
- redirect reads (forge a `BucketMergeRecord`).

A retraction was added that synced but was applied **without a signature check**
— any peer could have hidden any block cluster-wide. Fixed by gating the watcher
on `retraction_signature_ok` (the envelope must carry a valid node signature).

## The rule

1. **Produce a signed block.** Use `build_signed_envelope` (node signs; agent
   co-signs when bound) for content/state writes, or a purpose-built signed
   record (`BucketMergeRecord`, `Grant`, `NodeAttestation`, …) for bare structs.
   Never emit an unsigned envelope on a path that confers trust/authority/state.
2. **Verify the signature on ingest, before acting.** The sync classifier
   (`validate_sigchain_for_sync`) verifies bare-struct records
   (`verify_signature`) before storing; a watcher/notifier arm that *applies* a
   block (mutates trust, ACL, `RETRACTED`, the alias map) must verify authorship
   first (`verify_envelope_authorship` → `Valid`/`NodeSigned`, or a record's own
   `verify_signature`). `BadSignature`/`AgentNotTrusted` ⇒ drop.
3. **Authenticity is mandatory; authority may be deferred.** Like
   `NodeAttestation` and merges: accept an *authentic* block (signature
   verifies) and re-check *authority* (was the signer allowed to do this — the
   target's author, an admin, the attesting node) in the eventually-complete
   trust scan. Never defer authenticity — an unverifiable signature fails closed.
4. **Fail closed on the security-relevant paths.** A genuine "pre-trust /
   unattributed" write may read as `NoSidecar`; that's tolerable for *read*
   filtering, but a path that *mutates* trust/ACL/visibility must require a
   verifying signature, not accept `NoSidecar`.

## Smell test

For every block a watcher or sync path consumes: *"if a random peer forged this,
what could they do to me — and what stops them?"* If the answer is "nothing
checks the signature," it's a forgeable-authority bug.
