# memvault design

How memvault is built today. `README.md` covers how to use it; `standards/`
covers the rules every change must follow. This file explains the pieces and
how they fit. Keep it current (see `AGENTS.md`).

## 1. Shape of the system

memvault is a local-first knowledge base. Every node keeps the full vault in
one redb file of **content-addressed blocks**; everything else (indexes,
search, bucket tables) is derived from those blocks and can be rebuilt. Nodes
of a cluster replicate blocks peer to peer over libp2p. Clients (CLI, MCP
server, web UI) talk to a node either in-process (`LocalClient`) or over the
node's REST API (`HttpApiClient`).

```
 memctl CLI ─┐   memvault-mcp (stdio) ─┐   web UI (Dioxus, WASM) ─┐
             │                         │                          │
             ▼                         ▼                          ▼
        ┌──────────────── MemvaultClient trait ─────────────────────┐
        │  LocalClient (in-process)      HttpApiClient (REST + JWT) │
        └──────┬────────────────────────────────────────┬───────────┘
               │                                        │ /api/v1 (axum, memvault-web)
               ▼                                        ▼
   store (redb blocks + derived indexes) ◀── LocalClient inside the daemon
   tantivy search index · keystore               │
               ▲                                  │
               └──── memvault-swarm sync ◀──▶ libp2p (memvault-net) ◀──▶ peers
```

## 2. Crates

Dependencies point down; `memvault-core` is the root.

| Crate | Responsibility |
|---|---|
| `memvault-core` | IDs, CIDs, DAG-CBOR codec, the `Signed<T>` envelope, `BucketDecl`/`BucketRole`, `Visibility`/`Classification`, `QueryScope`, VFS/skill constants, `BLOCKSTORE_VERSION`. WASM-compatible. |
| `memvault-auth` | Sigchain record types (genesis, attestations, revocations, grants, join tokens, merges, shares), JWT, domain-separated signing. |
| `memvault-doc` | `Op` / `TextPatch`, `Document`, `Entity` / `Edge`, op application, body-link resolution. |
| `memvault-store` | redb blockstore, derived index tables, the single `ingest_block` write path, `reindex_block`. |
| `memvault-attach` | UnixFS chunking of files, attachment manifests, range reads. |
| `memvault-keystore` | Append-only key/value log (`keystore.mvks`), optional passphrase sealing, optional TPM. |
| `memvault-query` | Tantivy search index, audit queries, history, quotas. |
| `memvault-extract`, `-extract-abi`, `-extract-guest-*` | Extism host plus sandboxed WASM guests for text, PDF page rendering, OCR, audio transcription. |
| `memvault-api` | `MemvaultClient` trait, `LocalClient`, `HttpApiClient` (`http-client` feature), ACL, sigchain handling, rebuild, extraction pipeline, VFS, skills, wire DTOs (`memvault_api::wire`). |
| `memvault-net` | libp2p behaviours and protocol codecs (block exchange, join, auth, share), gossip topics. |
| `memvault-swarm` | The sync driver: RBSR reconciliation, block fetch/serve, sync vetting, join handling. |
| `memvault-web` | axum REST API under `/api/v1` (`server` feature), Dioxus web UI (`webui`), OIDC sign-in. Native deps are gated off for `wasm32`. |
| `memvault-mcp` | MCP server (rmcp, stdio transport) and `enroll` subcommand. |
| `memctl` | CLI, daemon (swarm + web/API), and the WASM client entry point. |
| `memvault-import` / `memvault-export` | Bulk import; vault export to a directory or tar. |
| `memvault-policy`, `memvault-summarize` | PII/egress policy and LLM summarisation. Not wired into any binary yet. |
| `memvault-smoke` | Integration tests (`TestNode` harness). |

## 3. Data model

**Nodes.** Three kinds of node, each addressed by a `NodeRef` with a string
label (`"type:hex"`):

| Node | Label | Built from |
|---|---|---|
| Document | `doc:<32-byte hex>` | ops `DocCreate` / `DocEdit(TextPatch)` / `DocSetMeta` / `DocRemoveMeta` |
| Entity | `entity:<32-byte hex>` | ops `EntityCreate` / `EntityUpdate` / `EntityDelete` |
| File | `file:<manifest CID hex>` | an attachment manifest plus chunk blocks |

The legacy `attachment:` prefix is accepted on read.

**Ops, not snapshots.** Documents and entities are never stored whole. Each
change is an `Op` wrapped in a signed envelope; the current state is rebuilt
by replaying a node's ops in `(wall_ns, cid)` order. A `TextPatch` is a list
of `Retain`/`Insert`/`Delete` counted in chars. `Op` variants are
append-only. (A Loro `CrdtDocument` wrapper exists in `memvault-doc` but is
not used.)

**Edges.** `EdgeAdd` / `EdgeRemove` / `EdgeUpdate` ops connect any node to any
node: `{id, relation, target: NodeRef, weight, props, provenance}`.

**Files.** Files of 64 KiB or less are one raw block; larger ones are 256 KiB
chunks in a balanced DAG-PB tree (UnixFS, IPFS-compatible, SHA2-256 CIDs). The
`AttachmentManifest` (name, MIME type, size, root) is a DAG-CBOR block; its
CID is the file's identity. Each upload also writes a signed `attachment`
envelope (tagged `_manifest:<hex>`) that carries bucket and metadata.

**Annotations.** Derived data about a node (text extraction, page renders,
OCR/transcripts) is a signed `annotation` envelope tagged `("_ann", target)`.
Annotations sync like everything else, so a node without a capability still
serves results a peer produced.

**Retraction.** Deleting is a signed `retraction` block tagged
`("retraction", target)`; nothing is erased. Reads hide retracted nodes unless
the scope asks for them.

**Buckets.** Every piece of content belongs to one bucket. A `BucketDecl`
holds name, owner (agent pubkey / node pubkey), default visibility and
classification, and a role: `Standard`, `Agent` (an agent's own bucket, id
derived from its pubkey) or `Legacy` (pre-bucket data, per node). A bucket is
bound to exactly one cluster. Buckets can be **merged**: a signed
`BucketMergeRecord` makes one bucket an alias of a canonical one at read and
ACL time; nothing is moved or re-signed. Buckets can be archived, including
the default one.

**Views.** Saved tag filters `{name, tags, bucket_id}`.

**VFS.** Each bucket has its own virtual filesystem. The root is an entity
found by tags `(vfs, root)` + `(bucket, <hex>)`; directories are entities of
kind `vfs:dir`, linked by `vfs:child` edges. A node can be mounted at several
paths; unlinking never deletes the node.

**Skills.** An entity of kind `skill` whose `skill:instruction`,
`skill:resource` and `skill:requires` edges collect docs and files; it can be
hydrated to disk as a `SKILL.md` bundle.

## 4. Storage

**One redb file** (`blocks.redb`, page cache `MEMVAULT_CACHE_MB`). The
`BLOCKS` table maps CID → bytes and is the only source of truth. Everything
else in the file is a derived table:

- lookup indexes: `BY_TAG`, `BY_AUTHOR`, `BY_TIME`, `BY_CAUSAL`,
  `BY_PROVENANCE`, `BY_BUCKET`, `CLUSTER_ORIGIN`;
- bucket state: `BUCKETS` (bucket → current decl CID), `BUCKET_CLUSTER`,
  `BUCKET_TRUST`, `SCOPE_MEMBERS`, `SCOPE_REGISTRY`, `VFS_ROOT`;
- trust/lifecycle state: `REVOCATIONS`, `RETRACTED`, `CONSUMED_TOKENS`,
  `ROTATIONS`, `SHARE_INBOX`, `SHARE_OUTBOX`;
- `LOCAL_IDENTITY` (peer id, cluster id, schema version).

Derived tables never sync and must be reconstructable from blocks
([blockstore-not-redb](standards/blockstore-not-redb.md)).

**CIDs.** Envelopes and other structured blocks are CIDv1, DAG-CBOR codec,
Blake3-256. File chunks are SHA2-256 with the raw or dag-pb codec. A block is
only ever stored under the CID of its own bytes; `put_block` verifies this.

**Envelopes.** Content is written as `Signed<T>`: `payload`, `author` (node
key), `tags`, `visibility`, `wall_ns`, `bucket_id` (v2+), node/agent
attestations (v3+), the node `signature` and an optional agent co-signature.
The version is chosen by which fields are set. `build_signed_envelope` is the
only way content envelopes are made; it refuses to write unsigned. The cluster
id is not part of the envelope: the receiving node stamps its own cluster
(`CLUSTER_ORIGIN`) at ingest.

**Bare records.** Sigchain records, grants, merge records and manifests are
signed structs stored as plain DAG-CBOR blocks without an envelope. Their tags
are synthesised from their shape when they are ingested locally, synced, or
re-indexed.

**One write path.** Every block, local or synced, goes through
`ingest_block(cid, bytes, &IngestMeta)`, which stores it and writes its
indexes ([block-ingestion](standards/block-ingestion.md)). `IngestMeta`
carries what the bytes can't (cluster, extra tags, author, time, bucket).

**Rebuild.** `reindex_block` re-derives a block's index rows from its bytes
and understands every historical format (legacy raw `BucketDecl`,
envelope-wrapped decls, annotations, attachments). `BLOCKSTORE_VERSION` (in
`memvault-core`, with a changelog) is bumped when derived indexing changes; a
node whose stored version is older rebuilds on startup (`rebuild_if_needed`),
and `memctl repair-index` forces it. There is no SQL database and no
migration directory: the rebuild is the migration.

**Search.** A Tantivy index beside the store (`blocks.tantivy/`, with a
`blocks.tantivy.version` marker) holds one row per node (`node_id`,
`node_type`, `body`, `label`, `tags`, `bucket_id`, `retracted`,
`entity_kind`, …). Rows are replaced by `node_id`. A format change wipes and
rebuilds it. Labels for listings come from this index, not from decoding
blocks ([listings-without-bodies](standards/listings-without-bodies.md)).

**Keystore.** `identity/keystore.mvks` holds the node seed, the admin key,
the cluster id and join-token state. It is sealed with XChaCha20-Poly1305
when `MEMVAULT_KEYSTORE_PASSPHRASE` is set.

## 5. Identity, trust and access

**Keys.** Each node has an ed25519 key (also its libp2p identity). Each agent
(an MCP client, the web UI's `_ui` agent, a service) has its own ed25519 key
in an identity directory. Clusters have one or more admin keys.

**Sigchain.** Trust is a chain of signed records, all blocks tagged
`("sigchain", <label>)`:

1. `AdminGenesis` — self-signed, binds the admin key to the cluster id
   (`memctl genesis`).
2. `NodeAttestation` — admin-signed, admits a node (minted when a node redeems
   a join token).
3. `AgentAttestation` — node-signed, binds an agent key and role to that node.
4. Revocations of nodes, agents and grants; admin admission and retirement;
   token redemptions; retractions; bucket merges.

**Join.** An admin issues a signed `JoinToken` (`mvjoin1:…`: role, validity,
max uses, initial grants). A new node redeems it over `/join/1.0`; an admin
peer checks it and replies with a `NodeAttestation` plus the bootstrap
sigchain blocks. Agents enrol by redeeming an agent token
(`memvault-mcp enroll`, `memctl agent enroll`).

**Roles.** Agent roles: `agent-host`, `auditor`, `service`, `admin` (admin
bypasses ACL). Node roles: `node`, `admin`.

**Grants.** An admin- or owner-signed `Grant` gives an audience (cluster,
peer, agent key, role) actions (`Read`, `Write`, `Admin`, `Egress`) on
buckets for a time window.

**ACL.** `check_bucket_access` resolves the bucket to its merge canonical,
requires an agent attested by a trusted node, then passes the bucket owner or
a valid, unrevoked, authentically signed grant from an authorised issuer.
HTTP handlers enforce it per object (`enforce_*_action`) and filter listings
with `filter_readable`; in-process `LocalClient` callers are trusted.

**HTTP auth.** Every request carries an EdDSA JWT signed by the agent key
(`sub` = agent pubkey, `scope` = read/write/admin); verification walks agent
attestation → node attestation → admin key. The web UI signs in by
`MEMVAULT_UI_AUTH`: `open` (everyone is `_ui`), `jwt` (a proxy supplies the
agent JWT) or `oidc`.

**Signing rule.** Any block that confers trust, authority, access or
visibility is signed, and ingest verifies the signature before acting on it
([sign-everything](standards/sign-everything.md)).

## 6. Sync

**Transport.** libp2p over TCP and QUIC (noise, yamux), with identify, ping,
mDNS, Kademlia and gossipsub. All protocol messages are length-prefixed
DAG-CBOR.

| Protocol | Purpose |
|---|---|
| `/ai-memvault/block/1.0` | request/response block exchange and range fingerprints |
| `/ai-memvault/join/1.0` | join-token redemption |
| `/ai-memvault/auth/1.0` | wired, not yet acted on |
| `/ai-memvault/share/1.0` | cross-cluster shares (not wired into the swarm yet) |

Gossip topic `ai-memvault/heads/v1/<cluster>` announces new heads after the
mesh forms.

**Reconciliation (RBSR).** On connect, and every 5 minutes, a node splits
time into 64 windows and sends each window's fingerprint (count and XOR of
CIDs over `BY_TIME`). The peer returns the CIDs of windows that differ;
matching windows cost nothing, so bandwidth tracks the difference. Missing
blocks are fetched in batches of 50, with one outstanding request per peer;
file manifests and chunks are chased explicitly because chunks have no time
index entry.

**Serving.** A node serves blocks only to attested nodes of its cluster (when
an admin key is pinned) on the same `BLOCKSTORE_VERSION`; private buckets are
withheld from remote peers.

**Receiving.** Each received block is checked (`verify_cid`), vetted
(`vet_sync_block`: sigchain records are signature-checked and get their
synthetic tags; invalid ones are dropped) and then ingested through
`ingest_block` like a local write.

## 7. API surfaces

**`MemvaultClient`** is the one interface every frontend uses. `LocalClient`
works directly on the store, index and keystore; `HttpApiClient` speaks REST
with a JWT minted from the agent's key. The two must answer identically
([client-parity](standards/client-parity.md)). `ClientArgs::connect` picks
local mode when `--db` is given, HTTP otherwise.

**Read scoping.** Reads take a `QueryScope` (buckets, view, retraction mode,
node kind, entity kind, detail), always intersected with the buckets the
caller may read ([query-scope](standards/query-scope.md),
[bucket-scoping](standards/bucket-scoping.md)). Writes need a concrete
bucket; frontends default to the caller's agent bucket.

**Wire format.** One serde shape per type, IDs as strings, built with the
helpers in `memvault_api::wire`
([api-wire-conventions](standards/api-wire-conventions.md),
[wire-dtos](standards/wire-dtos.md)).

**Frontends.**
- REST: axum under `/api/v1` in `memvault-web`, bound to 127.0.0.1, served by
  the daemon (port 8401). Also `/api/v1/events` (SSE from the in-process
  `EventBus`), metrics and health.
- MCP: `memvault-mcp`, stdio transport, backed by either client.
- CLI: `memctl` (with no arguments it runs a full node: swarm + web/API).
- Web UI: Dioxus, compiled to WASM and embedded in `memctl`; pages for notes,
  graph, files, VFS, views, buckets, skills, audit and admin.

## 8. Extraction

Text extraction runs inline when a file is written. Media work (page
rendering, OCR, audio transcription, Office→PDF via `soffice`) runs as
background jobs in sandboxed WASM guests under Extism, configured by
`extraction.toml`. Results are stored as annotations, so they sync.

## 9. Deployment

Binaries: `memctl` (CLI, daemon, embedded web UI), `memvault-mcp`,
`memvault-web`, `memvault-import`, `memvault-export`. The Nix flake builds
them (`package.nix`; a `slim` variant without the WASM client), provides a
NixOS module (`services.memvault`), a Docker image (`memctl daemon`, data in
`/var/lib/memvault`) and a two-node sync VM test (`tests/sync.nix`). Work in
the dev shell: `nix develop`.

On-disk layout and environment variables are listed in `README.md`.

## 10. Known gaps

Built but not wired in, and so not to be relied on:

- `BlockAccessToken` (per-bucket access for remote peers) is only built in
  tests; production requests send no token.
- The `EDGES` and `HEADS` tables are never written; edges live in ops.
- `BlockEncryption` (AES-GCM at rest) and the JSON-RPC Unix-socket module have
  no callers.
- The `share` protocol and federation gossip topic are only exercised by tests.
- `memvault-policy` and `memvault-summarize` have no consumers.
