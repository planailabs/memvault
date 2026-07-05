# memvault

Local-first, peer-to-peer knowledge base with a content-addressed block store, knowledge graph, full-text search, and MCP integration.

## Download binaries

Freshly built by our GitLab CI: [ » Download ](https://git.plan.ai/plan-ai/memvault/-/jobs/artifacts/trunk/browse/artifacts?job=artifact:memctl)

## Quick start (CLI)

```bash
# Store a note
memctl put "Meeting notes from today" --title "Meeting 2026-05-04" --tag "project:acme"

# Search
memctl search "meeting"

# Add entities and link them
memctl graph add person --prop name=Alice
memctl graph add project --prop name="Project X"
memctl graph link <alice-id> <project-id> works_on
```

## Quick start (MCP)

```bash
# Add to Claude Code — local mode, talks to the redb file directly
claude mcp add memvault -- memvault-mcp --db ~/.local/share/memvault/blocks.redb
```

Run `/mcp` inside Claude Code to verify the connection, then just talk to it:

```
> Store a note in memvault: the staging DB password rotates every 90 days, tag it ops:staging
> Search memvault for everything we know about the api gateway
> Add Alice and the payments service to the knowledge graph and link her as maintainer
> What did I save about the acme project last week?
> Attach this PDF to memvault and extract its text
```

See [MCP server](#mcp-server) below for HTTP mode, all flags, and manual `.mcp.json` configuration.

## Quick start (cluster)

> [!NOTE]
> Clustering is optional — a single node works fully standalone.
> Run `memctl genesis` to start a cluster; add peers whenever you want replication across machines.

```bash
# Node A — create the cluster and start a node
memctl genesis
memctl daemon --listen /ip4/0.0.0.0/tcp/4001

# Node A — issue a single-use join token (keystore-only, works while the daemon runs)
memctl token issue --node-role node --label node-b
# → mvjoin1:...

# Node B — join with the token, then start a node pointed at node A
memctl cluster-join mvjoin1:...
memctl daemon --bootstrap /ip4/<node-a-ip>/tcp/4001
# cluster-join stashes the token; the daemon redeems it automatically
# over /join/1.0 once the nodes connect
```

Blocks now sync both ways. Try it:

```bash
# Node B — write a document
memctl put "Deploy notes for the api gateway" --title "Deploy 2026-07-05" --tag "project:gateway"

# Node A — it syncs over
memctl search "gateway"
memctl list --limit 5

# Grow the knowledge graph — entities and edges sync like any other block
memctl graph add service --prop name=api-gateway
memctl graph add person --prop name=Alice
memctl graph link <alice-id> <service-id> maintains
memctl graph query <alice-id>

# Check cluster health — peer count should show the other node
memctl status
```

## Architecture

memvault stores everything as content-addressed blocks in a single [redb](https://github.com/cberner/redb) database file (`blocks.redb`). Secondary indexes (by tag, author, time, bucket, causal links, provenance) are derived from the blocks and can be rebuilt at any time with `memctl repair-index`.

Three types of objects live in the store:

| Type | ID format | Example |
|------|-----------|---------|
| **Document** | `doc:<hex>` | Notes, memos, any text with frontmatter |
| **Entity** | `entity:<hex>` | Knowledge graph nodes (person, project, concept, skill, ...) |
| **File** | `file:<hex>` | Files stored as UnixFS DAGs (IPFS-compatible) |

Any object can link to any other via typed, weighted edges. An edge from a document to an entity, or from a file to another file, works the same way.

Layered on top of blocks and edges:

- **Buckets** — every write is scoped to a bucket. Agents get their own default bucket; capability grants control who can read or write which bucket, and buckets can be merged into a canonical one (a read/ACL alias overlay — nothing is moved or re-signed).
- **VFS** — a per-bucket virtual filesystem: directories, paths, and tree views over any node, with a node mountable at multiple paths.
- **Views** — saved tag filters for scoping queries.
- **Skills** — graph entities that aggregate instruction docs and resource files by typed edges, hydratable to disk as a `SKILL.md` bundle.
- **Cross-cluster shares** — federation via share proposals between clusters, approved or rejected through an inbox/outbox flow.

## MCP server

The MCP server (`memvault-mcp`) exposes memvault to LLM agents via the Model Context Protocol over stdio.

### Two modes

**Local mode** — direct access to a redb file, no daemon needed (takes priority when `--db` is set):

```bash
memvault-mcp --db ~/.local/share/memvault/blocks.redb
```

**HTTP mode** — talks to a running daemon, authenticated with an enrolled agent identity (every request carries a JWT signed with the agent's ed25519 key):

```bash
memvault-mcp --url http://127.0.0.1:8401 --identity-dir ~/.local/share/memvault/agents/claude
```

### Configuration

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--db` | `MEMVAULT_DB` | -- | redb path (local mode, bypasses HTTP) |
| `--url` | `MEMVAULT_URL` | `http://127.0.0.1:8401` | Daemon API URL (HTTP mode) |
| `--identity-dir` | `MEMVAULT_IDENTITY_DIR` | `<data-dir>/identity/ui_agent` | Agent identity dir (HTTP mode) |
| `--default-tags` | `MEMVAULT_DEFAULT_TAGS` | -- | Comma-separated `scope:label` tags |
| `--default-visibility` | `MEMVAULT_DEFAULT_VISIBILITY` | `internal` | `internal`, `federated`, or `public` |
| `--agent-id` | `MEMVAULT_AGENT_ID` | derived from pubkey | Display label for the agent's default bucket |

### Agent enrollment (HTTP mode)

An agent identity is created by redeeming a join token against a running daemon:

```bash
# On the cluster: issue an agent token
memctl token issue --agent-role agent-host --label claude

# On the agent host: exchange it for a credential
memvault-mcp enroll --server http://127.0.0.1:8401 --token mvjoin1:... --agent-id claude
# → credential written to <data-dir>/agents/claude/

# Run the MCP server with that identity
memvault-mcp --url http://127.0.0.1:8401 --identity-dir <data-dir>/agents/claude
```

Agent roles: `agent-host`, `auditor`, `service`, `admin`. Every write an agent makes without an explicit bucket lands in its own agent bucket, derived from its ed25519 pubkey.

### MCP tools (62)

**Documents & tags:**

| Tool | Description |
|------|-------------|
| `memvault_put` | Store a document with optional title and tags |
| `memvault_get` | Retrieve a document by hex-encoded doc ID |
| `memvault_search` | Full-text search across docs, entities, and files |
| `memvault_list` | List recent documents, optionally filtered by tag |
| `memvault_list_all` | List all nodes (docs, entities, files), optionally filtered by view |
| `memvault_doc_history` | Operation history for a document |
| `memvault_retract` | Soft-delete any node (creates a tombstone) |
| `memvault_tag` / `memvault_untag` | Add / remove `scope:label` tags on any node |
| `memvault_get_tags` | Effective tags for a node |

**Files:**

| Tool | Description |
|------|-------------|
| `memvault_upload_file` | Upload a local file by absolute path |
| `memvault_read_range` | Read a byte range from a file |
| `memvault_extract_text` | Extract text from PDF, DOCX, HTML, Markdown |
| `memvault_file_info` | Manifest metadata (name, MIME type, size) |
| `memvault_pin` / `memvault_unpin` | Pin / unpin against garbage collection |

**Knowledge graph:**

| Tool | Description |
|------|-------------|
| `memvault_graph_add` | Create an entity (person, project, concept, ...) |
| `memvault_get_entity` / `memvault_list_entities` | Fetch one / list entities |
| `memvault_graph_link` | Link two entities by hex ID |
| `memvault_graph_query` | List all edges for an entity |
| `memvault_traverse` | Walk the graph from any node up to a max depth |

**Cross-type linking:**

| Tool | Description |
|------|-------------|
| `memvault_link` | Link any two nodes: `entity:<hex>`, `doc:<hex>`, `file:<hex>` |
| `memvault_edges` | List all edges (in + out) for any node |
| `memvault_unlink` | Remove an edge by ID |

**VFS** (`memvault_vfs_*`): `ls`, `tree`, `resolve`, `find`, `mkdir`, `link`, `unlink`, `mv` — organise nodes into a per-bucket directory hierarchy; a node can be mounted at multiple paths, and unlinking never deletes the underlying node.

**Skills** (`memvault_skill_*`): `publish`, `list`, `get`, `rename`, `delete`, `link_resource`, `unlink_resource`, `hydrate` — bundle instruction docs and resources as a skill entity and materialize it to disk as a `SKILL.md` bundle.

**Buckets & agents** (`memvault_bucket_*`, `memvault_agent_rename`): `list`, `create`, `get`, `rename`, `archive`, `merge`, `unmerge`, `merges`, `grants_list` — manage bucket scoping, merge overlays, and capability grants.

**Views** (`memvault_view_*`): `list`, `create`, `update`, `delete` — saved tag filters.

**Cross-cluster shares** (`memvault_share_*`): `inbox`, `outbox`, `decide` — review and approve/reject federation proposals (two-step: preview with `confirm: false`, then commit).

**Export, status & audit:**

| Tool | Description |
|------|-------------|
| `memvault_export` | Export a single node to a temp file |
| `memvault_export_vault` | Export the whole vault (or a filtered subset) to a directory or tar |
| `memvault_status` | Block count, doc count, peer count, uptime |
| `memvault_audit` | Query the audit log, optionally by op kind |

### Adding to Claude Code

**Option 1: Project-scoped** (recommended) — add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "memvault": {
      "command": "memvault-mcp",
      "args": ["--db", "/home/user/.local/share/memvault/blocks.redb"],
      "env": {
        "MEMVAULT_DEFAULT_TAGS": "agent:claude"
      }
    }
  }
}
```

**Option 2: Via CLI** — project scope by default, `--scope user` for all projects:

```bash
claude mcp add memvault -- memvault-mcp --db /home/user/.local/share/memvault/blocks.redb
claude mcp add --scope user memvault -- memvault-mcp --db /home/user/.local/share/memvault/blocks.redb
```

**HTTP mode** (when a daemon is running — enroll first, see above):

```json
{
  "mcpServers": {
    "memvault": {
      "command": "memvault-mcp",
      "args": ["--url", "http://127.0.0.1:8401"],
      "env": {
        "MEMVAULT_IDENTITY_DIR": "/home/user/.local/share/memvault/agents/claude"
      }
    }
  }
}
```

After adding, restart Claude Code or run `/mcp` to verify the server is connected. You should see 62 tools available under the `memvault_*` prefix.

**First use** — initialize the database if it doesn't exist yet:

```bash
memctl genesis
```

## memctl CLI

Management CLI. Targets a local store via `--data-dir` (looks for `blocks.redb` inside) or `--db` (path to the redb file directly), or a running daemon via `--url` with an enrolled identity. `--agent-id` binds writes to an enrolled agent's identity and bucket; `--bucket-id` targets a specific bucket.

### Commands

Run `memctl <command> --help` for full flags; `memctl` with no arguments runs a full node (web UI + P2P swarm).

```
# Documents
memctl genesis                    Initialize a new cluster
memctl put <text> [--title T]     Store a document
memctl get <cid>                  Retrieve a block by CID
memctl search <query>             Full-text search
memctl list [--limit N]           List recent documents
memctl history <doc-id>           Document operation history
memctl retract <cid> --reason R   Soft-delete
memctl doc <links|backlinks|dangling|reindex-links>   Document link tooling

# Knowledge graph & skills
memctl graph add <kind> --prop k=v    Create entity
memctl graph link <src> <tgt> <rel>   Link entities
memctl graph query <from>             Traverse edges
memctl skill <publish|list|get|...>   Manage skill bundles

# Cluster
memctl daemon [--listen A] [--bootstrap A,..]   Run a node (P2P swarm + web/API server)
memctl cluster-join <mvjoin1:...>               Join an existing cluster
memctl token <issue|list|revoke>                Join-token management
memctl agent <enroll|list|...>                  Agent enrollment management
memctl peers / peer-id / status                 Node info
memctl node-attest <pubkey>                     Attest a pre-genesis peer
memctl uncluster                                Detach this node from its cluster

# Buckets, grants & shares
memctl bucket <list|create|merge|...>   Bucket management
memctl grant <...>                      Capability grants
memctl share <...>                      Cross-cluster share proposals

# Import & export
memctl export / export-blocks           Export vault contents / raw blocks
memctl import-files / import-docs       Bulk import

# Maintenance
memctl repair-index               Rebuild all indexes from blockstore
memctl audit [--limit N]          Show audit log
memctl gc                         Garbage-collect unpinned blocks
memctl sigchain / diff-blocks     Inspect trust chain / compare stores
```

## Web UI

The web UI is served by the daemon on port 8401 (by default) and provides:

- **Notes** -- create, edit, view with markdown rendering, version history
- **Graph** -- interactive force-directed knowledge graph with entity/doc/file nodes, focus mode, and drag-to-rearrange
- **Files** -- upload, preview, download, text extraction
- **Skills** -- browse and inspect skill bundles
- **Buckets** -- bucket status, merges, and capability grants
- **VFS** -- browse the virtual filesystem hierarchy
- **Views** -- manage saved tag filters
- **Audit** -- filterable audit trail with human-readable descriptions
- **Admin** -- cluster status, token and agent management

Global search (`Ctrl+K` or the search button) searches across all node types -- document bodies, entity properties, filenames.

## Node references

Cross-type linking uses a unified `NodeRef` format:

```
entity:a1b2c3d4e5f6...    # 32-byte hex entity ID
doc:9f8e7d6c5b4a...       # 32-byte hex document ID
file:4a5b6c7d...          # hex-encoded manifest CID
```

These work everywhere: MCP tools (`memvault_link`, `memvault_edges`), the REST API (`/api/v1/links`), and the web UI's quick-link forms. The legacy `attachment:` prefix on old edges is still understood on read.

## Storage layout

```
~/.local/share/memvault/
  blocks.redb           # Primary block store + all indexes (incl. cluster ID)
  text_index.json       # Full-text search index cache (auto-rebuilt if stale)
  identity/             # Node identity: libp2p key + keystore.mvks (admin key, pinned genesis, tokens)
  identity/ui_agent/    # Local agent credential used by the web UI
  agents/<agent-id>/    # Enrolled agent credentials (private_key.pem, attestation, agent.json)
  trust/                # Trust anchors
  extraction.toml       # Optional media extraction config (see below)
```

## Media extraction

Beyond plain text extraction (always on), the daemon can transcribe audio
(Whisper via candle), OCR images (ocrs), and pre-render document pages with
a selectable text layer (hayro + pdfplumber) — all as sandboxed WASM
plugins running in background jobs after upload. Results are cached as
annotation blocks and sync across the cluster like any other block; a node
without a capability still serves results produced by peers.

Everything is configured in `<data_dir>/extraction.toml` (path overridable
via `MEMVAULT_EXTRACTION_CONFIG`). **Every option is optional** — with no
file at all, PDF/image page rendering works out of the box and
transcription/OCR report `unavailable` until models are provisioned:

```toml
# Directory mapped read-only into plugin sandboxes as /models.
models_dir = "/var/lib/memvault/models"
# Office→PDF conversion (docx/odt/pptx/…): autodetects `soffice` on PATH.
#libreoffice_path = "/usr/bin/soffice"

[render]                  # PDF/image page pre-rendering
#enabled = false
dpi = 144                 # raster resolution
max_pages = 200           # hard cap per document
page_batch = 8            # pages per sandbox call (bounds guest memory)

[whisper]                 # audio transcription
model_dir = "whisper-small"   # relative to models_dir; unset = disabled
language = "auto"
max_duration_secs = 7200

[ocr]                     # image OCR + scanned-PDF text layers
#enabled = false
detection_model = "ocrs/text-detection.rten"
recognition_model = "ocrs/text-recognition.rten"

[limits]                  # per-plugin sandbox bounds (wall-clock, no fuel)
audio_timeout_ms = 900000
ocr_timeout_ms = 120000
pdfrender_timeout_ms = 300000
memory_max_pages = 40960  # 64 KiB wasm pages (2.5 GiB)
```

Model provisioning (no auto-download — models are explicit):

```
<models_dir>/
  whisper-small/          # any candle-compatible Whisper model dir
    config.json
    tokenizer.json
    model.safetensors
  ocrs/
    text-detection.rten   # from the ocrs project's released models
    text-recognition.rten
```

Disabling a capability (unset prerequisites or `enabled = false`) means:
uploads don't queue the op, reads report `unavailable` with a reason, and
nothing is cached as a failure — enabling it later takes effect on the
next read with no cleanup.

## Index rebuild

If search results are missing or indexes seem corrupt:

```bash
memctl repair-index
```

This does a two-phase rebuild:
1. Clears and rebuilds all store secondary indexes (BY_TAG, BY_AUTHOR, BY_TIME, etc.) from the raw blocks
2. Rebuilds the full-text search index and saves it to `text_index.json`

The text index cache includes a format version. When memvault is updated with index format changes, the cache is automatically discarded and rebuilt on next startup.
