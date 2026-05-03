# memvault

Local-first, peer-to-peer knowledge base with a content-addressed block store, knowledge graph, full-text search, and MCP integration.

## Quick start (standalone)

```bash
# Initialize a cluster
memctl genesis

# Store a note
memctl put "Meeting notes from today" --title "Meeting 2026-05-04" --tag "project:acme"

# Search
memctl search "meeting"

# Add entities and link them
memctl graph-add person --prop name=Alice
memctl graph-add project --prop name="Project X"
memctl graph-link <alice-id> <project-id> works_on
```

## Architecture

memvault stores everything as content-addressed blocks in a single [redb](https://github.com/cberner/redb) database file (`blocks.redb`). Secondary indexes (by tag, author, time, causal links, provenance) are derived from the blocks and can be rebuilt at any time with `memctl repair-index`.

Three types of objects live in the store:

| Type | ID format | Example |
|------|-----------|---------|
| **Document** | `doc:<hex>` | Notes, memos, any text with frontmatter |
| **Entity** | `entity:<hex>` | Knowledge graph nodes (person, project, concept, ...) |
| **Attachment** | `attachment:<hex>` | Files stored as UnixFS DAGs (IPFS-compatible) |

Any object can link to any other via typed, weighted edges. An edge from a document to an entity, or from a file to another file, works the same way.

## MCP server

The MCP server (`plan-ai-memvault`) exposes memvault to LLM agents via the Model Context Protocol over stdio.

### Two modes

**HTTP mode** (default) -- talks to a running daemon:

```bash
plan-ai-memvault --url http://127.0.0.1:8401
```

**Local mode** -- direct access to a redb file, no daemon needed:

```bash
plan-ai-memvault --db ~/.local/share/memvault/blocks.redb
plan-ai-memvault --db /path/to/blocks.redb --cluster-id abc123...
```

### Configuration

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--url` | `MEMVAULT_URL` | `http://127.0.0.1:8401` | Daemon API URL (HTTP mode) |
| `--token-file` | `MEMVAULT_TOKEN_FILE` | `~/.local/share/memvault/api.token` | Bearer token (HTTP mode) |
| `--db` | `MEMVAULT_DB` | -- | redb path (local mode, bypasses HTTP) |
| `--cluster-id` | `MEMVAULT_CLUSTER_ID` | all zeros | Cluster ID hex (local mode) |
| `--default-tags` | `MEMVAULT_DEFAULT_TAGS` | -- | Comma-separated `scope:label` tags |
| `--default-visibility` | `MEMVAULT_DEFAULT_VISIBILITY` | `internal` | `internal`, `federated`, or `public` |

### MCP tools (18)

**Documents:**

| Tool | Description |
|------|-------------|
| `memvault_put` | Store a document with optional title and tags |
| `memvault_get` | Retrieve a document by hex-encoded doc ID |
| `memvault_search` | Full-text search across docs, entities, and files |
| `memvault_list` | List recent documents, optionally filtered by tag |
| `memvault_retract` | Soft-delete a document (creates a tombstone) |

**Files:**

| Tool | Description |
|------|-------------|
| `memvault_attach` | Upload a base64-encoded file |
| `memvault_read_range` | Read a byte range from an attachment |
| `memvault_extract_text` | Extract text from PDF, DOCX, HTML, Markdown |
| `memvault_attachment_info` | Get file metadata (name, MIME type, size) |
| `memvault_pin` | Pin a file to prevent garbage collection |
| `memvault_unpin` | Unpin a file |

**Knowledge graph:**

| Tool | Description |
|------|-------------|
| `memvault_graph_add` | Create an entity (person, project, concept, ...) |
| `memvault_graph_link` | Link two entities by hex ID |
| `memvault_graph_query` | List all edges for an entity |

**Cross-type linking:**

| Tool | Description |
|------|-------------|
| `memvault_link` | Link any two nodes: `entity:<hex>`, `doc:<hex>`, `attachment:<hex>` |
| `memvault_edges` | List all edges (in + out) for any node |
| `memvault_unlink` | Remove an edge by ID |

**Status:**

| Tool | Description |
|------|-------------|
| `memvault_status` | Block count, doc count, peer count, uptime |

### Example: Claude Code MCP config

```json
{
  "mcpServers": {
    "memvault": {
      "command": "plan-ai-memvault",
      "args": ["--db", "/home/user/.local/share/memvault/blocks.redb"],
      "env": {
        "MEMVAULT_DEFAULT_TAGS": "agent:claude"
      }
    }
  }
}
```

## memctl CLI

Management CLI for direct store operations. Supports `--data-dir` (looks for `blocks.redb` inside) or `--db` (path to the redb file directly).

### Commands

```
memctl genesis                    Initialize a new cluster
memctl put <text> [--title T]     Store a document
memctl get <cid>                  Retrieve a block by CID
memctl search <query>             Full-text search
memctl list [--limit N]           List recent documents
memctl audit [--limit N]          Show audit log
memctl history <doc-id>           Document operation history
memctl retract <cid> --reason R   Soft-delete

memctl graph-add <kind> --prop k=v    Create entity
memctl graph-link <src> <tgt> <rel>   Link entities
memctl graph-query <from>             List edges

memctl repair-index               Rebuild all indexes from blockstore
memctl fix-cluster-id             Index null-cluster blocks into CLUSTER_ORIGIN
memctl status                     Node status
memctl token-issue [--role R]     Issue a join token
memctl token-list                 List tokens
memctl token-revoke <cid>         Revoke a token
```

## Web UI

The web UI runs on port 8401 (by default) and provides:

- **Notes** -- create, edit, view with markdown rendering, version history
- **Graph** -- interactive force-directed knowledge graph with entity/doc/file nodes, focus mode, and drag-to-rearrange
- **Files** -- upload, preview (images), download, text extraction
- **Timeline** -- chronological feed of all operations
- **Audit** -- filterable audit trail with human-readable descriptions
- **Admin** -- cluster status, token management

Global search (`Ctrl+K` or the search button) searches across all node types -- document bodies, entity properties, filenames.

## Node references

Cross-type linking uses a unified `NodeRef` format:

```
entity:a1b2c3d4e5f6...    # 32-byte hex entity ID
doc:9f8e7d6c5b4a...       # 32-byte hex document ID
attachment:4a5b6c7d...    # hex-encoded manifest CID
```

These work everywhere: MCP tools (`memvault_link`, `memvault_edges`), the REST API (`/api/v1/links`), and the web UI's quick-link forms.

## Storage layout

```
~/.local/share/memvault/
  blocks.redb           # Primary block store + all indexes
  text_index.json       # Full-text search index cache (auto-rebuilt if stale)
  cluster_id            # Hex-encoded cluster identifier
  api.token             # Bearer token for HTTP API auth
  identity/             # Node identity keys
  trust/                # Trust anchors
```

## Index rebuild

If search results are missing or indexes seem corrupt:

```bash
memctl repair-index
```

This does a two-phase rebuild:
1. Clears and rebuilds all store secondary indexes (BY_TAG, BY_AUTHOR, BY_TIME, etc.) from the raw blocks
2. Rebuilds the full-text search index and saves it to `text_index.json`

The text index cache includes a format version. When memvault is updated with index format changes, the cache is automatically discarded and rebuilt on next startup.
