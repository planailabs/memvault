## ── Navigation ──────────────────────────────────────────────────

nav-brand = memvault
nav-section-memory = Memory
nav-notes = Notes
nav-graph = Graph
nav-files = Files
nav-vfs = VFS
nav-section-operations = Operations
nav-audit = Audit
nav-views = Views
nav-admin = Admin

## ── Common ──────────────────────────────────────────────────────

loading = Loading...
error-prefix = Error: { $error }
all = All
save = Save
cancel = Cancel
edit = Edit
delete = Delete
history = History
list = List
grid = Grid
untitled = Untitled
unnamed = Unnamed

## ── Topbar ──────────────────────────────────────────────────────

topbar-search = Search
topbar-shortcut = { "\u2318" }K

## ── Notes ───────────────────────────────────────────────────────

notes-title = Notes
notes-new = New Note
notes-edit = Edit Note
notes-th-tags = Tags
notes-th-visibility = Visibility
notes-th-files = Files
notes-th-updated = Updated
notes-placeholder-title = Note title
notes-placeholder-body = Markdown content...
notes-placeholder-tags = scope:label, scope:label, ...
notes-th-title = Title
notes-section-attachments = Attachments ({ $count })
notes-attachments = Attachments ({ $count })
notes-section-links = Links ({ $count })
notes-links = Links ({ $count })
notes-section-metadata = Metadata
notes-metadata = Metadata
notes-detail-title = Note
notes-history-title = History
notes-history-empty = No history entries.
notes-add-link = Add Link
notes-link-target = Target
notes-link-relation = Relation
notes-link-btn = Link
notes-link-search-placeholder = Search nodes...
notes-form-title = Title
notes-form-title-placeholder = Note title
notes-form-body = Body
notes-form-body-placeholder = Markdown content...
notes-form-tags = Tags
notes-form-tags-placeholder = scope:label, scope:label, ...
notes-form-visibility = Visibility
by = by

## ── Graph ───────────────────────────────────────────────────────

graph-title = Knowledge Graph
graph-loading = Loading graph...
graph-empty = No entities found. Create entities via the MCP tools to populate the graph.
graph-node-count = { $nodes } nodes, { $edges } edges
graph-zoom = Zoom: { $level }x
graph-fit-view = Fit View
graph-show-all = Show All
graph-focus-node = Focus on this node
graph-section-properties = Properties
graph-section-edges = Edges ({ $count })
graph-view-details = View Details
graph-view-document = View Document
graph-view-file = View File
graph-filter-nodes = Filter nodes...
graph-edges-count = { $count } edges

## ── Entity Detail ───────────────────────────────────────────────

entity-title = Entity
entity-no-properties = No properties
entity-section-edges = Outgoing Edges ({ $count })
entity-th-relation = Relation
entity-th-target = Target
entity-th-weight = Weight
entity-view-in-graph = View in Graph
entity-history-title = Entity History
entity-history-no-entries = No history entries.
entity-history-by = by

## ── Files ───────────────────────────────────────────────────────

files-title = Files
files-empty = No files found.
files-th-name = Name
files-th-type = Type
files-th-size = Size
files-th-cid = CID
files-th-uploaded = Uploaded

## ── File Detail ─────────────────────────────────────────────────

file-title = File
file-download = Download
file-section-metadata = Metadata
file-meta-filename = Filename
file-meta-mime = MIME Type
file-meta-size = Size
file-meta-sha256 = SHA256
file-meta-dimensions = Dimensions
file-meta-duration = Duration
file-meta-cid = CID
file-meta-replication = Replication
file-section-links = Links ({ $count })
file-section-text = Extracted Text

## ── VFS ─────────────────────────────────────────────────────────

vfs-title = VFS
vfs-empty = Empty directory
vfs-creating = Creating...
vfs-new-folder = New Folder
vfs-placeholder-folder = New folder name...
vfs-th-name = Name
vfs-th-type = Type
vfs-th-node-id = Node ID

## ── Views ───────────────────────────────────────────────────────

views-title = Views
views-new = New View
views-edit = Edit View
views-description = Views are saved tag filter sets. When a view is active, only items with ALL the required tags are shown.
views-empty = No views yet. Create one to filter content by tags.
views-no-tags = No tags (matches everything)
views-create = Create
views-tags-label = Required tags (comma-separated, scope:label format)
views-placeholder-name = e.g. Research, Project X
views-placeholder-tags = e.g. domain:pharmacology, type:research-paper
views-name-required = Name is required

## ── Audit ───────────────────────────────────────────────────────

audit-title = Audit Trail
audit-th-operation = Operation
audit-th-description = Description
audit-th-author = Author
audit-th-time = Time
audit-placeholder-author = Author ID prefix...

## ── Audit descriptions ─────────────────────────────────────────

audit-created-doc = Created document "{ $name }"
audit-created-doc-generic = Created document
audit-edited-doc = Edited "{ $name }"
audit-edited-doc-generic = Edited document
audit-updated-meta = Updated metadata on "{ $name }"
audit-updated-meta-generic = Updated document metadata
audit-attached-to = Attached file to "{ $name }"
audit-attached-file = Attached file "{ $name }"
audit-attached-generic = Attached file
audit-detached-from = Detached file from "{ $name }"
audit-detached-generic = Detached file
audit-created-entity = Created entity "{ $name }"
audit-created-entity-generic = Created entity
audit-linked = Linked { $source } -> { $target }
audit-removed-edge = Removed edge from { $source }
audit-retracted = Retracted "{ $name }"
audit-retracted-generic = Retracted item
audit-updated-tags = Updated tags on "{ $name }"
audit-updated-tags-generic = Updated tags
audit-extracted-text = Extracted text from "{ $name }"
audit-extracted-text-generic = Extracted text
audit-op-on = { $op } on "{ $name }"

## ── Admin ───────────────────────────────────────────────────────

admin-title = Administration
admin-stat-documents = Documents
admin-stat-blocks = Blocks
admin-stat-peers = Peers
admin-stat-uptime = Uptime
admin-section-node = Node Info
admin-peer-id = Peer ID
admin-cluster-id = Cluster ID
admin-section-tokens = API Tokens ({ $count })
admin-no-tokens = No tokens issued.

## ── Tokens ──────────────────────────────────────────────────────

tokens-title = API Tokens
tokens-issue = Issue Token
tokens-issue-button = Issue
tokens-revoke = Revoke
tokens-issued-message = Token issued! Copy it now — it won't be shown again:
tokens-th-label = Label
tokens-th-role = Role
tokens-th-used = Used
tokens-th-status = Status
tokens-placeholder-label = Token label
tokens-placeholder-max-uses = Max Uses
tokens-status-active = Active
tokens-status-revoked = Revoked
tokens-role-service = Service
tokens-role-agent-host = Agent Host
tokens-role-auditor = Auditor
tokens-role-admin = Admin

## ── Link Form (shared across detail pages) ─────────────────────

link-add = Add Link
link-select-target = Select a target from search results
link-linked = Linked (edge { $edgeId })
link-placeholder-search = Search nodes...
link-label-target = Target
link-label-relation = Relation
link-btn = Link

## ── Visibility ─────────────────────────────────────────────────

visibility-internal = Internal
visibility-federated = Federated
visibility-public = Public
