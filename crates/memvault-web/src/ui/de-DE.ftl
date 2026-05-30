## ── Navigation ──────────────────────────────────────────────────

nav-brand = memvault
nav-section-memory = Wissen
nav-notes = Notizen
nav-graph = Graph
nav-files = Dateien
nav-vfs = VFS
nav-section-operations = Betrieb
nav-audit = Protokoll
nav-views = Ansichten
nav-admin = Admin

## ── Allgemein ───────────────────────────────────────────────────

loading = Wird geladen...
error-prefix = Fehler: { $error }
all = Alle
save = Speichern
cancel = Abbrechen
edit = Bearbeiten
delete = { "\u00D6" }schen
history = Verlauf
list = Liste
grid = Raster
untitled = Ohne Titel
unnamed = Unbenannt

## ── Kopfleiste ─────────────────────────────────────────────────

topbar-search = Suche
topbar-shortcut = { "\u2318" }K

## ── Notizen ─────────────────────────────────────────────────────

notes-title = Notizen
notes-new = Neue Notiz
notes-edit = Notiz bearbeiten
notes-th-tags = Tags
notes-th-visibility = Sichtbarkeit
notes-th-files = Dateien
notes-th-updated = Aktualisiert
notes-placeholder-title = Titel der Notiz
notes-placeholder-body = Markdown-Inhalt...
notes-placeholder-tags = bereich:label, bereich:label, ...
notes-th-title = Titel
notes-section-attachments = Anhänge ({ $count })
notes-attachments = Anhänge ({ $count })
notes-section-links = Verknüpfungen ({ $count })
notes-links = Verknüpfungen ({ $count })
notes-section-metadata = Metadaten
notes-metadata = Metadaten
notes-detail-title = Notiz
notes-history-title = Verlauf
notes-history-empty = Keine Verlaufseinträge.
notes-add-link = Verknüpfung hinzufügen
notes-link-target = Ziel
notes-link-relation = Beziehung
notes-link-btn = Verknüpfen
notes-link-search-placeholder = Knoten suchen...
notes-form-title = Titel
notes-form-title-placeholder = Titel der Notiz
notes-form-body = Inhalt
notes-form-body-placeholder = Markdown-Inhalt...
notes-form-tags = Tags
notes-form-tags-placeholder = bereich:label, bereich:label, ...
notes-form-visibility = Sichtbarkeit
by = von

## ── Graph ───────────────────────────────────────────────────────

graph-title = Wissensgraph
graph-loading = Graph wird geladen...
graph-empty = Keine Entitäten gefunden. Erstelle Entitäten über die MCP-Tools, um den Graphen zu füllen.
graph-node-count = { $nodes } Knoten, { $edges } Kanten
graph-stat-nodes = Knoten
graph-stat-edges = Kanten
graph-stat-kinds = Arten
graph-stat-zoom = Zoom
graph-zoom = Zoom: { $level }x
graph-fit-view = Einpassen
graph-show-all = Alle anzeigen
graph-focus-node = Auf diesen Knoten fokussieren
graph-section-properties = Eigenschaften
graph-section-edges = Kanten ({ $count })
graph-section-incoming = Eingehend · { $count }
graph-section-outgoing = Ausgehend · { $count }
graph-legend-kinds = Arten
graph-hint = ziehen · scrollen · Doppelklick zum Erweitern
graph-view-details = Details anzeigen
graph-view-document = Dokument anzeigen
graph-view-file = Datei anzeigen
graph-filter-nodes = Knoten filtern...
graph-edges-count = { $count } Kanten

## ── Entitäts-Details ────────────────────────────────────────────

entity-title = Entität
entity-no-properties = Keine Eigenschaften
entity-section-edges = Ausgehende Kanten ({ $count })
entity-th-relation = Beziehung
entity-th-target = Ziel
entity-th-weight = Gewicht
entity-view-in-graph = Im Graph anzeigen
entity-history-title = Entitäts-Verlauf
entity-history-no-entries = Keine Verlaufseinträge.
entity-history-by = von

## ── Dateien ─────────────────────────────────────────────────────

files-title = Dateien
files-empty = Keine Dateien gefunden.
files-th-name = Name
files-th-type = Typ
files-th-size = Größe
files-th-cid = CID
files-th-uploaded = Hochgeladen

## ── Datei-Details ───────────────────────────────────────────────

file-title = Datei
file-download = Herunterladen
file-section-metadata = Metadaten
file-meta-filename = Dateiname
file-meta-mime = MIME-Typ
file-meta-size = Größe
file-meta-sha256 = SHA256
file-meta-dimensions = Abmessungen
file-meta-duration = Dauer
file-meta-cid = CID
file-meta-replication = Replikation
file-meta-uploaded-by = Hochgeladen von
file-section-links = Verknüpfungen ({ $count })
file-section-text = Extrahierter Text

## ── VFS ─────────────────────────────────────────────────────────

vfs-title = VFS
vfs-empty = Leeres Verzeichnis
vfs-creating = Wird erstellt...
vfs-new-folder = Neuer Ordner
vfs-placeholder-folder = Name des neuen Ordners...
vfs-th-name = Name
vfs-th-type = Typ
vfs-th-node-id = Knoten-ID

## ── Ansichten ───────────────────────────────────────────────────

views-title = Ansichten
views-new = Neue Ansicht
views-edit = Ansicht bearbeiten
views-description = Ansichten sind gespeicherte Tag-Filter. Bei aktiver Ansicht werden nur Einträge mit ALLEN erforderlichen Tags angezeigt.
views-empty = Noch keine Ansichten. Erstelle eine, um Inhalte nach Tags zu filtern.
views-no-tags = Keine Tags (zeigt alles)
views-create = Erstellen
views-tags-label = Erforderliche Tags (kommagetrennt, bereich:label-Format)
views-placeholder-name = z.B. Forschung, Projekt X
views-placeholder-tags = z.B. bereich:pharmakologie, typ:forschungsarbeit
views-name-required = Name ist erforderlich

## ── Protokoll ───────────────────────────────────────────────────

audit-title = Prüfprotokoll
audit-th-operation = Vorgang
audit-th-description = Beschreibung
audit-th-author = Autor
audit-th-time = Zeit
audit-placeholder-author = Autoren-ID-Präfix...

## ── Protokoll-Beschreibungen ────────────────────────────────────

audit-created-doc = Dokument erstellt "{ $name }"
audit-created-doc-generic = Dokument erstellt
audit-edited-doc = "{ $name }" bearbeitet
audit-edited-doc-generic = Dokument bearbeitet
audit-updated-meta = Metadaten aktualisiert auf "{ $name }"
audit-updated-meta-generic = Dokument-Metadaten aktualisiert
audit-attached-to = Datei angehängt an "{ $name }"
audit-attached-file = Datei angehängt "{ $name }"
audit-attached-generic = Datei angehängt
audit-detached-from = Datei entfernt von "{ $name }"
audit-detached-generic = Datei entfernt
audit-created-entity = Entität erstellt "{ $name }"
audit-created-entity-generic = Entität erstellt
audit-linked = Verknüpft { $source } -> { $target }
audit-removed-edge = Kante entfernt von { $source }
audit-retracted = Zurückgezogen "{ $name }"
audit-retracted-generic = Eintrag zurückgezogen
audit-updated-tags = Tags aktualisiert auf "{ $name }"
audit-updated-tags-generic = Tags aktualisiert
audit-extracted-text = Text extrahiert aus "{ $name }"
audit-extracted-text-generic = Text extrahiert
audit-op-on = { $op } auf "{ $name }"

## ── Admin ───────────────────────────────────────────────────────

admin-title = Verwaltung
admin-stat-documents = Dokumente
admin-stat-blocks = Blöcke
admin-stat-peers = Peers
admin-stat-uptime = Betriebszeit
admin-section-node = Knoten-Info
admin-peer-id = Peer-ID
admin-cluster-id = Cluster-ID
admin-section-tokens = API-Token ({ $count })
admin-no-tokens = Keine Token ausgestellt.

## ── Token ───────────────────────────────────────────────────────

tokens-title = API-Token
tokens-issue = Token ausstellen
tokens-issue-button = Ausstellen
tokens-revoke = Widerrufen
tokens-issued-message = Token ausgestellt! Jetzt kopieren — es wird nicht erneut angezeigt:
tokens-th-label = Bezeichnung
tokens-th-role = Rolle
tokens-th-used = Verwendet
tokens-th-status = Status
tokens-placeholder-label = Token-Bezeichnung
tokens-placeholder-max-uses = Max. Nutzungen
tokens-status-active = Aktiv
tokens-status-revoked = Widerrufen
tokens-role-service = Dienst
tokens-role-agent-host = Agent-Host
tokens-role-node = Knoten
tokens-role-auditor = Prüfer
tokens-role-admin = Admin

## ── Verknüpfungs-Formular ──────────────────────────────────────

link-add = Verknüpfung hinzufügen
link-select-target = Ziel aus den Suchergebnissen auswählen
link-linked = Verknüpft (Kante { $edgeId })
link-placeholder-search = Knoten suchen...
link-label-target = Ziel
link-label-relation = Beziehung
link-btn = Verknüpfen

## ── Sichtbarkeit ───────────────────────────────────────────────

visibility-internal = Intern
visibility-federated = Föderiert
visibility-public = Öffentlich
