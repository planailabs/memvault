#!/usr/bin/env bash
# Populate node_a with random demo data (docs, entities, files, links, VFS).
# Run AFTER genesis-node-a.sh but BEFORE or AFTER starting the daemon.
set -euo pipefail

export MEMVAULT_DATA_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.a}"
export MEMVAULT_DB="$MEMVAULT_DATA_DIR/blocks.redb"

echo "=== Seeding node_a ==="
echo "  Data dir: $MEMVAULT_DATA_DIR"

cargo run -p memctl --features daemon -- seed

echo ""
echo "Seed complete."
