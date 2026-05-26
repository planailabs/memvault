#!/usr/bin/env bash
# Run repair-index on both node_a and node_b.
# Rebuilds all secondary indexes, creates missing file manifests,
# and repairs VFS trees.
set -euo pipefail

NODE_A_DIR="${NODE_A_DATA_DIR:-$HOME/.local/share/memvault.a}"
NODE_B_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.b}"

echo "=== Repair index: node_a ==="
MEMVAULT_DATA_DIR="$NODE_A_DIR" MEMVAULT_DB="$NODE_A_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- repair-index

echo ""
echo "=== Repair index: node_b ==="
MEMVAULT_DATA_DIR="$NODE_B_DIR" MEMVAULT_DB="$NODE_B_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- repair-index

echo ""
echo "Done."
