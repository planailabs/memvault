#!/usr/bin/env bash
# Initialize node_a's memvault cluster.
# Run this BEFORE starting the daemon.
set -euo pipefail

export MEMVAULT_DATA_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.a}"
export MEMVAULT_DB="$MEMVAULT_DATA_DIR/blocks.redb"

echo "=== Genesis for node_a ==="
echo "  Data dir: $MEMVAULT_DATA_DIR"

cargo run -p memctl --features daemon -- genesis

echo ""
echo "Cluster ID: $(cat "$MEMVAULT_DATA_DIR/cluster_id")"
echo ""
echo "Done. Start node_a with:"
echo "  MEMVAULT_DATA_DIR=$MEMVAULT_DATA_DIR cargo run -p memctl --features daemon -- daemon --api-port 8401"
