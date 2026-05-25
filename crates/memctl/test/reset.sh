#!/usr/bin/env bash
# Reset both test nodes (delete all data).
set -euo pipefail

echo "Removing node_a and node_b data..."
rm -rf "$HOME/.local/share/memvault.a"
rm -rf "$HOME/.local/share/memvault.b"
echo "Done. Run genesis-node-a.sh to start fresh."
