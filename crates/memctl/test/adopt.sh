#!/usr/bin/env bash
# Adopt user's memvault as node a
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/reset.sh"

echo "Copying memvault to node a..."
cp -rp "$HOME/.local/share/memvault" "$HOME/.local/share/memvault.a"

"$SCRIPT_DIR/genesis-node-a.sh"
"$SCRIPT_DIR/join-node-b.sh"
