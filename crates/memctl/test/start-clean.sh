#!/usr/bin/env bash
# Reset everything and set up a fresh two-node cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/reset.sh"
"$SCRIPT_DIR/genesis-node-a.sh"
"$SCRIPT_DIR/seed-node-a.sh"
"$SCRIPT_DIR/join-node-b.sh"
