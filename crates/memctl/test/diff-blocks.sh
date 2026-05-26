#!/usr/bin/env bash
# Compare block sets between two memvault nodes (semantic diff).
# Usage: ./diff-blocks.sh [node_a_db] [node_b_db]
set -euo pipefail

MEMCTL="${MEMCTL:-cargo run -p memctl --}"

DB_A="${1:-$HOME/.local/share/memvault.a/blocks.redb}"
DB_B="${2:-$HOME/.local/share/memvault.b/blocks.redb}"

$MEMCTL diff-blocks "$DB_A" "$DB_B"
