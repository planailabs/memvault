#!/usr/bin/env bash
# Compare block sets between two memvault nodes.
# Usage: ./diff-blocks.sh [node_a_db] [node_b_db]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MEMCTL="${MEMCTL:-cargo run -p memctl --}"

DB_A="${1:-$HOME/.local/share/memvault.a/blocks.redb}"
DB_B="${2:-$HOME/.local/share/memvault.b/blocks.redb}"

DIR_A="$(mktemp -d)"
DIR_B="$(mktemp -d)"
trap 'rm -rf "$DIR_A" "$DIR_B"' EXIT

echo "Exporting blocks from node A ($DB_A)..."
$MEMCTL --db "$DB_A" export-blocks -o "$DIR_A"

echo "Exporting blocks from node B ($DB_B)..."
$MEMCTL --db "$DB_B" export-blocks -o "$DIR_B"

COUNT_A="$(ls "$DIR_A" | wc -l)"
COUNT_B="$(ls "$DIR_B" | wc -l)"
echo ""
echo "Node A: $COUNT_A blocks"
echo "Node B: $COUNT_B blocks"

ONLY_A="$(comm -23 <(ls "$DIR_A" | sort) <(ls "$DIR_B" | sort))"
ONLY_B="$(comm -13 <(ls "$DIR_A" | sort) <(ls "$DIR_B" | sort))"

if [ -z "$ONLY_A" ] && [ -z "$ONLY_B" ]; then
    echo "Blocks are identical."
    exit 0
fi

if [ -n "$ONLY_A" ]; then
    echo ""
    echo "=== Only on Node A ($(echo "$ONLY_A" | wc -l) blocks) ==="
    echo "$ONLY_A"
fi

if [ -n "$ONLY_B" ]; then
    echo ""
    echo "=== Only on Node B ($(echo "$ONLY_B" | wc -l) blocks) ==="
    echo "$ONLY_B"
fi

# Run diffoscope if available
if command -v diffoscope &>/dev/null; then
    echo ""
    echo "Running diffoscope..."
    diffoscope --exclude-directory-metadata=yes "$DIR_A" "$DIR_B" || true
fi
