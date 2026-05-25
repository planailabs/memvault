#!/usr/bin/env bash
# Join node_b to node_a's cluster.
#
# Prerequisites:
#   1. Run genesis-node-a.sh first
#   2. Start node_a's daemon (so it can issue tokens)
#
# This script:
#   1. Reads node_a's cluster_id
#   2. Issues a join token from node_a
#   3. Enrolls node_b as an agent using that token
set -euo pipefail

NODE_A_DIR="${NODE_A_DATA_DIR:-$HOME/.local/share/memvault.a}"
NODE_B_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.b}"
NODE_A_DB="$NODE_A_DIR/blocks.redb"
NODE_B_DB="$NODE_B_DIR/blocks.redb"

echo "=== Join node_b to node_a's cluster ==="
echo "  Node A data: $NODE_A_DIR"
echo "  Node B data: $NODE_B_DIR"

# Read cluster_id from node_a
if [ ! -f "$NODE_A_DIR/cluster_id" ]; then
    echo "ERROR: node_a has no cluster_id. Run genesis-node-a.sh first."
    exit 1
fi
CLUSTER_ID=$(cat "$NODE_A_DIR/cluster_id")
echo "  Cluster ID: $CLUSTER_ID"

# Issue a join token from node_a
echo ""
echo "Issuing join token from node_a..."
TOKEN=$(cargo run -p memctl --features daemon -- \
    --data-dir "$NODE_A_DIR" \
    --db "$NODE_A_DB" \
    token-issue --role agent-host --label "node-b" --ttl 3600)
echo "  Token: ${TOKEN:0:30}..."

# Initialize node_b's data dir if needed
mkdir -p "$NODE_B_DIR"

# Copy cluster_id to node_b (so it knows which cluster to join)
cp "$NODE_A_DIR/cluster_id" "$NODE_B_DIR/cluster_id"

# Run genesis on node_b with the same cluster ID... actually no.
# node_b should run its own genesis OR join via the token.
# For now: run genesis on node_b to set up the store, then the daemon
# will connect to node_a via P2P.
if [ ! -f "$NODE_B_DB" ]; then
    echo ""
    echo "Running genesis on node_b..."
    cargo run -p memctl --features daemon -- \
        --data-dir "$NODE_B_DIR" \
        --db "$NODE_B_DB" \
        genesis
fi

# Enroll node_b as an agent
echo ""
echo "Enrolling node_b agent..."
cargo run -p memctl --features daemon -- \
    --data-dir "$NODE_B_DIR" \
    --db "$NODE_B_DB" \
    agent-enroll --token "$TOKEN" --agent-id "node-b"

echo ""
echo "=== Done ==="
echo "Start node_b with:"
echo "  MEMVAULT_DATA_DIR=$NODE_B_DIR cargo run -p memctl --features daemon -- daemon --api-port 8402 --listen /ip4/127.0.0.1/tcp/9002 --bootstrap /ip4/127.0.0.1/tcp/9001"
