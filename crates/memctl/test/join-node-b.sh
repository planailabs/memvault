#!/usr/bin/env bash
# Join node_b to node_a's cluster.
#
# Prerequisites:
#   1. Run genesis-node-a.sh first
#
# This script does NOT run genesis on node_b. Instead:
#   1. Issues a join token from node_a
#   2. Runs `cluster-join` on node_b (sets cluster_id, creates default bucket)
#   3. Enrolls node_b as an agent
set -euo pipefail

NODE_A_DIR="${NODE_A_DATA_DIR:-$HOME/.local/share/memvault.a}"
NODE_B_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.b}"

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
TOKEN=$(MEMVAULT_DATA_DIR="$NODE_A_DIR" MEMVAULT_DB="$NODE_A_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- token-issue --role agent-host --label "node-b" --ttl 3600)
echo "  Token: ${TOKEN:0:30}..."

# Join the cluster on node_b (sets cluster_id, creates default bucket)
echo ""
echo "Joining cluster on node_b..."
MEMVAULT_DATA_DIR="$NODE_B_DIR" MEMVAULT_DB="$NODE_B_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- cluster-join "$CLUSTER_ID"

# Enroll node_b as an agent
echo ""
echo "Enrolling node_b agent..."
MEMVAULT_DATA_DIR="$NODE_B_DIR" MEMVAULT_DB="$NODE_B_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- agent-enroll --token "$TOKEN" --agent-id "node-b"

echo ""
echo "=== Done ==="
echo ""
echo "Start both nodes:"
echo "  Node A: MEMVAULT_DATA_DIR=$NODE_A_DIR cargo run -p memctl --features daemon -- daemon --api-port 8401 --listen /ip4/127.0.0.1/tcp/9001"
echo "  Node B: MEMVAULT_DATA_DIR=$NODE_B_DIR cargo run -p memctl --features daemon -- daemon --api-port 8402 --listen /ip4/127.0.0.1/tcp/9002 --bootstrap /ip4/127.0.0.1/tcp/9001"
