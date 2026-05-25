#!/usr/bin/env bash
# Join node_b to node_a's CLUSTER (node-level operation).
#
# This makes node_b a peer in the cluster — it will participate in
# P2P gossip, bitswap, and serve the REST API independently.
#
# This is DIFFERENT from agent enrollment:
#   - cluster-join: node joins the P2P cluster (replicates data)
#   - agent-enroll: agent gets API credentials (consumes data via HTTP)
#
# Prerequisites:
#   1. Run genesis-node-a.sh first
set -euo pipefail

NODE_A_DIR="${NODE_A_DATA_DIR:-$HOME/.local/share/memvault.a}"
NODE_B_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.b}"

echo "=== Join node_b to node_a's cluster (node-level) ==="
echo "  Node A data: $NODE_A_DIR"
echo "  Node B data: $NODE_B_DIR"

# Read cluster_id from node_a
if [ ! -f "$NODE_A_DIR/cluster_id" ]; then
    echo "ERROR: node_a has no cluster_id. Run genesis-node-a.sh first."
    exit 1
fi
CLUSTER_ID=$(cat "$NODE_A_DIR/cluster_id")
echo "  Cluster ID: $CLUSTER_ID"

# Join the cluster on node_b (node-level — sets cluster_id, creates default bucket)
echo ""
echo "Joining cluster on node_b (node-level)..."
MEMVAULT_DATA_DIR="$NODE_B_DIR" MEMVAULT_DB="$NODE_B_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- cluster-join "$CLUSTER_ID"

echo ""
echo "=== Node joined ==="
echo ""
echo "Node_b is now a cluster peer. Start it with:"
echo "  MEMVAULT_DATA_DIR=$NODE_B_DIR cargo run -p memctl --features daemon -- daemon --api-port 8402 --listen /ip4/127.0.0.1/tcp/9002 --bootstrap /ip4/127.0.0.1/tcp/9001"
echo ""
echo "To enroll an agent (e.g. openclaw) on this node, run:"
echo "  ./test/enroll-agent.sh"
