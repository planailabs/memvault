#!/usr/bin/env bash
# Join node_b to node_a's CLUSTER (node-level operation).
#
# This makes node_b a peer in the cluster — it will participate in
# P2P gossip, bitswap, and serve the REST API independently.
#
# This is DIFFERENT from agent enrollment:
#   - cluster-join: node joins the P2P cluster (replicates data)
#   - agent enroll: agent gets API credentials (consumes data via HTTP)
#
# A join token is issued by node_a (the admin); it embeds the
# cluster's `AdminGenesis` block so node_b can pin the admin pubkey
# at join time. Raw-cluster_id joining is no longer supported.
#
# Prerequisites:
#   1. Run genesis-node-a.sh first
set -euo pipefail

NODE_A_DIR="${NODE_A_DATA_DIR:-$HOME/.local/share/memvault.a}"
NODE_B_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.b}"

echo "=== Join node_b to node_a's cluster (node-level) ==="
echo "  Node A data: $NODE_A_DIR"
echo "  Node B data: $NODE_B_DIR"

# Sanity: node_a must be genesis'd. Identity (admin key, cluster_id, the
# pinned AdminGenesis, peer_id) now lives in the keystore — the intended
# store — not in loose files under identity/. genesis-node-a.sh opens a
# client once so the keystore is populated.
if [ ! -f "$NODE_A_DIR/identity/keystore.mvks" ]; then
    echo "ERROR: node_a has no keystore. Run genesis-node-a.sh first."
    exit 1
fi

# Issue a join token on node_a. `token issue` reads the admin key,
# cluster_id and AdminGenesis straight from node_a's keystore (no redb
# open), and embeds the AdminGenesis in the token automatically.
echo ""
echo "Issuing join token on node_a..."
TOKEN=$(MEMVAULT_DATA_DIR="$NODE_A_DIR" MEMVAULT_DB="$NODE_A_DIR/blocks.redb" \
    cargo run -q -p memctl --features daemon -- \
        token issue --role agent-host --ttl 3600 --max-uses 1 --label node-b-join \
    | tail -n1)

if [[ "$TOKEN" != mvjoin1:* ]]; then
    echo "ERROR: token issue did not return an mvjoin1: token."
    echo "       Got: $TOKEN"
    exit 1
fi
echo "  Token: ${TOKEN:0:40}..."

# Join with the token on node_b. The command verifies the token's
# AdminGenesis self-signature and writes the pin file.
echo ""
echo "Joining cluster on node_b (node-level)..."
MEMVAULT_DATA_DIR="$NODE_B_DIR" MEMVAULT_DB="$NODE_B_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- cluster-join "$TOKEN"

echo ""
echo "=== Node joined ==="
echo ""
echo "Node_b is now a cluster peer with the admin pubkey pinned."
echo "Start it with:"
echo "  MEMVAULT_DATA_DIR=$NODE_B_DIR cargo run -p memctl --features daemon -- daemon --api-port 8402 --listen /ip4/127.0.0.1/tcp/9002 --bootstrap /ip4/127.0.0.1/tcp/9001"
echo ""
echo "To enroll an agent (e.g. openclaw) on this node, run:"
echo "  ./test/enroll-agent.sh"
