#!/usr/bin/env bash
# Enroll an AGENT on a cluster node (agent-level operation).
#
# Agents are clients (like openclaw, hermes) that access the cluster
# through a node's HTTP API. They have their own Ed25519 identity
# for signing writes, but do NOT participate in P2P replication.
#
# This is DIFFERENT from cluster-join:
#   - cluster-join: node joins the P2P cluster (replicates data)
#   - agent-enroll: agent gets API credentials (consumes data via HTTP)
#
# Prerequisites:
#   1. Run genesis-node-a.sh (creates the cluster)
#   2. Optionally run join-node-b.sh (adds another node)
set -euo pipefail

# Which node to enroll the agent on
NODE_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.a}"
AGENT_ID="${1:-openclaw}"

echo "=== Enroll agent '${AGENT_ID}' on node ==="
echo "  Node data:  $NODE_DIR"
echo "  Agent ID:   $AGENT_ID"

# Issue a join token
echo ""
echo "Issuing join token..."
TOKEN=$(MEMVAULT_DATA_DIR="$NODE_DIR" MEMVAULT_DB="$NODE_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- token-issue --role agent-host --label "$AGENT_ID" --ttl 86400)
echo "  Token: ${TOKEN:0:30}..."

# Enroll the agent
echo ""
echo "Enrolling agent..."
MEMVAULT_DATA_DIR="$NODE_DIR" MEMVAULT_DB="$NODE_DIR/blocks.redb" \
    cargo run -p memctl --features daemon -- agent-enroll --token "$TOKEN" --agent-id "$AGENT_ID"

IDENTITY_DIR="$NODE_DIR/agents/$AGENT_ID"
echo ""
echo "=== Agent enrolled ==="
echo "  Identity dir: $IDENTITY_DIR"
echo ""
echo "The agent can now authenticate to this node's API."
echo "MCP server usage:"
echo "  MEMVAULT_AGENT_ID=$AGENT_ID MEMVAULT_IDENTITY_DIR=$IDENTITY_DIR \\"
echo "    plan-ai-memvault --url http://127.0.0.1:8401"
