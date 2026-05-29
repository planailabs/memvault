#!/usr/bin/env bash
# Enroll an AGENT on a cluster node and exercise the write path.
#
# Agents are clients (like openclaw, hermes) that access the cluster
# through a node's HTTP API. They have their own Ed25519 identity for
# signing writes, but do NOT participate in P2P replication.
#
# This is DIFFERENT from cluster-join:
#   - cluster-join: node joins the P2P cluster (replicates data)
#   - agent enroll: agent gets API credentials (consumes data via HTTP)
#
# Prerequisites:
#   1. Run genesis-node-a.sh (creates the cluster)
#   2. Optionally run join-node-b.sh (adds another node)
#
# Args:
#   $1: agent id (default: openclaw)
set -euo pipefail

NODE_DIR="${MEMVAULT_DATA_DIR:-$HOME/.local/share/memvault.a}"
AGENT_ID="${1:-openclaw}"

# Identity (admin key, cluster_id, AdminGenesis) lives in the keystore.
if [ ! -f "$NODE_DIR/identity/keystore.mvks" ]; then
    echo "ERROR: $NODE_DIR has no keystore. Run genesis-node-a.sh first."
    exit 1
fi

echo "=== Enroll agent '${AGENT_ID}' ==="
echo "  Node data:  $NODE_DIR"
echo "  Agent ID:   $AGENT_ID"

# 1. Issue a join token. `token issue` prints only the token on its last
#    line, so capture cleanly.
echo ""
echo "Step 1/4: Issue a join token..."
TOKEN=$(MEMVAULT_DATA_DIR="$NODE_DIR" MEMVAULT_DB="$NODE_DIR/blocks.redb" \
    cargo run -q -p memctl --features daemon -- \
        token issue --role agent-host --label "$AGENT_ID" --ttl 86400 \
    | tail -n1)
if [[ "$TOKEN" != mvjoin1:* ]]; then
    echo "ERROR: token issue did not return an mvjoin1: token."
    echo "       Got: $TOKEN"
    exit 1
fi
echo "  Token: ${TOKEN:0:40}..."

# 2. Enroll the agent. Generates the keypair + node-signed
#    AgentAttestation under $NODE_DIR/agents/$AGENT_ID/.
echo ""
echo "Step 2/4: Enroll the agent locally..."
MEMVAULT_DATA_DIR="$NODE_DIR" MEMVAULT_DB="$NODE_DIR/blocks.redb" \
    cargo run -q -p memctl --features daemon -- \
        agent enroll --token "$TOKEN" --agent-id "$AGENT_ID"

IDENTITY_DIR="$NODE_DIR/agents/$AGENT_ID"
# The agent's private key is the only on-disk artifact (the attestation
# lives on the sigchain, resolved by pubkey at JWT-verify time).
if [ ! -f "$IDENTITY_DIR/private_key.pem" ]; then
    echo "ERROR: agent enroll did not create $IDENTITY_DIR/private_key.pem"
    exit 1
fi
echo "  Identity dir: $IDENTITY_DIR"

# 3. Write something into memvault — AS the enrolled agent. The global
#    `--agent-id` flag binds the agent's identity to the LocalClient,
#    so the resulting envelope gets an `EnvelopeAuthorship` sidecar
#    signed by the agent (not by the node).
echo ""
echo "Step 3/4: Put a sample doc into memvault (authored by agent)..."
DOC_TEXT="Smoke test note for agent ${AGENT_ID} at $(date -u +%FT%TZ)"
MEMVAULT_DATA_DIR="$NODE_DIR" MEMVAULT_DB="$NODE_DIR/blocks.redb" \
    cargo run -q -p memctl --features daemon -- \
        --agent-id "$AGENT_ID" \
        put --title "agent-${AGENT_ID}-smoke" \
            --tag "agent=${AGENT_ID}" \
            --tag "kind=smoke" \
            --visibility internal \
            "$DOC_TEXT"

# 4. List docs as the same agent — proves both the write landed AND the
#    read path works under the agent's bound identity.
echo ""
echo "Step 4/4: List recent docs as the agent..."
MEMVAULT_DATA_DIR="$NODE_DIR" MEMVAULT_DB="$NODE_DIR/blocks.redb" \
    cargo run -q -p memctl --features daemon -- \
        --agent-id "$AGENT_ID" list --limit 5

echo ""
echo "=== Agent enrolled and write-path verified ==="
echo ""
echo "MCP server usage (agent signs JWTs from $IDENTITY_DIR):"
echo "  MEMVAULT_AGENT_ID=$AGENT_ID MEMVAULT_IDENTITY_DIR=$IDENTITY_DIR \\"
echo "    plan-ai-memvault --url http://127.0.0.1:8401"
