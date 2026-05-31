#!/usr/bin/env nix-shell
#! nix-shell -i bash -p skopeo

set -euxo pipefail

# Ensure skopeo trust policy exists (CI runners may lack it).
mkdir -p /etc/containers 2>/dev/null || mkdir -p "$HOME/.config/containers"
POLICY_DIR="/etc/containers"
[ -w "$POLICY_DIR" ] || POLICY_DIR="$HOME/.config/containers"
[ -f "$POLICY_DIR/policy.json" ] || echo '{"default":[{"type":"insecureAcceptAnything"}]}' > "$POLICY_DIR/policy.json"

REGISTRY="${CI_REGISTRY:-git.plan.ai:5050}"
PROJECT="${CI_PROJECT_PATH:-plan-ai/memvault}"
TAG="${CI_COMMIT_SHORT_SHA:-latest}"

for img in memctl; do
  nix build ".#docker-${img}" -L

  skopeo copy \
    "docker-archive:$(readlink -f result)" \
    "docker://${REGISTRY}/${PROJECT}/${img}:${TAG}" \
    --dest-creds "${CI_REGISTRY_USER}:${CI_REGISTRY_PASSWORD}"

  skopeo copy \
    "docker-archive:$(readlink -f result)" \
    "docker://${REGISTRY}/${PROJECT}/${img}:latest" \
    --dest-creds "${CI_REGISTRY_USER}:${CI_REGISTRY_PASSWORD}"
done

# NixOS-in-Docker test image with the shared self-signed memvault node.
for img in test-memvault; do
  nix build ".#nixosConfigurations.${img}.config.system.build.dockerImage" -L

  skopeo copy \
    "docker-archive:$(readlink -f result)" \
    "docker://${REGISTRY}/${PROJECT}/${img}:${TAG}" \
    --dest-creds "${CI_REGISTRY_USER}:${CI_REGISTRY_PASSWORD}"

  skopeo copy \
    "docker-archive:$(readlink -f result)" \
    "docker://${REGISTRY}/${PROJECT}/${img}:latest" \
    --dest-creds "${CI_REGISTRY_USER}:${CI_REGISTRY_PASSWORD}"
done
