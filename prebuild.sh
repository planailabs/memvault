#!/usr/bin/env bash

set -euo pipefail

if [ -z "${XZAR_TOKEN:-}" ]; then
  echo "XZAR_TOKEN is not set; skipping cache prebuild/upload job."
  echo "This is expected for pipelines that do not receive protected CI variables."
  exit 0
fi

# ── Configure xzar plan.ai cache ────────────────────────────────────
xzar config add-server planai https://xzar.plan.ai "$XZAR_TOKEN"

upload() {
  while ! xzar --server planai upload --pin "$1" --desc "$(readlink -f "$2")" --leave-after-abandon 1m "$2"; do true; done
}

# ── Build devShell & push to xzar cache ─────────────────────────────
nix build .#devShells.x86_64-linux.default -o result-devshell
upload memvault/devshell result-devshell
rm -f result-devshell

# ── Build CI image & push to xzar cache ─────────────────────────────
nix build .#image -o result-image
upload memvault/image result-image
rm -f result-image

# ── Build all exposed packages & push to xzar cache ────────────────
for pkg in default memctl dioxus-cli-patched docker-memctl; do
  nix build ".#${pkg}" -o "result-${pkg}" -L
  upload "memvault/${pkg}" "result-${pkg}"
  rm -f "result-${pkg}"
done
