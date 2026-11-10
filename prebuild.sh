#!/usr/bin/env bash

set -euo pipefail

if [ -z "${XZAR_TOKEN:-}" ]; then
  echo "XZAR_TOKEN is not set; skipping cache prebuild/upload job."
  echo "This is expected for pipelines that do not receive protected CI variables."
  exit 0
fi

# ── Progress reporting ──────────────────────────────────────────────
# GitLab fails a *running* job with `no_updates_running` once the runner has
# gone silent for a while (~30-60 min), and the cold builds below are
# legitimately silent for longer than that: in pipeline 2925 a single dioxus
# compile step printed nothing for 46 minutes, and in pipeline 3328 the job
# trace stopped 12 s after the flake evaluation and the job was dropped 51
# minutes later, mid-`nix build`, with no error line at all. Build logs alone
# do not close that gap, so every slow step runs in the background while a
# heartbeat keeps the trace advancing; a real hang then shows up as a growing
# elapsed time instead of a silently dropped job.
HEARTBEAT_SECONDS=${HEARTBEAT_SECONDS:-60}

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# run_logged <label> <command...>
run_logged() {
  local label=$1
  shift
  local started=$SECONDS status=0 pid hb
  log "start: ${label}"
  "$@" &
  pid=$!
  (
    while sleep "$HEARTBEAT_SECONDS"; do
      kill -0 "$pid" 2>/dev/null || break
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] running: ${label} ($((SECONDS - started))s elapsed)"
    done
  ) &
  hb=$!
  wait "$pid" || status=$?
  kill "$hb" 2>/dev/null || true
  wait "$hb" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    log "failed: ${label} (status ${status}, $((SECONDS - started))s)"
    return "$status"
  fi
  log "done: ${label} ($((SECONDS - started))s)"
}

# ── Configure xzar plan.ai cache ────────────────────────────────────
run_logged "xzar config add-server planai" \
  xzar config add-server planai https://xzar.plan.ai "$XZAR_TOKEN"

# Upload with bounded retries. The previous unconditional `while ! upload; do
# true; done` retried forever with no output, so a persistent xzar failure was
# indistinguishable from a hung build: the trace went quiet and GitLab dropped
# the job as `no_updates_running` with nothing explaining why.
upload() {
  local pin=$1 path=$2 attempt=1 delay=15
  local max_attempts=${XZAR_UPLOAD_ATTEMPTS:-5}
  while :; do
    if run_logged "xzar upload ${pin} (attempt ${attempt}/${max_attempts})" \
      xzar --server planai upload --pin "$pin" --desc "$(readlink -f "$path")" \
      --leave-after-abandon 1m "$path"; then
      return 0
    fi
    if [ "$attempt" -ge "$max_attempts" ]; then
      log "error: xzar upload of ${pin} failed ${max_attempts} times; giving up"
      return 1
    fi
    attempt=$((attempt + 1))
    log "retrying ${pin} in ${delay}s"
    sleep "$delay"
    delay=$((delay * 2))
  done
}

# ── Build devShell & push to xzar cache ─────────────────────────────
run_logged "nix build .#devShells.x86_64-linux.default" \
  nix build .#devShells.x86_64-linux.default -o result-devshell -L
upload memvault/devshell result-devshell
rm -f result-devshell

# ── Build CI image & push to xzar cache ─────────────────────────────
run_logged "nix build .#image" nix build .#image -o result-image -L
upload memvault/image result-image
rm -f result-image

# ── Build all exposed packages & push to xzar cache ────────────────
# memctl-slim is what the flake check boots; memvault-mcp is the MCP server.
for pkg in default memctl memctl-slim memvault-mcp dioxus-cli-patched docker-memctl; do
  run_logged "nix build .#${pkg}" nix build ".#${pkg}" -o "result-${pkg}" -L
  upload "memvault/${pkg}" "result-${pkg}"
  rm -f "result-${pkg}"
done
