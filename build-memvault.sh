#!/usr/bin/env bash
# Build the memctl binary (memvault CLI + embedded web UI daemon) via dx.
# Both client (WASM) and server (native daemon) are compiled from the same
# crate, sharing a cache — this guarantees hydration consistency.
#
# The --embed flag tells dx to bake the client's public assets into the
# server binary via dioxus-server's rust-embed integration.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$SCRIPT_DIR/crates/memvault-web"

# Cargo and dx both need a usable Cargo home. CI normally symlinks ~/.cargo to a
# shared cache volume; if that symlink is broken, dx's nested cargo-metadata run
# fails later with an opaque "failed to create directory ... File exists" error.
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_HOME
if [ -L "$CARGO_HOME" ] && [ ! -e "$CARGO_HOME" ]; then
  echo "✗ CARGO_HOME points at a broken symlink: $CARGO_HOME -> $(readlink "$CARGO_HOME")" >&2
  echo "  Initialize the cache target before linking ~/.cargo." >&2
  exit 1
fi

RELEASE="${RELEASE:-1}"
if [ "$RELEASE" = "1" ]; then
  DX_PROFILE="--release"
else
  DX_PROFILE=""
fi

# ── 1. Cargo metadata preflight ─────────────────────────────────────────
# dx has its own cargo-metadata watchdog.  On loaded CI runners that watchdog
# can expire before emitting useful Cargo diagnostics, so resolve metadata once
# up front with a normal timeout.  This both warms Cargo's metadata cache for dx
# and makes lock/network failures point at the actual failing command.
METADATA_TIMEOUT="${CARGO_METADATA_TIMEOUT:-180}"
echo "▸ Preflighting cargo metadata (timeout: ${METADATA_TIMEOUT}s)…"
set +e
timeout "$METADATA_TIMEOUT" cargo metadata --format-version=1 --locked --no-deps >/dev/null
status=$?
set -e
if [ "$status" -ne 0 ]; then
  echo "✗ cargo metadata preflight failed (exit ${status})" >&2
  echo "Active cargo/rustc processes:" >&2
  ps -ef | grep -E '[c]argo|[r]ustc|[r]ustdoc' >&2 || true
  exit "$status"
fi

# ── 2. Tailwind CSS ─────────────────────────────────────────────────────
echo "▸ Building Tailwind CSS…"
(cd "$WEB_DIR" && npm run tailwind:build)

# ── 3. Dioxus fullstack build ───────────────────────────────────────────
# Use @client/@server overrides so the WASM client only gets the web feature
# (avoiding native deps like tokio/mio) while the server gets all features
# for a fully functional daemon binary.
echo "▸ Building Dioxus fullstack (client + server)…"
# `nix develop` may set TMPDIR to an executor-owned /tmp/nix-shell.* directory.
# dx and tee both create temporary files during bundling, and failures there used
# to surface as opaque rustc/dx errors plus "tee: ... Operation not permitted".
# Force a repository-local writable temp/log directory before invoking dx.
BUILD_TMPDIR="${MEMVAULT_BUILD_TMPDIR:-$SCRIPT_DIR/target/build-memvault-tmp}"
mkdir -p "$BUILD_TMPDIR"
if ! tmp_probe="$(mktemp "$BUILD_TMPDIR/write-test.XXXXXX")"; then
  echo "✗ Cannot create temporary files in $BUILD_TMPDIR" >&2
  ls -ld "$BUILD_TMPDIR" >&2 || true
  exit 1
fi
rm -f "$tmp_probe"
export TMPDIR="$BUILD_TMPDIR"
DX_LOG="$BUILD_TMPDIR/dx-build-memctl.$$.log"
DX_CMD=(dx build --package memctl)
if [ -n "$DX_PROFILE" ]; then
  DX_CMD+=("$DX_PROFILE")
fi
# `--embed` bakes the client assets into the server binary; `@server
# --features embed` turns on memctl's `embed` cargo feature, which is the
# runtime gate (`#[cfg(feature = "embed")]`) that makes the daemon actually
# serve the fullstack web UI. Both are required — without the feature the
# assets are embedded but the daemon reports "Web UI: disabled".
DX_CMD+=(--embed
  @client --platform web --no-default-features --features web
  @server --platform server --features embed)
set +e
"${DX_CMD[@]}" 2>&1 | tee "$DX_LOG"
status=${PIPESTATUS[0]}
set -e
if [ "$status" -ne 0 ]; then
  echo "✗ dx build failed (exit ${status})" >&2
  if [ -f "$DX_LOG" ]; then
    echo "Last 120 lines from $DX_LOG:" >&2
    tail -n 120 "$DX_LOG" >&2 || true
  else
    echo "No dx log was written at $DX_LOG" >&2
  fi
  if grep -q "cargo metadata took too long" "$DX_LOG" 2>/dev/null; then
    echo "✗ dx timed out waiting for cargo metadata even after preflight." >&2
  fi
  echo "Active cargo/rustc/dx processes:" >&2
  ps -ef | grep -E '[c]argo|[r]ustc|[r]ustdoc|[d]x' >&2 || true
  echo "Temporary directory state:" >&2
  ls -ld "$TMPDIR" "$BUILD_TMPDIR" >&2 || true
  df -h "$BUILD_TMPDIR" >&2 || true
  exit "$status"
fi
rm -f "$DX_LOG"

echo "✓ memctl built (assets embedded in server binary)"
echo "  Binary: $SCRIPT_DIR/target/dx/memctl/release/web/server"
