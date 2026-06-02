#!/usr/bin/env bash
# Build memctl for every supported target and drop the binaries under
# ./artifacts/<nix-system>/memctl so CI can collect them as job artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR/artifacts"

# ── Tailwind CSS ────────────────────────────────────────────────────────
(cd "$SCRIPT_DIR/crates/memvault-web" && npm run tailwind:build)

# ── Helpers ─────────────────────────────────────────────────────────────

nix_system_for() {
  case "$1" in
    x86_64-unknown-linux-musl) echo "x86_64-linux" ;;
    aarch64-apple-darwin)      echo "aarch64-darwin" ;;
    *) echo "unknown rust target: $1" >&2; exit 1 ;;
  esac
}

stage_memctl_binary() {
  local rust_target="$1"
  local nix_system
  nix_system="$(nix_system_for "$rust_target")"
  local bin_src="$SCRIPT_DIR/target/dx/memctl/release/web/server"

  if [ ! -f "$bin_src" ]; then
    echo "missing memctl binary: $bin_src" >&2
    exit 1
  fi

  local dest="$ARTIFACT_DIR/$nix_system"
  mkdir -p "$dest"
  cp "$bin_src" "$dest/memctl"
  chmod +x "$dest/memctl"
  echo "✓ staged $dest/memctl"
}

mkdir -p "$ARTIFACT_DIR"

# ── Linux (musl) ────────────────────────────────────────────────────────
# libloading (via dioxus→subsecond) emits #[link(name = "dl")] on Linux,
# but musl libc has dlopen/dlsym built-in — no separate libdl exists.
# Provide an empty stub archive so the linker resolves -ldl.
DL_STUB="$(mktemp -d)"
ar rcs "$DL_STUB/libdl.a"
export RUSTFLAGS="${RUSTFLAGS:-} -L $DL_STUB"

dx build --package memctl --release --embed \
  @client --platform web --no-default-features --features web \
  @server --platform server --features embed --target x86_64-unknown-linux-musl

rm -rf "$DL_STUB"
unset RUSTFLAGS

stage_memctl_binary x86_64-unknown-linux-musl

# ── macOS (aarch64) ─────────────────────────────────────────────────────
SDKROOT="$(nix build --no-link --print-out-paths "$SCRIPT_DIR#macosx-sdk")"
export SDKROOT

# Shim cargo so dx uses cargo-zigbuild for the macOS cross-compile.
# zigbuild handles cc-rs, assembly, and linking via zig's built-in
# cross-compilation — no manual CC/AR wrappers needed.
CARGO_SHIM="$(mktemp -d)"
REAL_CARGO="$(which cargo)"
ZIGBUILD="$(which cargo-zigbuild)"
cat > "$CARGO_SHIM/cargo" <<SHIM
#!/usr/bin/env bash
# Only use zigbuild for apple/darwin targets; pass through for wasm/native.
# dx calls "cargo rustc ..." so we invoke cargo-zigbuild directly (it
# accepts build/rustc/test/run subcommands natively).
use_zig=false
prev=""
# Strip +toolchain args (e.g. +nightly) — cargo-zigbuild doesn't support them.
args=()
for arg in "\$@"; do
  case "\$prev" in
    --target) [[ "\$arg" == *apple* || "\$arg" == *darwin* ]] && use_zig=true ;;
  esac
  case "\$arg" in
    --target=*apple*|--target=*darwin*) use_zig=true ;;
    +*) prev="\$arg"; continue ;;
  esac
  prev="\$arg"
  args+=("\$arg")
done
if \$use_zig; then
  CARGO="$REAL_CARGO" exec "$ZIGBUILD" "\${args[@]}"
else
  exec "$REAL_CARGO" "\$@"
fi
SHIM
chmod +x "$CARGO_SHIM/cargo"
export PATH="$CARGO_SHIM:$PATH"

dx build --package memctl --release --embed \
  @client --platform web --no-default-features --features web \
  @server --platform server --features embed --target aarch64-apple-darwin

export PATH="${PATH#"$CARGO_SHIM:"}"
rm -rf "$CARGO_SHIM"

stage_memctl_binary aarch64-apple-darwin

echo
echo "✓ memctl artifacts ready under $ARTIFACT_DIR/"
find "$ARTIFACT_DIR" -type f
