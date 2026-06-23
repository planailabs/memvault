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
# Provide an empty stub archive so the linker resolves -ldl. The same temporary
# directory also carries tiny fortify compatibility objects for bundled C code
# that was compiled with glibc-style fortify references while targeting static
# musl (notably zstd-sys on CI).
DL_STUB="$(mktemp -d)"
cat > "$DL_STUB/fortify-compat.c" <<'FORTIFY_COMPAT'
typedef __SIZE_TYPE__ size_t;
void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) {
  (void)destlen;
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  for (size_t i = 0; i < len; i++) d[i] = s[i];
  return dest;
}
void *__memmove_chk(void *dest, const void *src, size_t len, size_t destlen) {
  (void)destlen;
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  if (d < s) {
    for (size_t i = 0; i < len; i++) d[i] = s[i];
  } else {
    for (size_t i = len; i > 0; i--) d[i - 1] = s[i - 1];
  }
  return dest;
}
void *__memset_chk(void *dest, int c, size_t len, size_t destlen) {
  (void)destlen;
  unsigned char *d = (unsigned char *)dest;
  for (size_t i = 0; i < len; i++) d[i] = (unsigned char)c;
  return dest;
}
FORTIFY_COMPAT
cc -c "$DL_STUB/fortify-compat.c" -o "$DL_STUB/fortify-compat.o"
ar rcs "$DL_STUB/libdl.a" "$DL_STUB/fortify-compat.o"
export RUSTFLAGS="${RUSTFLAGS:-} -L $DL_STUB"

# zstd-sys compiles bundled C code during the server build. On the Nix CI
# shell's musl cross toolchain, fortify can leave references such as
# `__memcpy_chk` that are not provided by the static musl link. Disable fortify
# only for this musl artifact build; the native CI build/test path remains
# covered by the default Nix hardening flags.
OLD_HARDENING_DISABLE="${hardeningDisable-}"
export hardeningDisable="${hardeningDisable:-} fortify"
export CFLAGS_x86_64_unknown_linux_musl="${CFLAGS_x86_64_unknown_linux_musl:-} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"

dx build --package memctl --release --embed \
  @client --platform web --no-default-features --features web \
  @server --platform server --features embed --target x86_64-unknown-linux-musl

rm -rf "$DL_STUB"
unset RUSTFLAGS
unset CFLAGS_x86_64_unknown_linux_musl
if [ -n "$OLD_HARDENING_DISABLE" ]; then
  export hardeningDisable="$OLD_HARDENING_DISABLE"
else
  unset hardeningDisable
fi
unset OLD_HARDENING_DISABLE

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
