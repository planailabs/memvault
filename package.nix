{
  lib,
  stdenv,
  rust-bin,
  makeRustPlatform,
  pkg-config,
  openssl,
  zstd,
  dioxus-cli-patched,
  nodejs,
  wasm-bindgen-cli_0_2_121,
  binaryen,
  tailwindcss_3,
  lld,
  rcodesign,
  libiconv,
  gitSha ? "unknown",
  # When true, build a slim `memctl` via plain `cargo build` — skips the
  # dx fullstack/WASM client pipeline. The resulting binary still serves
  # the API + SSR routes the daemon needs (the embedded WASM client is
  # the only thing missing), which is enough for integration tests and
  # any headless deployment that doesn't actually use the browser UI.
  slim ? false,
}:

let
  # Both build flavors want a rustc + cargo that know about the wasm32
  # targets because memvault-extract/build.rs nests wasm32 cargo
  # invocations for the guest crates: wasm32-unknown-unknown (text guest)
  # and wasm32-wasip1 (media guests). nixpkgs' rustc ships
  # wasm32-unknown-unknown std but not wasip1, so override the toolchain
  # via rust-overlay on both paths.
  toolchainWasm = rust-bin.stable.latest.default.override {
    targets = [ "wasm32-unknown-unknown" "wasm32-wasip1" ];
  };
  wasmRustPlatform = makeRustPlatform {
    cargo = toolchainWasm;
    rustc = toolchainWasm;
  };
  rp = wasmRustPlatform;
in

rp.buildRustPackage ({
  pname = "memctl";
  version = "0.1.0";
  # Only what the build reads, so a commit to CI, docs, tests or nix does not
  # rebuild memctl.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./crates ./plan-ai-design ];
  };
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = import ./extra-hashes.nix;
  };

  nativeBuildInputs = [
    pkg-config
    nodejs
    tailwindcss_3
  ] ++ lib.optionals (!slim) [
    dioxus-cli-patched
    wasm-bindgen-cli_0_2_121
    binaryen
    lld
    rcodesign
  ];

  buildInputs = [
    openssl
    # nixpkgs' cargo-setup-hook exports ZSTD_SYS_USE_PKG_CONFIG=1 for every
    # cargo build, so zstd-sys (pulled in by tantivy-sstable /
    # wasmtime-internal-cache) resolves libzstd through pkg-config instead of
    # compiling its vendored copy. Without zstd on the pkg-config path the
    # build script panics with "Can't probe for zstd in pkg-config" before any
    # crate is compiled.
    zstd
  ] ++ lib.optionals stdenv.isDarwin [ libiconv ];

  env.GIT_SHA = gitSha;

  doCheck = false;
} // (if slim then {
  # Plain cargo build of memctl only. Faster than dx by a wide margin;
  # adequate for any caller that doesn't serve the browser-side WASM
  # client (integration tests, headless deployments).
  cargoBuildFlags = [ "-p" "memctl" ];

  meta = {
    description = "memvault control binary (slim: no embedded WASM client)";
    license = lib.licenses.asl20;
    mainProgram = "memctl";
  };
} else {
  # Fullstack build via dx: @client gets only the web feature (no native
  # deps like tokio/mio), @server gets default features + `embed`. --embed
  # bakes the client's public assets into the server binary via rust-embed;
  # `@server --features embed` turns on the runtime gate
  # (`#[cfg(feature = "embed")]`) that makes the daemon serve the fullstack
  # web UI. Both are required — without the feature the assets are embedded
  # but `memctl daemon` reports "Web UI: disabled".
  #
  # Keep these phases inside the buildRustPackage argument set. Merging them
  # onto the finished derivation would only add inert attributes and would let
  # the default cargo build compile/install every workspace binary instead of
  # the dx-built memctl package.
  buildPhase = ''
    runHook preBuild

    # Preflight Cargo metadata so dx's short cargo-metadata watchdog can't
    # mask the underlying Cargo failure on busy CI runners. Keep the budget as
    # high as dx's own (patches/dioxus-cli-all.patch: 30 min): on a loaded
    # builder this workspace's ~1250 crates take many minutes, and a 180 s bound
    # aborted the nix build with dx reporting "cargo metadata took too long".
    timeout 1800 cargo metadata --format-version=1 --locked >/dev/null

    # Tailwind CSS for memvault-web
    (cd crates/memvault-web && npm run tailwind:build)

    dx build --package memctl --release --embed \
      @client --platform web --no-default-features --features web \
      @server --platform server --features embed

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    cp target/dx/memctl/release/web/server $out/bin/memctl

    # `memctl daemon` enables the UI router when it is compiled with the
    # embed feature. If dx also emits a public directory, install it beside
    # the binary for tooling/static fallbacks; embedded-only builds are valid.
    if [ -d target/dx/memctl/release/web/public ]; then
      cp -r target/dx/memctl/release/web/public $out/bin/public
    fi

    runHook postInstall
  '';

  meta = {
    description = "memvault control binary (CLI + embedded daemon with web UI)";
    license = lib.licenses.asl20;
    mainProgram = "memctl";
  };
}))
