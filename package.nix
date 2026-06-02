{
  lib,
  stdenv,
  rustPlatform,
  rust-bin,
  makeRustPlatform,
  pkg-config,
  openssl,
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
  # The slim build wants a rustc + cargo that know about wasm32 because
  # memvault-extract/build.rs nests a wasm32 cargo invocation for the
  # extract-guest crate. The full dx build already brings this via
  # dioxus-cli, so we only override the rustPlatform on the slim path.
  toolchainWasm = rust-bin.stable.latest.default.override {
    targets = [ "wasm32-unknown-unknown" ];
  };
  slimRustPlatform = makeRustPlatform {
    cargo = toolchainWasm;
    rustc = toolchainWasm;
  };
  rp = if slim then slimRustPlatform else rustPlatform;
in

rp.buildRustPackage {
  pname = "memctl";
  version = "0.1.0";
  src = ./.;
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

  buildInputs = [ openssl ]
    ++ lib.optionals stdenv.isDarwin [ libiconv ];

  env.GIT_SHA = gitSha;

  doCheck = false;
}
// (if slim then {
  # Plain cargo build of memctl. Faster than dx by a wide margin;
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
  buildPhase = ''
    runHook preBuild

    # Preflight Cargo metadata so dx's short cargo-metadata watchdog can't
    # mask the underlying Cargo failure on busy CI runners.
    timeout 180 cargo metadata --format-version=1 --locked --no-deps >/dev/null

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

    # `memctl daemon` enables the UI router only when fullstack assets are
    # available. Keep Nix's full Dioxus build self-contained by installing
    # the generated public assets beside the binary, matching memctl's
    # runtime probe; this preserves API-only behaviour for slim/plain builds.
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
})
