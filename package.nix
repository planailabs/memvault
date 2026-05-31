{
  lib,
  stdenv,
  rustPlatform,
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
}:

rustPlatform.buildRustPackage {
  pname = "memctl";
  version = "0.1.0";
  src = ./.;
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = import ./extra-hashes.nix;
  };

  nativeBuildInputs = [
    pkg-config
    dioxus-cli-patched
    nodejs
    wasm-bindgen-cli_0_2_121
    binaryen
    tailwindcss_3
    lld
    rcodesign
  ];

  buildInputs = [ openssl ]
    ++ lib.optionals stdenv.isDarwin [ libiconv ];

  env.GIT_SHA = gitSha;

  doCheck = false;

  # Fullstack build via dx: @client gets only the web feature (no native
  # deps like tokio/mio), @server gets default features. --embed bakes the
  # client's public assets into the server binary via rust-embed.
  buildPhase = ''
    runHook preBuild

    # Preflight Cargo metadata so dx's short cargo-metadata watchdog can't
    # mask the underlying Cargo failure on busy CI runners.
    timeout 180 cargo metadata --format-version=1 --locked --no-deps >/dev/null

    # Tailwind CSS for memvault-web
    (cd crates/memvault-web && npm run tailwind:build)

    dx build --package memctl --release --embed \
      @client --platform web --no-default-features --features web \
      @server --platform server

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    cp target/dx/memctl/release/web/server $out/bin/memctl
    runHook postInstall
  '';

  meta = {
    description = "memvault control binary (CLI + embedded daemon with web UI)";
    license = lib.licenses.asl20;
    mainProgram = "memctl";
  };
}
