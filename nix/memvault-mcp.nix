{
  lib,
  stdenv,
  rust-bin,
  makeRustPlatform,
  pkg-config,
  openssl,
  libiconv,
}:

let
  # memvault-extract's build.rs nests `cargo build --target
  # wasm32-unknown-unknown` (text guest) and `--target wasm32-wasip1`
  # (media guests) invocations. nixpkgs' default rustc has no wasm std,
  # so override via rust-overlay.
  toolchainWasm = rust-bin.stable.latest.default.override {
    targets = [ "wasm32-unknown-unknown" "wasm32-wasip1" ];
  };
  rp = makeRustPlatform {
    cargo = toolchainWasm;
    rustc = toolchainWasm;
  };
in

rp.buildRustPackage {
  pname = "memvault-mcp";
  version = "0.1.0";
  src = ./..;
  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = import ../extra-hashes.nix;
  };
  cargoBuildFlags = [ "-p" "memvault-mcp" ];
  doCheck = false;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ]
    ++ lib.optionals stdenv.isDarwin [ libiconv ];

  meta = {
    description = "memvault MCP (Model Context Protocol) server";
    license = lib.licenses.asl20;
    mainProgram = "memvault-mcp";
  };
}
