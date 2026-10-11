{ gitSha ? "unknown" }:

final: prev:
let
  # Patched dioxus-cli with:
  # - --skip-platform-features: prevents dx from auto-adding "web"/"desktop"/etc.
  # - --embed: embeds public assets into the server binary via rust-embed.
  # - optional codesign: falls back to rcodesign for cross-compilation.
  dioxus-cli-patched = prev.dioxus-cli.overrideAttrs (old: {
    patches = (old.patches or []) ++ [
      ./patches/dioxus-cli-all.patch
    ];
  });

  # cargo-zigbuild 0.23.4 regressed Apple cross-links (rust-cross/cargo-zigbuild
  # #479). Its #477 `-Wl,<path>` rewrite turns a `-Wl,<existing-file>` operand
  # into a bare positional, even when that operand belongs to
  # `-Wl,-exported_symbols_list`. rustc emits the export list as two args
  # (`-Wl,-exported_symbols_list -Wl,<list>`), so the list is detached and the
  # linker binds the flag to the next token, `-dead_strip`:
  #   error: unable to read exported symbols list '-dead_strip': FileNotFound
  # The bug is masked under zig < 0.16 (the flag pair is stripped outright) but
  # nixpkgs ships zig 0.16.0, so every Apple CDYLIB link broke — the
  # `artifact:memctl` job fails while cross-compiling for aarch64-apple-darwin.
  # The upstream fix (#480) is unreleased (0.23.4 is still the latest tag), so
  # pin the last known-good release. 0.23.3 links the same cdylib (per #479).
  # Built via buildRustPackage directly (not overrideAttrs) so the vendor hash
  # is recomputed for the pinned version.
  cargo-zigbuild = prev.rustPlatform.buildRustPackage {
    pname = "cargo-zigbuild";
    version = "0.23.3";
    src = prev.fetchFromGitHub {
      owner = "rust-cross";
      repo = "cargo-zigbuild";
      tag = "v0.23.3";
      hash = "sha256-woxvGA+Pa224PSRzSVWg6cCFzd5XwcuSTR9J9GGFD+s=";
    };
    cargoHash = "sha256-SSMS3WVZiae+NOiOn2mrcsKfVW6rwzjZIbl+vXStm2k=";
    nativeBuildInputs = [ prev.makeWrapper ];
    postInstall = ''
      wrapProgram $out/bin/cargo-zigbuild \
        --prefix PATH : ${prev.zig}/bin
    '';
    doInstallCheck = true;
    nativeInstallCheckInputs = [ prev.versionCheckHook ];
    versionCheckProgramArg = "--version";
    meta = {
      description = "Tool to compile Cargo projects with zig as the linker";
      mainProgram = "cargo-zigbuild";
      homepage = "https://github.com/rust-cross/cargo-zigbuild";
      license = prev.lib.licenses.mit;
    };
  };
in
{
  inherit dioxus-cli-patched;
  inherit cargo-zigbuild;

  memctl = prev.callPackage ./package.nix { inherit gitSha dioxus-cli-patched; };

  # Slim build — skips the dx fullstack/WASM client pipeline. Same Rust
  # source, dramatically faster to build; used by integration tests and
  # by anyone running memctl headless.
  memctl-slim = prev.callPackage ./package.nix {
    inherit gitSha dioxus-cli-patched;
    slim = true;
  };

  # MCP server: standalone Rust binary that fronts a memvault cluster
  # over the Model Context Protocol (stdio).
  memvault-mcp = prev.callPackage ./nix/memvault-mcp.nix { };
}
