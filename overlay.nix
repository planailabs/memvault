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
in
{
  inherit dioxus-cli-patched;

  memctl = prev.callPackage ./package.nix { inherit gitSha dioxus-cli-patched; };

  # Slim build — skips the dx fullstack/WASM client pipeline. Same Rust
  # source, dramatically faster to build; used by integration tests and
  # by anyone running memctl headless.
  memctl-slim = prev.callPackage ./package.nix {
    inherit gitSha dioxus-cli-patched;
    slim = true;
  };
}
