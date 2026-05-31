{
  description = "memvault — local-first, peer-to-peer knowledge base";

  inputs = {
    # Include git submodules (e.g. plan-ai-design) in the flake source.
    self.submodules = true;

    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nixos2docker.url = "git+https://git.plan.ai/plan-ai/nixos2docker";
    nixos2docker.inputs.nixpkgs.follows = "nixpkgs";
    gitlab-incus-image.url = "git+https://git.mkg20001.io/mkg20001/gitlab-incus-image.git";
    gitlab-incus-image.inputs.nixpkgs.follows = "nixpkgs";
    xzar.url = "github:mkg20001/xzar";
    xzar.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, nixos2docker, gitlab-incus-image, xzar, ... }:
    {
      overlays.default = import ./overlay.nix {
        gitSha = self.rev or self.dirtyRev or "unknown";
      };

      nixosModules.default = import ./nix/module.nix;
      nixosModules.memvault = import ./nix/module.nix;

      # NixOS-in-Docker test image with a single memvault node.
      # Build with:
      #   nix build .#nixosConfigurations.test-memvault.config.system.build.dockerImage
      # Then: docker load < result
      nixosConfigurations = let
        # Common base for NixOS-in-Docker test containers.
        baseModule = name: { ... }: {
          virtualisation.dockerImage.name = name;
          virtualisation.dockerImage.tag = "latest";
          fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
          boot.loader.grub.enable = false;
          system.stateVersion = "26.11";
        };

        mkTestSystem = { name, modules }: nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            nixos2docker.nixosModules.default
            (baseModule name)
          ] ++ modules;
        };
      in {
        test-memvault = mkTestSystem {
          name = "test-memvault";
          modules = [
            self.nixosModules.default
            ({ ... }: {
              nixpkgs.overlays = [ self.overlays.default ];
              networking.hostName = "memvault";

              services.memvault = {
                enable = true;
                apiPort = 8401;
                listen = "/ip4/0.0.0.0/tcp/4001";
                openFirewall = true;
              };
            })
          ];
        };
      };
    } //
    flake-utils.lib.eachDefaultSystem (system:
      let
        gitSha = self.rev or self.dirtyRev or "unknown";
        overlays = [
          (import rust-overlay)
          (import ./overlay.nix { inherit gitSha; })
          xzar.overlays.default
        ];
        pkgs = import nixpkgs { inherit system overlays; };
        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [
            "aarch64-apple-darwin"
            "x86_64-apple-darwin"
            "x86_64-unknown-linux-musl"
            "wasm32-unknown-unknown"
          ];
        };

        darwinDeps = pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.libiconv
        ];

        inherit (pkgs) memctl memvault-mcp dioxus-cli-patched;

        # Standalone unpacked MacOSX SDK so cargo-zigbuild can satisfy
        # `-framework CoreFoundation` etc when cross-compiling Apple targets
        # from Linux. We pull the .src out of nixpkgs' darwin.apple_sdk
        # (a plain fetchurl FOD) — this avoids needing to build any darwin
        # stdenv on the host.
        macosx-sdk = let
          darwinPkgs = import nixpkgs { system = "aarch64-darwin"; };
        in darwinPkgs.apple-sdk_26.src;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            toolchain
            cargo-edit
            cargo-watch
            cargo-zigbuild
            zig
            rsync

            # Dioxus fullstack toolchain
            dioxus-cli-patched
            rcodesign  # ad-hoc MachO signing when cross-compiling from Linux

            # Build dependencies
            pkg-config
            openssl
            nodejs
            tailwindcss_3
            lld

            # Dev tools
            xzar-client  # binary cache client

            # WASM
            wasm-pack
            wasm-bindgen-cli_0_2_121
            binaryen  # wasm-opt
          ] ++ darwinDeps;

          RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
        };

        packages = {
          default = memctl;
          memctl = memctl;
          memvault-mcp = memvault-mcp;
          dioxus-cli-patched = dioxus-cli-patched;
          macosx-sdk = macosx-sdk;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          docker-memctl = import ./nix/docker.nix {
            inherit pkgs memctl;
            tag = gitSha;
          };

          # NixOS-in-Incus image for gitlab CI runners.
          image = (nixpkgs.lib.nixosSystem {
            system = "x86_64-linux";
            modules = [
              "${nixpkgs}/nixos/modules/virtualisation/lxc-container.nix"
              gitlab-incus-image.nixosModules.gitlab-incus-image
              ({ pkgs, ... }: {
                environment.systemPackages = with pkgs; [
                  openssh
                  rsync
                  pkgs.xzar-client
                  pixz
                ];

                nixpkgs.overlays = [
                  xzar.overlays.default
                ];

                programs.git.config.advice.detachedHead = false;

                nix.settings = {
                  substituters = [
                    "https://xzar.plan.ai"
                  ];
                  trusted-public-keys = [
                    "xzar.plan.ai:KUE66pjr6UX5HHCn9kedN1DJ2J5nSlBrKmE7tUjXewE="
                  ];
                };
              })
            ];
          }).config.system.build.gitlab-incus-image;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          tarball = pkgs.runCommand "memctl-tarball" {} ''
            mkdir -p $out pack
            cp ${memctl}/bin/memctl pack/memctl
            cd pack
            tar czf $out/memctl.tar.gz memctl
          '';
        };

        checks = pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # Multi-node cluster sync — two NixOS VMs form one cluster and
          # verify a document put on node_a syncs to node_b.
          sync = pkgs.callPackage ./tests/sync.nix { };
        };
      });
}
