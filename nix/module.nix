{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.memvault;
  stateDir = "/var/lib/memvault";
in
{
  options.services.memvault = {
    enable = lib.mkEnableOption "memvault daemon (memctl daemon)";

    package = lib.mkPackageOption pkgs "memctl" { };

    apiPort = lib.mkOption {
      type = lib.types.port;
      default = 8401;
      description = ''
        TCP port for the embedded HTTP API + web UI.
        The daemon binds to 127.0.0.1; expose it via a reverse proxy if needed.
      '';
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "/ip4/0.0.0.0/tcp/0";
      description = ''
        libp2p multiaddr the swarm listens on. The default uses an
        OS-assigned TCP port; pick a fixed one (e.g. `/ip4/0.0.0.0/tcp/4001`)
        if you want a stable port for firewalling.
      '';
      example = "/ip4/0.0.0.0/tcp/4001";
    };

    bootstrap = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        libp2p multiaddrs of bootstrap peers to dial on startup.
      '';
      example = [ "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooW..." ];
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether to open the listen port (parsed from `services.memvault.listen`)
        in the firewall. Only effective for `/ip4/.../tcp/<port>` style
        multiaddrs with a non-zero port.
      '';
    };

    allowedOrigins = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "https://memvault.example.com" ];
      description = ''
        Extra HTTP `Origin` values the CSRF guard accepts. The daemon
        already accepts same-origin requests (where the request `Origin`
        matches `Host`), so this list is only needed when a reverse
        proxy rewrites the public hostname — then the browser's `Origin`
        is the proxy's URL but `Host` (as the daemon sees it) is the
        upstream's. Listing the proxy URL here closes the gap.
      '';
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File containing extra environment variables for the service
        (KEY=VALUE per line). Useful for `RUST_LOG`, secrets, or
        `MEMVAULT_*` overrides not exposed by this module.
      '';
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional arguments passed to `memctl daemon`.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.memvault = {
      description = "memvault daemon";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        MEMVAULT_DATA_DIR = stateDir;
        MEMVAULT_API_PORT = toString cfg.apiPort;
      } // lib.optionalAttrs (cfg.allowedOrigins != [ ]) {
        MEMVAULT_ALLOWED_ORIGINS = lib.concatStringsSep "," cfg.allowedOrigins;
      };

      serviceConfig = {
        ExecStart = lib.concatStringsSep " " ([
          (lib.getExe cfg.package)
          "daemon"
          "--listen" (lib.escapeShellArg cfg.listen)
          "--api-port" (toString cfg.apiPort)
        ] ++ lib.optionals (cfg.bootstrap != [ ]) [
          "--bootstrap" (lib.escapeShellArg (lib.concatStringsSep "," cfg.bootstrap))
        ] ++ map lib.escapeShellArg cfg.extraArgs);

        Restart = "on-failure";
        RestartSec = 5;

        DynamicUser = true;
        StateDirectory = "memvault";
        WorkingDirectory = stateDir;

        # Hardening
        CapabilityBoundingSet = "";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        # libp2p QUIC + mDNS need AF_NETLINK for interface enumeration.
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
      } // lib.optionalAttrs (cfg.environmentFile != null) {
        EnvironmentFile = cfg.environmentFile;
      };
    };

    networking.firewall = lib.mkIf cfg.openFirewall (
      let
        # Extract TCP port from a `/ip4/.../tcp/<port>` style multiaddr.
        m = builtins.match ".*/tcp/([0-9]+).*" cfg.listen;
        port = if m == null then null else lib.toInt (builtins.head m);
      in
      lib.mkIf (port != null && port != 0) {
        allowedTCPPorts = [ port ];
      }
    );
  };
}
