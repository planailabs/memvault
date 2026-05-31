{
  pkgs,
  memctl,
  tag ? "latest",
}:

let
  cacert = pkgs.cacert;
  certEnv = "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt";
in
pkgs.dockerTools.buildLayeredImage {
  name = "memctl";
  inherit tag;
  contents = [ memctl cacert ];
  config = {
    Entrypoint = [ "${memctl}/bin/memctl" ];
    Cmd = [ "daemon" ];
    Env = [
      certEnv
      "MEMVAULT_DATA_DIR=/var/lib/memvault"
      "MEMVAULT_API_PORT=8401"
    ];
    ExposedPorts = {
      "8401/tcp" = { };
    };
    Volumes = {
      "/var/lib/memvault" = { };
    };
    WorkingDir = "/var/lib/memvault";
  };
}
