# NixOS integration test for memvault cluster sync.
#
# Two nodes (a, b) form one cluster:
#   1. node_a runs `memctl genesis` and issues a node-join token
#   2. node_b consumes the token via `memctl cluster-join`
#   3. node_a stores a document with `memctl put`
#   4. both daemons start; libp2p (mDNS + bitswap + gossipsub) syncs blocks
#   5. node_b's daemon is stopped and `memctl list` is asserted to show the doc
#
# Build / run with:
#   nix build .#checks.x86_64-linux.sync -L
{ pkgs, ... }:

let
  # API-only memctl build — skips the dx fullstack/WASM client and just
  # compiles the native daemon (memvault-web/server, axum, dioxus SSR).
  # Drastically faster than the full dx build and sufficient for sync
  # verification through CLI commands.
  memctl-test = pkgs.rustPlatform.buildRustPackage {
    pname = "memctl-test";
    version = "0.1.0";
    src = ./..;
    cargoLock = {
      lockFile = ../Cargo.lock;
      outputHashes = import ../extra-hashes.nix;
    };
    cargoBuildFlags = [ "-p" "memctl" ];
    doCheck = false;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.openssl ];
    meta.mainProgram = "memctl";
  };

  commonNode = { pkgs, ... }: {
    environment.systemPackages = [
      memctl-test
      pkgs.jq
    ];
    # Avoid firewall interference with libp2p TCP + mDNS between test
    # machines.
    networking.firewall.enable = false;
    # mDNS broadcast must reach the peer interface.
    networking.firewall.allowedUDPPorts = [ 5353 ];
    # Stable data dir for both genesis/join and the running daemon.
    environment.variables.MEMVAULT_DATA_DIR = "/var/lib/memvault";
    environment.variables.RUST_LOG = "info,memvault_swarm=debug";
  };
in

pkgs.testers.nixosTest {
  name = "memvault-sync";

  nodes = {
    node_a = commonNode;
    node_b = commonNode;
  };

  testScript = ''
    import re
    import time

    start_all()

    for m in [node_a, node_b]:
        m.succeed("mkdir -p /var/lib/memvault")

    # ── 1. Genesis on node_a ─────────────────────────────────────────
    node_a.log("Running genesis on node_a")
    node_a.succeed("memctl genesis 2>&1 | tee /tmp/genesis.log")

    # ── 2. Issue a node-join token on node_a ────────────────────────
    node_a.log("Issuing join token on node_a")
    token_out = node_a.succeed(
        "memctl token issue --node-role node --ttl 3600 --max-uses 1 "
        "--label node-b-join 2>/dev/null"
    )
    token = ""
    for line in token_out.splitlines():
        line = line.strip()
        if line.startswith("mvjoin1:"):
            token = line
            break
    assert token, f"no mvjoin1: token in `token issue` output:\n{token_out}"
    node_a.log(f"Got join token: {token[:40]}...")

    # ── 3. node_b consumes the token ─────────────────────────────────
    node_b.log("Joining cluster on node_b")
    node_b.succeed(f"memctl cluster-join '{token}'")

    # ── 4. node_a stores a document BEFORE its daemon starts ────────
    # `memctl put` opens the redb store directly, so it must run while no
    # daemon holds the file lock.
    node_a.log("Storing test document on node_a")
    doc_text = "hello-from-node-a-cross-sync-fixture"
    doc_id_out = node_a.succeed(
        f"memctl put '{doc_text}' --title 'sync-test' --tag 'project:test'"
    )
    doc_id = doc_id_out.strip().splitlines()[-1].strip()
    assert re.fullmatch(r"[0-9a-f]+", doc_id), \
        f"unexpected put output (not a hex doc id): {doc_id_out!r}"
    node_a.log(f"Document stored with id={doc_id}")

    # Sanity: node_b should NOT have the doc yet.
    pre_list = node_b.succeed("memctl list --limit 50")
    assert doc_id not in pre_list, \
        f"node_b unexpectedly already has the doc:\n{pre_list}"

    # ── 5. Start daemons on both nodes ──────────────────────────────
    # Pin TCP ports so the swarm is observable; mDNS handles peer
    # discovery on the shared test subnet.
    node_a.execute(
        "memctl daemon --listen /ip4/0.0.0.0/tcp/4001 --api-port 8401 "
        ">/tmp/daemon.log 2>&1 &"
    )
    node_b.execute(
        "memctl daemon --listen /ip4/0.0.0.0/tcp/4001 --api-port 8401 "
        ">/tmp/daemon.log 2>&1 &"
    )

    for m, name in [(node_a, "node_a"), (node_b, "node_b")]:
        m.wait_for_open_port(8401)
        m.log(f"{name} daemon API up on 8401")

    # ── 6. Wait for node_b to discover node_a and sync the doc ──────
    # libp2p mDNS + gossipsub + bitswap pull blocks; this is async, so
    # poll the HTTP search endpoint instead of guessing a sleep.
    synced = False
    last_status = ""
    for attempt in range(120):
        status, body = node_b.execute(
            f"curl -sf 'http://127.0.0.1:8401/api/v1/search?q={doc_text}' "
            "|| true"
        )
        last_status = body
        if doc_id in body or doc_text in body:
            synced = True
            node_b.log(
                f"node_b observed the doc via HTTP search after ~{attempt}s"
            )
            break
        time.sleep(1)

    if not synced:
        node_a.log("--- node_a daemon log ---")
        node_a.log(node_a.succeed("cat /tmp/daemon.log | tail -100"))
        node_b.log("--- node_b daemon log ---")
        node_b.log(node_b.succeed("cat /tmp/daemon.log | tail -100"))
        raise Exception(
            f"node_b never synced the doc from node_a within 120s. "
            f"last /api/v1/search response: {last_status!r}"
        )

    # ── 7. Stop node_b's daemon and confirm via the CLI ─────────────
    # `memctl list` re-opens the redb store directly; the daemon must
    # release the file lock first.
    node_b.execute("pkill -TERM -f 'memctl daemon' || true")
    for _ in range(30):
        status, _ = node_b.execute("pgrep -f 'memctl daemon'")
        if status != 0:
            break
        time.sleep(1)

    list_out = node_b.succeed("memctl list --limit 50")
    assert doc_id in list_out, (
        f"node_b's local store does not contain the synced doc {doc_id}:\n"
        f"{list_out}"
    )
    node_b.log("node_b's CLI confirmed the synced document")

    node_b.log("All memvault sync tests passed!")
  '';
}
