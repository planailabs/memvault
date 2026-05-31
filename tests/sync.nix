# NixOS integration test for memvault cluster sync.
#
# Two nodes (a, b) form one cluster, and each enrols its own agent so the
# write/read paths can stay on the HTTP API while the daemons keep running.
#
# Build / run with:
#   nix build .#checks.x86_64-linux.sync -L
{ pkgs, ... }:

let
  # Use the shared slim memctl from the overlay rather than redeclaring
  # the derivation here. `pkgs.memctl-slim` skips the dx fullstack /
  # WASM client pipeline but still serves the API + SSR routes the
  # daemon needs — adequate for the HTTP integration paths this test
  # exercises.
  memctl-test = pkgs.memctl-slim;

  commonNode = { pkgs, ... }: {
    environment.systemPackages = [
      memctl-test
      pkgs.jq
    ];
    # Allow libp2p TCP + mDNS between the two test machines.
    networking.firewall.enable = false;
    networking.firewall.allowedUDPPorts = [ 5353 ];
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

    def last_token(output):
        for line in reversed(output.splitlines()):
            line = line.strip()
            if line.startswith("mvjoin1:"):
                return line
        raise Exception(f"no mvjoin1: token in output:\n{output}")

    # ── 1. Genesis + agent/token setup on node_a (no daemon yet) ────
    node_a.log("Running genesis on node_a")
    node_a.succeed("memctl genesis 2>&1 | tee /tmp/genesis.log")

    node_a.log("Issuing writer-agent token on node_a")
    writer_token = last_token(node_a.succeed(
        "memctl token issue --agent-role agent-host --label writer "
        "--ttl 86400 --max-uses 1"
    ))

    node_a.log("Enrolling writer agent on node_a")
    writer_enroll_out = node_a.succeed(
        f"memctl agent enroll --token '{writer_token}' --agent-id writer"
    )
    node_a.succeed("test -f /var/lib/memvault/agents/writer/private_key.pem")
    bucket_match = re.search(r"Bucket:\s*([0-9a-f]{64})", writer_enroll_out)
    assert bucket_match, (
        "could not parse writer bucket id from enroll output:\n"
        + writer_enroll_out
    )
    writer_bucket = bucket_match.group(1)
    node_a.log(f"Writer bucket = {writer_bucket}")

    node_a.log("Issuing node-join token for node_b")
    node_token = last_token(node_a.succeed(
        "memctl token issue --node-role node --label node-b "
        "--ttl 86400 --max-uses 1"
    ))

    node_a.log("Issuing reader-agent token (to be redeemed on node_b)")
    reader_token = last_token(node_a.succeed(
        "memctl token issue --agent-role agent-host --label reader "
        "--ttl 86400 --max-uses 1"
    ))

    # ── 2. node_b joins the cluster and enrols its reader agent ─────
    node_b.log("Joining cluster on node_b")
    node_b.succeed(f"memctl cluster-join '{node_token}'")

    node_b.log("Enrolling reader agent on node_b")
    node_b.succeed(
        f"memctl agent enroll --token '{reader_token}' --agent-id reader"
    )
    node_b.succeed("test -f /var/lib/memvault/agents/reader/private_key.pem")

    # ── 3. Start daemons on both nodes ──────────────────────────────
    # `--url http://localhost:8401` (distinct from the literal default
    # `http://127.0.0.1:8401`) defeats memctl's "fall back to local db"
    # heuristic so subsequent CLI calls actually hit the HTTP API.
    for m, name in [(node_a, "node_a"), (node_b, "node_b")]:
        m.execute(
            "memctl daemon --listen /ip4/0.0.0.0/tcp/4001 --api-port 8401 "
            ">/tmp/daemon.log 2>&1 &"
        )
        m.wait_for_open_port(8401)
        m.log(f"{name} daemon API up on 8401")

    # ── 4. Writer agent on node_a creates a doc via HTTP ────────────
    doc_text = "hello-from-node-a-cross-sync-fixture"
    node_a.succeed(f"printf '%s' '{doc_text}' > /tmp/sync-test.md")

    node_a.log("Importing doc as writer agent over HTTP")
    import_rc, import_out = node_a.execute(
        "memctl --url http://localhost:8401 "
        "--identity-dir /var/lib/memvault/agents/writer "
        "import-docs --visibility public /tmp/sync-test.md 2>&1"
    )
    if import_rc != 0:
        node_a.log(f"import-docs failed (rc={import_rc}):\n{import_out}")
        node_a.log("--- node_a daemon log (tail) ---")
        node_a.log(node_a.succeed("tail -200 /tmp/daemon.log"))
        raise Exception(f"import-docs exited {import_rc}")
    m = re.search(r"-> (\S+)", import_out)
    assert m, f"could not parse imported doc id from:\n{import_out}"
    node_id = m.group(1)
    node_a.log(f"Doc imported with id={node_id}")

    # ── 4b. Grant reader Read on writer's bucket (via HTTP, signed by
    # the daemon's admin authority on node_a). Crucially, the resulting
    # grant block must propagate via the sigchain so node_b can use it
    # for ACL evaluation — exercising that propagation is the whole
    # point of the test.
    node_a.log(
        f"Issuing read grant on writer's bucket {writer_bucket} for "
        f"audience=reader"
    )
    grant_cid = node_a.succeed(
        "memctl --url http://localhost:8401 "
        "--identity-dir /var/lib/memvault/agents/writer "
        f"grant create {writer_bucket} "
        "--agent reader --actions read --ttl 86400"
    ).strip().splitlines()[-1].strip()
    assert re.fullmatch(r"[0-9a-f]+", grant_cid), \
        f"unexpected grant create output: {grant_cid!r}"
    node_a.log(f"Grant published with cid={grant_cid}")

    # ── 5. Poll until node_b's reader agent can export the doc through
    # the sync'd grant.
    synced = False
    for attempt in range(180):
        node_b.execute("rm -rf /tmp/export && mkdir -p /tmp/export")
        rc, _ = node_b.execute(
            "memctl --url http://localhost:8401 "
            "--identity-dir /var/lib/memvault/agents/reader "
            "export --output /tmp/export "
            ">/tmp/export.log 2>&1"
        )
        if rc == 0:
            grep_rc, _ = node_b.execute(
                f"grep -rqF '{doc_text}' /tmp/export"
            )
            if grep_rc == 0:
                synced = True
                node_b.log(
                    f"node_b's reader agent observed the doc after ~{attempt}s"
                )
                break
        time.sleep(1)

    if not synced:
        node_a.log("--- node_a daemon log (tail) ---")
        node_a.log(node_a.succeed("tail -200 /tmp/daemon.log"))
        node_b.log("--- node_b daemon log (tail) ---")
        node_b.log(node_b.succeed("tail -200 /tmp/daemon.log"))
        node_b.log("--- node_b last export log ---")
        node_b.log(node_b.succeed("cat /tmp/export.log || true"))
        raise Exception(
            "node_b's reader agent never observed the doc within 180s"
        )

    # Daemons are still running — the entire test stayed on the HTTP path.
    for m, name in [(node_a, "node_a"), (node_b, "node_b")]:
        rc, _ = m.execute("pgrep -f 'memctl daemon'")
        assert rc == 0, f"{name} daemon unexpectedly exited"

    node_b.log("All memvault sync tests passed!")
  '';
}
