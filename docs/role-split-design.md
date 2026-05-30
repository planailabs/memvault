# Design: split the shared `Role` into `AgentRole` and `NodeRole`

Status: **proposal** (design-only; no code changes yet)
Author: design pass, 2026-05-30

## Problem

Today a single enum is shared across two unrelated trust domains:

```rust
// memvault-auth/src/role.rs
pub enum Role { Admin, AgentHost, Auditor, Service, Node }
```

It is used by **all** of:

- `NodeAttestation.role` — cluster membership / P2P replication trust.
- `AgentAttestation.role` — agent (API) capability.
- `JoinToken.role` — carried into whichever attestation a redemption mints.
- `GrantAudience::Role(Role)` — ACL audience matched against the agent's role.

Because the type is shared, the type system permits nonsensical states that
only *runtime* checks currently forbid:

- `AgentAttestation { role: Node }` — an agent claiming to be a peer node.
- `NodeAttestation { role: Service }` — a replicating node tagged with an
  app-level account role.
- An agent enrolled as `Admin`, or a node-join token carrying `Auditor`.

This session added runtime gates to compensate (node-join refuses non-`Node`
tokens; `peer_is_trusted_node`/`scan_trusted_nodes` require `Node`;
`attest_node` rejects non-`Node`; admin/node tokens require genesis). **Those
gates are patching a type-system gap.** Splitting the enum makes the
distinction structural and lets several of those runtime gates become
compile-time guarantees.

The two domains also have **different ACL semantics**: a cluster admin is a
*node/cluster* authority (signing key based, not ACL-gated), whereas agent
roles are API capabilities subject to grants/ACL. They must not converge.

## Proposed types

```rust
/// Agent (API) capability. Lives on AgentAttestation; the audience of
/// GrantAudience::Role; matched by the ACL evaluator.
pub enum AgentRole {
    /// Hosts agents, reads/writes data on their behalf (the default).
    AgentHost,
    /// Read-only / observability. Bypasses retraction filtering on reads.
    Auditor,
    /// Service / automation account.
    Service,
    /// API admin — full API access. Distinct from the cluster/node admin
    /// below; this is an *agent* with admin-level API capability and it
    /// participates in the API/ACL surface. (NEW.)
    Admin,
}

/// Cluster membership / node trust. Lives on NodeAttestation. Not ACL-gated.
pub enum NodeRole {
    /// A cluster peer node that replicates data over P2P.
    Node,
    /// Cluster admin node — pairs with an admin signing key and is the trust
    /// authority. Not affected by ACLs (it *is* the granting authority).
    Admin,
}
```

Two distinct `Admin`s, in two enums, that **cannot** be confused at the type
level:

| | `NodeRole::Admin` | `AgentRole::Admin` |
|---|---|---|
| Domain | cluster / P2P trust | API access |
| Backed by | an admin **signing key** (AdminGenesis / AdminKeyAdmission) | an agent keypair + AgentAttestation |
| ACL | exempt — it is the authority | participates (admin-level API caller) |
| Appears on | `NodeAttestation` | `AgentAttestation` |

### Join tokens

A `JoinToken` is unambiguously either a node-join or an agent-enrol token, so
the role becomes a tagged union instead of a bare enum:

```rust
pub enum TokenRole {
    Node(NodeRole),    // redeemed via /join/1.0 → NodeAttestation
    Agent(AgentRole),  // redeemed via `agent enroll` → AgentAttestation
}

pub struct JoinToken {
    // ...
    pub role: TokenRole,
    // ...
}
```

This collapses the current cross-flow runtime gates:

- node-join can `match token.role { TokenRole::Node(r) => mint NodeAttestation(r), _ => refuse }`
- agent-enrol can `match token.role { TokenRole::Agent(r) => mint AgentAttestation(r), _ => refuse }`

No more "is this role allowed for this flow" string/enum checks — the wrong
variant simply can't be redeemed.

## Per-site changes

| Site | Today | After |
|---|---|---|
| `memvault-auth/src/role.rs` | `Role` | `AgentRole`, `NodeRole`, `TokenRole` |
| `NodeAttestation.role` (`node_attestation.rs`) | `Role` | `NodeRole` |
| `AgentAttestation.role` (`agent_attestation.rs`) | `Role` | `AgentRole` |
| `JoinToken.role` (`token.rs`) | `Role` | `TokenRole` |
| `GrantAudience::Role(_)` (`grant.rs`) | `Role` | `AgentRole` |
| ACL match (`memvault-api/src/acl.rs:110`) | `*r == attestation.role` | `*r == agent_att.role` (`AgentRole`) |
| JWT chain (`jwt.rs`) | agent role is `Role` | `AgentRole` |
| `attest_node` (`local.rs`) | `role: Role`, rejects non-`Node` | `role: NodeRole` (no runtime reject needed) |
| genesis self-att (`bootstrap.rs`) | `Role::Node` | `NodeRole::Node` |
| `build_join_response` (`swarm`) | copies `token.role`, refuses non-`Node` | `match TokenRole::Node(r)` |
| `peer_is_trusted_node` / `scan_trusted_nodes` | `att.role != Role::Node` filter | `NodeRole` is the only type; filter on `NodeRole::Node` vs `Admin` if needed |
| `tokens::issue_token` admin/node guard | `matches!(role, Admin\|Node)` needs genesis | `matches!(role, TokenRole::Node(_))` needs genesis (node tokens); agent-Admin is an API role, genesis rule TBD |
| `memctl` `RoleArg` | one enum → `Role` | split CLI: node-role vs agent-role args per subcommand (`cluster-join`/`token issue --node-role` vs `agent`/`token issue --agent-role`) |
| web `parse_role` (`api/admin.rs`) | → `Role` | context-specific (`AgentRole` for agent tokens, `NodeRole` for node tokens) |
| web `caller_sees_retracted` (`api/auth.rs`) | `Auditor \| Admin` (shared) | `AgentRole::Auditor \| AgentRole::Admin` — semantics unchanged, now type-correct |
| audit `sigchain_record` role tags (`memvault-query`) | `format!("{:?}", role)` | per-attestation role type; display only |

## Impact on this session's features

- **Node-role gate** (require `NodeAttestation` role `Node`): becomes
  structural — `NodeAttestation.role: NodeRole`. The `peer_is_trusted_node` /
  `scan_trusted_nodes` checks simplify (only node roles exist there); decide
  whether `NodeRole::Admin` also confers block-serving trust (it should — an
  admin node replicates).
- **Auditor retraction bypass**: `caller_sees_retracted` becomes
  `AgentRole::Auditor | AgentRole::Admin` — same behaviour you chose, now
  type-correct (the `Admin` there is the new API admin, not the cluster admin).
- **Admin/node tokens require genesis**: the node-token half stays (node
  membership needs a genesis'd cluster). The agent-`Admin` token is an API
  role; whether it also requires genesis is a separate policy call.
- **Redeemed audit envelope / token GC**: unaffected (role is only carried
  through, not branched on).

## Migration / wire-format break

`AgentRole` / `NodeRole` / `TokenRole` serialize differently from the current
`Role`, so **every already-signed `NodeAttestation`, `AgentAttestation`, and
`JoinToken` stops verifying after upgrade** (the signed payload bytes change).

Given `Role::Node` itself was only just introduced, the cleanest path is a
**hard cutover** (no dual-read): wipe/re-genesis dev clusters, reissue tokens.
If any cluster must survive the upgrade, the alternative is a versioned
attestation/token (`v1` legacy `Role`, `v2` split) with dual-read at verify
time — materially more work and not recommended unless required.

Recommendation: **hard cutover**, documented in the changelog, since this is
pre-stable.

## Blast radius (files)

- `memvault-auth`: `role.rs` (new types), `node_attestation.rs`,
  `agent_attestation.rs`, `token.rs`, `grant.rs`, `jwt.rs`, `sigchain_shape.rs`,
  `lib.rs` (exports), plus tests.
- `memvault-api`: `acl.rs`, `agent_identity.rs`, `bootstrap.rs`, `local.rs`
  (`attest_node`, role plumbing), `tokens.rs` (issue guard), `sigchain.rs`.
- `memvault-swarm`: `build_join_response`, `peer_is_trusted_node`.
- `memvault-query`: `audit/query.rs` (role display in sigchain records).
- `memctl`: `RoleArg` split + per-subcommand args.
- `memvault-web`: `api/admin.rs` (`parse_role`, token issue), `api/auth.rs`
  (`caller_role`/`caller_sees_retracted`), UI role pickers/badges.
- Tests across `memvault-smoke`, `memvault-api`, `memvault-web`.

## Open decisions

1. Does `NodeRole::Admin` confer block-serving / node trust like `Node`?
   (Assumed **yes** — an admin node still replicates.)
2. Does an `AgentRole::Admin` token require a genesis'd cluster to issue, like
   node tokens do? (Assumed **no** by default — it's an API role, not cluster
   membership — but easy to require.)
3. Is `AgentRole::Admin` ACL-**exempt** (sees/does everything) or merely a
   high-privilege audience that still needs grants? The phrase "for the API
   only" suggests it is an API-surface admin; exact ACL exemption to be pinned
   down before implementation.
4. CLI ergonomics: one `token issue` with a `--node-role`/`--agent-role`
   split, or separate `token issue-node` / `token issue-agent` subcommands.

## Not in scope here

No code changes. This document is the agreed shape to implement against once
the open decisions above are resolved.
