# TraceFence Architecture

## 1. System boundary

TraceFence separates enforcement from explanation. Workers, prompts, models and peer-agent
recommendations are untrusted inputs. The database-backed control plane and Action Gateway are
the authoritative runtime boundary. SigNoz is an independent evidence plane; it never grants
action authority.

| Plane | Responsibility |
|---|---|
| Registry | Runs, nodes, ancestry, scopes, leases, proposals, commands and manifests |
| Action Gateway | Live identity, lease, capability, scope and idempotency validation before commit |
| Invariant auditor | Durable discovery and export of safety violations independent of proof requests |
| Proof engine | Deterministic reconstruction of convergence, replacement and recovery |
| Evidence bundle | Hash- and HMAC-bound release evidence tied to a clean Git commit |
| SigNoz | Queryable traces, metrics, logs, dashboards, alerts and MCP reconciliation |

## 2. Registration, activation and graph budgets

A live parent requests child registration. In one transaction TraceFence:

1. authenticates the parent;
2. validates run state, declared state, lease and inherited scopes;
3. enforces run/node/depth/fan-out budgets;
4. verifies capability-subset delegation;
5. creates the child-owned scope;
6. records parent linkage, generation and the ordered scope snapshot;
7. creates a one-time activation intent and token digest.

Activation executes under an immediate write transaction. A concurrent second consumer cannot
obtain another valid permanent credential. Unconsumed intents expire through the lease scanner
and no longer block run completion.

## 3. Hierarchical versioned scopes

Each node stores an immutable ordered snapshot of the run scope, inherited ancestor scopes and
its own scope:

```json
[
  {"scope_id":"run", "version":1},
  {"scope_id":"root", "version":1},
  {"scope_id":"database", "version":1},
  {"scope_id":"database-child", "version":1}
]
```

At checkpoints and action admission every snapshot entry must satisfy:

```text
live scope exists
live status == ACTIVE
live version == snapshot version
```

Changing the database scope from `ACTIVE/v1` to `SUPERSEDED/v2` invalidates every descendant
that inherited `v1`. Runtime enforcement validates only the scopes already carried by the node;
it does not enumerate the dynamic subtree. Enumeration is reserved for proof.

## 4. Authority and proposals

- The human operator can control the selected single-tenant deployment.
- The root coordinator can control its run and descendants.
- A delegated parent requires `control:descendants` and may control strict descendants only.
- `CANCEL_RUN` is restricted to the operator or root and must target the root.
- Peers can submit correction/cancellation proposals but cannot directly control siblings.

An accepted proposal freezes the exact authorized command payload and its digest. A resulting
command must match that payload and the proposal records the resulting command ID and reviewer
fingerprint. Acceptance is therefore not a reusable permission grant.

## 5. Control commands and overlapping scopes

Commands are issued inside an immediate transaction:

1. authenticate the principal;
2. validate command-specific authority and quotas;
3. verify idempotency key and canonical payload digest;
4. load the target scope and current version;
5. update it exactly from `vN` to `vN+1` and set `CANCELLED` or `SUPERSEDED`;
6. persist the command, reason, issuer fingerprint and replacement manifest if applicable.

A node may inherit several invalid scopes when nested commands overlap. TraceFence attributes a
checkpoint, lease expiry or blocked action to every command whose exact target scope and
`to_version` appear in the live mismatches. Earlier commands therefore do not lose convergence
evidence when a broader command arrives later.

## 6. Exact replacement manifest

`CORRECT_SUBTREE` freezes a hash-bound manifest rather than only replacement text. The manifest
contains:

- replacement role and cooperative/non-compliant behavior profile;
- exact instruction JSON, instruction digest and instruction version;
- exact capability set;
- expected tool and canonical arguments digest;
- maximum committed invocations;
- deterministic service-state postconditions;
- causal-action requirement and stability window;
- direct-child budget.

Replacement creation validates the manifest, superseded node, correction command, parent,
instruction, behavior and exact capabilities in the same transaction that creates the node,
owned scope and activation intent. One command can create at most one replacement.

## 7. Leases and cooperative checkpoints

Active workers heartbeat before the lease deadline. A heartbeat cannot resurrect an already
expired lease. The supervised scanner marks overdue active nodes and expired activation intents
as `LEASE_EXPIRED` and records acknowledgements for all applicable invalidated scopes.

Cooperative workers call checkpoints around expensive or side-effecting stages. A checkpoint
can acknowledge multiple overlapping commands and changes the worker's declared state to the
effective cancelled/superseded state. Non-cooperative workers are still constrained by the
Action Gateway.

## 8. Atomic Action Gateway

Every protected tool request passes through one write transaction:

1. load and authenticate the node;
2. validate the tool schema after authentication;
3. check exact idempotency replay binding;
4. enforce action quotas;
5. validate run status, node state and lease;
6. load and compare every live scope;
7. validate exact capability and tool policy;
8. persist the attempt and all exact command/scope/version matches;
9. either commit a denial and acknowledgements, or execute the simulated tool mutation;
10. attach result digest and commit timestamp before committing.

For the included database-backed simulated tools, action admission and authoritative state
mutation share the same SQLite transaction. The linearization is therefore either:

```text
action commits before the control command
```

or:

```text
control command commits first and the action is denied
```

There is no committed middle state in which a stale action is admitted after the invalidation.

## 9. Tool registry and recovery contracts

One deterministic registry defines for each tool:

- capability;
- side-effect classification and risk class;
- accepted arguments;
- executor;
- recovery contract builder;
- current-state postconditions.

The current scenario's `reset_redis_pool` contract requires:

- one exact committed invocation with the expected argument digest;
- Redis status `healthy`;
- checkout status `healthy`;
- PostgreSQL restart count `0`;
- causal `last_action_id` binding to the authorized recovery action;
- an unchanged state for the configured stability window.

A committed tool call alone is not treated as recovery.

## 10. Deterministic proof

The proof engine reconstructs the graph as it existed at command time and reports separate
verdicts:

```text
control_convergence_verdict
replacement_lineage_verdict
recovery_action_verdict
recovery_postcondition_verdict
recovery_stability_verdict
recovery_outcome_verdict
runtime_verdict
telemetry_verdict
overall_verdict
```

Affected nodes are classified through durable acknowledgements, gateway blocks, lease expiry or
completion before the command. Replacement proof compares the node against every manifest
field. Recovery proof checks the exact action, result and request digests, current state,
causality and stability.

Proof requests are cached briefly and use per-command single-flight synchronization so duplicate
HTTP requests share one build. Different commands may be proved concurrently.

## 11. Durable invariant ledger and telemetry outbox

Safety detection is not dependent on someone requesting proof. A supervised auditor scans for
committed actions causally matched to invalidated commands. A newly discovered violation creates
in one transaction:

- an `InvariantViolation` record;
- a unique `TelemetryOutbox` event.

Delivery happens outside the database write lock. The event is marked delivered only after the
OpenTelemetry providers successfully force-flush. Failed export remains pending for at-least-once
retry. The outbox does not replace the future execution outbox required for real external APIs.

## 12. OpenTelemetry and SigNoz

The control plane emits manual spans, bounded-cardinality metrics and structured logs. Worker
activation receives causal trace context through stdin and the independent worker trace uses a
span link rather than pretending to be a single continuous process span.

Stale-action telemetry includes:

```text
run ID
node ID and role
action ID and tool
command ID
scope ID
snapshot version
live version/status
decision and denial reason
```

Before MCP proof queries, TraceFence force-flushes owned traces, metrics and logs. Exporter state
is exposed as `DISABLED`, `CONFIGURED`, `READY`, `DEGRADED` or `FAILED`; configured-but-failed
telemetry can make readiness fail closed.

The MCP adapter requires command evidence, stale-action evidence, correlated logs and safety
metrics. Missing or ambiguous evidence yields `PARTIAL`/`UNAVAILABLE`; contradiction yields
`INCONSISTENT`.

## 13. Signed evidence

A scenario can generate release evidence only from a clean committed worktree with a dedicated
signing key. The output contains timestamped immutable files, SHA-256 digests, schema version,
application version, run/command IDs, Git commit and HMAC-SHA256 signatures on the manifest and
latest pointer.

The verifier can additionally:

- require an expected commit;
- reject stale or future-dated evidence;
- compare the stored proof, graph, actions, services and violations against the authenticated
  live API;
- require telemetry verification.

## 14. Runtime and deployment model

FastAPI request handling offloads blocking service calls to a bounded worker pool. SQLite still
serializes safety-critical immediate write transactions, while independent reads and proof
coordination are not forced through one global event loop.

The process-local rate limiter keys valid operator traffic by a credential fingerprint and uses
network principal fallback for unauthenticated/node traffic. It is intentionally bounded and
suitable only for the single-process MVP.

## 15. Production evolution

External providers cannot participate in the SQLite transaction. A production adapter requires:

```text
validate live scopes
→ reserve provider idempotency and durable execution outbox
→ commit intent
→ call provider with short-lived scoped permit
→ reconcile provider result
→ verify postcondition
```

TraceFence now ships formal Alembic migrations for its supported SQLite schema. Production-scale
evolution would require a separately implemented and tested PostgreSQL/HA persistence layer, an
identity provider and per-run authorization, a shared rate limiter, and cryptographic binding of
worker runtime/image versions when remote attestation is available.
