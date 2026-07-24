# TraceFence Hardening and Release Verification Report

Date: 2026-07-24
Release candidate: `0.2.0`
Required database schema: **17**

## Executive result

The hierarchical-scope design remains the enforcement core. The surrounding implementation has
been hardened so authority, replay, activation, leases, replacement identity, recovery truth,
overlapping commands, evidence integrity and telemetry delivery fail closed.

Current pre-release local gate:

```text
194 automated tests passed
branch-aware total coverage             77.57% (required >= 70%)
Python compileall                       PASS
frontend JavaScript syntax              PASS
Ruff                                    PASS
strict mypy                             PASS (51 source files)
Bandit                                  PASS
pip-audit                               PASS (56 release dependencies, 0 advisories)
wheel build/content                     PASS
installed wheel service                 PASS
/livez                                  200
/readyz                                 evaluated with database/runtime/scanner/auditor checks
frontend and packaged app.js            200
```

The release dependency graph is preserved in four hash-locked sets. A reproducible CycloneDX
SBOM, dependency-audit report and redacted high-confidence secret-scan report are checked in.

## Signed two-run candidate validation

After commit `ed20fa7b22097260d3f987647b0fccd07ad94ab7`, two consecutive signed
distributed scenarios were executed against the same fresh schema-13 database and one running
control plane. Both evidence bundles were verified against the live authenticated API.

For each run:

```text
run status                              COMPLETED
control convergence                     VERIFIED
replacement lineage                     VERIFIED
recovery action                         VERIFIED
recovery postconditions                 VERIFIED
recovery stability                      VERIFIED
recovery outcome                        VERIFIED
runtime proof                           VERIFIED
stale action attempts                   1
stale actions committed                 0
durable invariant violations            0
PostgreSQL restart count                0
Redis pool reset count                  1
checkout status                         healthy
committed side effects                  exactly 1
telemetry proof                         UNAVAILABLE
overall proof                           PARTIAL
```

The second execution used a different run ID and command ID while sharing the same application
and database, demonstrating that command idempotency, service state, evidence directories and
proof attribution do not leak or replay across runs. Telemetry remained unavailable solely because
this runner had no live SigNoz credentials or optional instrumentation packages.


Live Foundry/SigNoz verification is still an external gate. No telemetry result is fabricated.

## Proof-contract remediation

### Exact replacement manifest

Every correction freezes a digest-bound manifest containing:

- role and behavior;
- instruction JSON, digest and version;
- exact capabilities;
- expected recovery tool and arguments digest;
- maximum committed invocations;
- deterministic postconditions;
- causal `last_action_id` requirement;
- stability window;
- replacement child budget.

Replacement registration validates all fields exactly and is transactionally linked to the
correction command. Extra capabilities, unrelated roles, changed behavior, altered instructions
or excess children are rejected.

### Recovery truth

Recovery is no longer inferred from a committed tool name. Proof separately verifies:

```text
recovery_action_verdict
recovery_postcondition_verdict
recovery_stability_verdict
recovery_outcome_verdict
```

The scenario requires Redis and checkout to be currently healthy, PostgreSQL restart count to
remain zero, state to be causally bound to the authorized action and the state to remain stable
for the configured window. Adversarial tests confirm that degrading state after a successful
call cannot remain `VERIFIED`.

### Overlapping commands

Scope mismatches are mapped to every exact command whose target scope and version are represented
in the node's live state. Checkpoints, lease expiry and gateway blocks acknowledge all applicable
commands, preventing a later broader command from erasing convergence evidence for an earlier
nested command.

## Control-plane remediation

- `CANCEL_RUN` is operator/root-only and root-target-only.
- Agent issuers require active status, a live lease and valid inherited scopes.
- Accepted proposals freeze an authorized command payload and link to exactly one resulting
  command and reviewer fingerprint.
- Command and action replay authenticate first and require exact canonical payload digests.
- Activation-token consumption is serialized and one-shot.
- Expired leases and expired activation intents cannot be revived.
- Run/node/depth/fan-out/command/action/proposal quotas bound resource use.
- Operator rate limits are keyed by credential fingerprint; unauthenticated/node traffic falls
  back to the network principal rather than caller-supplied IDs.
- Blocking service calls run in a bounded worker pool rather than one global event-loop lane.
- Request-size enforcement counts streaming bytes.

## Action and database integrity

The Action Gateway validates identity, replay, quota, run/node status, lease, every inherited
scope, capability and arguments inside one write transaction. Denied stale attempts record exact
command/scope/snapshot/live-version attribution and acknowledge all matching commands.

Schema 17 validates required tables, columns, indexes, foreign keys and checks at startup. The
database independently rejects malformed or cross-run:

- root, parent, supersedes, scope-owner and correction links;
- command issuer/target/replacement shapes and version jumps;
- proposal review/resulting-command links;
- acknowledgements;
- action-command-scope-version matches;
- invariant/outbox relationships;
- action result shapes and service-state counters/statuses.

Legacy or partially migrated databases fail with `SCHEMA_MIGRATION_REQUIRED`.

## Durable safety detection

A supervised invariant auditor scans committed actions independently of proof requests. A stale
commit creates in one transaction:

- a durable `InvariantViolation`;
- a unique `TelemetryOutbox` event.

Network export occurs outside the SQLite write lock. Delivery is acknowledged only after a
successful OpenTelemetry force flush, giving at-least-once retry semantics.

## Telemetry and SigNoz remediation

- Telemetry status is explicit: `DISABLED`, `CONFIGURED`, `READY`, `DEGRADED` or `FAILED`.
- Configured exporter failure can make readiness fail closed.
- Control plane and worker flush telemetry on shutdown.
- Worker traces use causal span links from stdin-delivered trace context.
- Stale-action telemetry contains command, scope and version attribution.
- Dashboard assets include safety metrics, command/stale-action trace panels, denied-action logs
  and telemetry-outbox backlog.
- Alert provisioning validates typed assets, live metric existence and an existing notification
  channel and binds deployed resources to exact specification/channel digests.
- MCP reconciliation rejects missing, ambiguous or contradictory responses.

## Evidence remediation

Mutable tracked evidence was removed. Scenario output now uses timestamped immutable directories
and a signed `latest.json` pointer. Generation requires a clean committed worktree and a dedicated
signing key independent of operator/node-token secrets.

The manifest binds:

```text
application version
schema version
run and command IDs
Git commit and clean state
every artifact SHA-256 digest
HMAC-SHA256 signature and key ID
```

Verification rejects unsigned legacy JSON, path traversal, checksum/signature mismatch, schema
drift, unexpected commits, future dates and optionally stale bundles. It can compare stored
proof, graph, actions, services and violations against the authenticated live API.

## Frontend and packaging

- Operator credentials are never embedded in source.
- JSON content type and authentication headers are merged correctly.
- The graph renders spawn/replacement edges, scope states, affected branches, blocked actions and
  the authorized replacement manifest.
- Streaming refreshes are sequence-protected and user refresh can abort older requests.
- Browser responses include CSP, nosniff, frame denial, referrer and permissions policies.
- The setuptools wheel contains the CLI, API, worker, evidence module and frontend assets.
- The built wheel was installed into an isolated target and run with the existing validated
  runtime dependencies; liveness, readiness and static assets passed.

## Automated adversarial coverage

The 194-test suite covers, among other cases:

- delegated run-cancellation escalation;
- invalid-token and payload-confused replay;
- concurrent double activation;
- expired-lease resurrection;
- cross-run state and attribution;
- fake, overprivileged and behavior-mismatched replacements;
- false recovery after state regression;
- recovery causality and stability;
- replacement child-budget violations;
- nested/overlapping command acknowledgements;
- proof single-flight and cache invalidation;
- stale committed-action violation/outbox delivery;
- rate-limit identity bypass;
- request-size bypass;
- dirty/stale/tampered/wrong-key/wrong-commit evidence;
- schema/constraint corruption;
- packaged frontend and security headers.

## Remaining mandatory environmental gate

On the target WSL/Docker environment:

1. create and preserve a real environment-specific Foundry deployment lock/receipt (the
   checked-in `casting.yaml.lock` is only a source-content lock);
2. install MCP and OpenTelemetry instrumentation extras;
3. start SigNoz and confirm traces, metrics and logs arrive;
4. configure a real notification channel;
5. run `make provision-signoz` and `make verify-signoz`;
6. run a fresh signed scenario bundle;
7. run `make verify-all` and require:

```text
runtime_verdict   = VERIFIED
telemetry_verdict = VERIFIED
overall_verdict   = VERIFIED
```

## Honest residual limitations

- Atomic mutation is demonstrated for in-database simulated tools. Real external providers still
  require a durable execution outbox, provider idempotency and reconciliation.
- SQLite and the process-local limiter are bounded single-process MVP choices.
- The operator is one credential/fingerprint trust domain rather than IdP-backed per-user RBAC.
- TraceFence cannot revoke independent credentials held outside the gateway.
- Worker runtime/model binaries are not remotely attested.
- Live Foundry/SigNoz reconciliation is not verified in this runner because Docker was not
  running and no SigNoz credentials were available.
