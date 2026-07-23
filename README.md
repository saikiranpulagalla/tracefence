# TraceFence

**Runtime-enforced cancellation and correction for dynamic AI-agent graphs.**

TraceFence assumes that AI workers can be wrong, delayed or non-cooperative. It therefore
places deterministic authority and live control-state validation at the side-effect boundary.
A worker may ignore a cancellation message, but a registered worker cannot commit a
TraceFence-mediated side effect after any inherited control scope becomes stale.

## Core guarantee

> A registered descendant can continue computing after cancellation, but it cannot commit a
> gateway-mediated side effect with a cancelled, superseded, expired or mismatched scope.

The checked-in scenario constructs a database-investigation subtree, supersedes that branch
after stronger Redis evidence appears, and then releases an independently running
non-compliant descendant that attempts `restart_postgres`.

Expected local result:

```text
restart_postgres                 DENY / SCOPE_SUPERSEDED
reset_redis_pool                  ALLOW / committed once
postgres restart count           0
redis and checkout state         healthy
control convergence              VERIFIED
replacement manifest             VERIFIED
recovery action                  VERIFIED
recovery postcondition           VERIFIED
recovery stability               VERIFIED
runtime proof                    VERIFIED
telemetry proof                  UNAVAILABLE until live SigNoz is configured
overall proof                    PARTIAL until telemetry verifies
```

## Architecture

```text
coordinator and worker processes
        │ register · activate · heartbeat · checkpoint · request action
        ▼
TraceFence control plane
  ├── authenticated run/node registry
  ├── hierarchical versioned scopes
  ├── command-specific authority and proposal binding
  ├── one-shot activation, leases and graph budgets
  ├── payload-bound idempotency
  ├── exact replacement manifests and recovery contracts
  ├── atomic action gateway
  ├── durable invariant ledger and telemetry outbox
  └── deterministic proof engine
        │
        ├── SQLite authoritative state (bounded MVP)
        ├── signed immutable evidence bundles
        └── OTLP traces · metrics · logs
                         │
                         ▼
                       SigNoz
          dashboard · alerts · MCP reconciliation
```

Detailed design: [`ARCHITECTURE.md`](ARCHITECTURE.md). Security model:
[`SECURITY.md`](SECURITY.md). Audit remediation: [`HARDENING_REPORT.md`](HARDENING_REPORT.md).

## Implemented safety properties

- All protected operator endpoints require `X-Operator-Key`.
- Node and activation credentials are returned once and stored only as HMAC-SHA256 digests.
- Activation-token consumption is serialized and succeeds at most once under concurrency.
- Expired leases and expired unactivated spawn intents cannot be revived.
- `CANCEL_RUN` is restricted to the human operator or root coordinator and must target the root.
- Delegated agents can control descendants only; sibling control is rejected.
- Command and action idempotency are checked after authentication and bound to canonical
  request digests, run and issuer.
- Corrections freeze an exact replacement manifest: role, behavior, instruction, exact
  capabilities, expected tool, arguments digest, postconditions, stability window and child
  budget.
- Replacement registration is transactionally linked to its correction command.
- Recovery verification checks the committed action, current authoritative postconditions,
  causal `last_action_id` binding and the required stability window.
- Overlapping commands are acknowledged individually instead of collapsing to a single
  latest command.
- Service state and all control-plane resources are isolated by run.
- The action gateway records exact command/scope/version attribution for stale denials.
- A supervised invariant auditor persists stale-commit violations and an at-least-once
  telemetry outbox independently of proof requests.
- Request-body size and process-local rate limits are enforced before route execution.
- Database schema version **13** validates required tables, columns, indexes, foreign keys and
  check constraints and fails closed on incompatible databases.
- Missing, ambiguous or contradictory SigNoz evidence cannot become `VERIFIED`.

## Requirements

- Python 3.12+
- Node.js only for the JavaScript syntax check
- Docker and SigNoz Foundry for the complete observability path
- A SigNoz service-account API key and an existing notification channel

## Install

Full development, MCP and OpenTelemetry environment:

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,mcp,otel-instrumentation]'
```

Pinned file-based alternatives:

```bash
make install-core    # runtime only
make install-dev     # runtime + test/static tools
make install-full    # runtime + test/static tools + MCP/OTel instrumentation
```

## Configure safely

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"  # operator key
python -c "import secrets; print(secrets.token_urlsafe(48))"  # token hash secret
python -c "import secrets; print(secrets.token_urlsafe(48))"  # evidence signing key
```

Use three independently generated values. Export the file in each terminal:

```bash
set -a
source .env
set +a
export PYTHONPATH=src
```

Outside `TRACEFENCE_ENV=test`, startup fails closed when secrets are missing, too short,
placeholder-like or reused across trust domains. Invalid boolean/integer environment values
also fail closed.

Reset an incompatible local database explicitly:

```bash
make reset
```

## Start the control plane

```bash
make api
```

The server binds to loopback by default:

```text
UI         http://127.0.0.1:9000
OpenAPI    http://127.0.0.1:9000/docs
Liveness   http://127.0.0.1:9000/livez
Readiness  http://127.0.0.1:9000/readyz
```

Readiness verifies database writability, the bounded control-plane executor, lease-scanner and
invariant-auditor freshness, telemetry state and outbox backlog. The browser stores no embedded
operator credential; the operator enters it locally for protected operations.

## Run the distributed scenario

Evidence generation is intentionally release-grade and therefore requires:

- a Git repository with a committed `HEAD`;
- a clean worktree;
- a dedicated `TRACEFENCE_EVIDENCE_SIGNING_KEY`.

Then run:

```bash
make scenario
make verify
```

The scenario uses explicit synchronization rather than guessed sleeps. The child activation
secret and causal trace context are delivered over stdin, never process arguments.

Generated evidence is placed under an immutable timestamped directory with a signed
`evidence/latest.json` pointer. See [`evidence/README.md`](evidence/README.md).

## Local quality gate

```bash
make audit
```

The current source passes **99 tests** and **73.81% branch coverage** in the available runner,
plus Python compilation, JavaScript syntax, whitespace, wheel-content and installed-service
checks. CI additionally runs Ruff, strict mypy, Bandit, pip-audit, wheel/sdist construction and
clean-wheel installation.

## SigNoz deployment and verification

Install the checked-in Foundry configuration:

```bash
make signoz
```

This must create a real `casting.yaml.lock` on the target machine. Never fabricate or copy a
lock from another environment.

Configure a real service-account key and existing notification channel:

```bash
export SIGNOZ_URL=http://localhost:8080
export SIGNOZ_MCP_URL=http://localhost:8000/mcp
export SIGNOZ_API_KEY='...'
export TRACEFENCE_NOTIFICATION_CHANNEL='exact-existing-channel-name'
```

Run a telemetry-enabled scenario so metric series exist, then:

```bash
make provision-signoz
make verify-signoz
make verify-all
```

Provisioning validates the checked-in dashboard and v2alpha1 alerts, discovers required MCP
tools and metrics, validates the notification channel, and refuses same-name resources whose
specification digest differs unless an explicit update is requested.

The final submission gate is:

```text
runtime_verdict   = VERIFIED
telemetry_verdict = VERIFIED
overall_verdict   = VERIFIED
```

## Proof verdicts

Runtime proof reports:

- `control_convergence_verdict`
- `replacement_lineage_verdict`
- `recovery_action_verdict`
- `recovery_postcondition_verdict`
- `recovery_stability_verdict`
- `recovery_outcome_verdict`
- `runtime_verdict`

Telemetry reconciliation then validates command spans, stale-action spans, correlated logs and
metrics. The overall verdict is:

- `VERIFIED`: runtime and telemetry both verify;
- `PARTIAL`: runtime verifies but telemetry is unavailable or incomplete;
- `INCONSISTENT`: authoritative state and telemetry disagree;
- `INCOMPLETE`: control convergence, replacement or recovery is unfinished.

## Important limitations

- The atomic commit guarantee covers the included simulated tools whose authoritative mutation
  is in the same database transaction. Real infrastructure/payment/cloud tools require a
  provider idempotency key, durable execution outbox and reconciliation workflow.
- The invariant telemetry outbox is implemented for durable safety-event delivery; it is not a
  full external-tool execution outbox.
- SQLite is suitable for this bounded single-process hackathon MVP. Production should use
  PostgreSQL, formal migrations and explicit row/advisory locking.
- The process-local rate limiter must be replaced by a shared limiter in multi-replica use.
- TraceFence controls registered nodes only while protected side effects remain behind the
  gateway. It cannot revoke independent external credentials held by an arbitrary process.
- The MVP uses a single operator credential with fingerprinted audit records, not an identity
  provider or per-user RBAC.
- Live SigNoz/Foundry verification remains an external environmental gate.

## Provenance

See [`DISCLOSURE.md`](DISCLOSURE.md) for prior conceptual work and AI-assistance disclosure.
