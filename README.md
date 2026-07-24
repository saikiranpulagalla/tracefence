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
- Node and activation credentials are stored only as HMAC-SHA256 digests; exact
  idempotent retries can recover them from short-lived AES-GCM response envelopes.
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
- Database schema version **17** validates required tables, columns, indexes, foreign keys and
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
python -c "import secrets; print(secrets.token_urlsafe(48))"  # credential recovery key
python -c "import secrets; print(secrets.token_urlsafe(48))"  # evidence signing key
```

Use four independently generated values. Export the file in each terminal:

```bash
set -a
source .env
set +a
export PYTHONPATH=src
```

Outside `TRACEFENCE_ENV=test`, startup fails closed when secrets are missing, too short,
placeholder-like or reused across trust domains. Invalid boolean/integer environment values
also fail closed.

Credential-bearing spawn, replacement and activation requests should always supply a stable
`operation_key`. Before commit, a failure rolls back the node, token digest and envelope
together. After commit but before the response, or after a response is lost, an authenticated
exact retry returns the same encrypted response while the envelope is live. A different
payload under the key conflicts. After envelope expiry, a still-pending activation credential
or a live node credential is rotated atomically; an inactive or terminal subject is not
revived. An activation-expired replacement remains terminal; its designated live parent must
use a new operation key to register a new pending attempt under the same immutable correction
manifest. The database stores only credential digests and authenticated ciphertext. Recovery
uses `TRACEFENCE_CREDENTIAL_RECOVERY_KEY`, independently generated from operator, token-hash
and evidence keys, with the bounded `TRACEFENCE_CREDENTIAL_RECOVERY_TTL_SECONDS` lifetime.

Reset an incompatible local database explicitly:

```bash
make reset
```

## Start the control plane

```bash
make api
```

The worker keeps per-request HTTP deadlines below the lease TTL, stops work when heartbeat
authority is lost, requires checkpoint JSON to contain `allowed: true`, and completes
cooperative work explicitly. Worker exit statuses are: `0` completed, `2` action rejected,
`3` lease lost, `4` transport/internal failure, `5` checkpoint denied, `6` completion
rejected, and `7` activation rejected. Activation and node credentials are supplied through
stdin/HTTP only and never through process arguments.

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

The current source passes **192 tests** and **77.57% total branch-aware coverage** in the
available runner, plus Python compilation, JavaScript syntax, Ruff, strict mypy, Bandit,
pip-audit, wheel/sdist construction, hash-locked installation and clean-wheel service checks.
`make audit` executes the compile, JavaScript syntax, static, security, dependency and coverage
gates shown by `make help`; it does not perform live SigNoz verification.

## SigNoz deployment and verification

Install the checked-in Foundry configuration:

```bash
make signoz
```

The checked-in `casting.yaml.lock` binds the reviewed `casting.yaml` source bytes only. A real
Foundry installation must replace or augment that source lock with the deployment tool's own
environment-specific lock/receipt. The checked-in lock is not evidence that Foundry or SigNoz
was deployed.

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
- Persistence is intentionally SQLite-only. Any non-SQLite URL is rejected before a driver is
  loaded; PostgreSQL and high-availability operation remain production backlog items.
- The process-local rate limiter must be replaced by a shared limiter in multi-replica use.
- TraceFence controls registered nodes only while protected side effects remain behind the
  gateway. It cannot revoke independent external credentials held by an arbitrary process.
- The MVP uses a single operator credential with fingerprinted audit records, not an identity
  provider or per-user RBAC.
- Live SigNoz/Foundry verification remains an external environmental gate.

## SQLite migrations and durability

TraceFence ships an Alembic baseline at `001_schema_v17`. New installations can be initialized
explicitly with:

```bash
TRACEFENCE_DATABASE_URL=sqlite+pysqlite:///./data/tracefence.db \
  python -m alembic upgrade head
```

Application bootstrap records both schema version 17 and the Alembic head, validates columns,
primary keys, named and unnamed foreign keys, unique/check constraints, indexes and mandatory
proof-revision triggers. A failed first bootstrap that began from an empty database is returned
to an empty retryable state. Existing unknown or structurally incomplete databases fail closed
with `SCHEMA_MIGRATION_REQUIRED`; back them up before migration.

Every connection enables foreign keys, WAL mode, a five-second busy timeout and
`synchronous=FULL`. WAL improves reader/writer concurrency but the `-wal` file can grow while
long-lived readers prevent checkpoints. Monitor free disk and WAL size, reserve at least twice
the combined database/WAL working set, and investigate readers before issuing a controlled
`PRAGMA wal_checkpoint(TRUNCATE)`.

For backups, use SQLite's online backup API or the `sqlite3 .backup` command against a quiesced
or coordinated writer. Do not copy only the main database file while WAL writes are active.
Restore into a separate path, run `PRAGMA integrity_check`, apply `alembic upgrade head`, start
TraceFence, and validate `/readyz` before replacing the original. Keep at least one tested,
offline backup and rehearse restoration; TraceFence does not provide automated disaster
recovery.

## Provenance

See [`DISCLOSURE.md`](DISCLOSURE.md) for prior conceptual work and AI-assistance disclosure.
