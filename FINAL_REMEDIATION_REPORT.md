# TraceFence Final Remediation Report

Date: 2026-07-24  
Branch: `fix/proof-and-runtime-integrity`  
Release candidate source version: `0.2.0`  
Schema: `17`

## Verdict

```text
Local release gate: PASS
Telemetry gate: BLOCKED
Production-ready: NO
```

The local verdict covers the committed static, security, test, coverage, package, clean-wheel,
and same-database scenario gates. Live SigNoz reconciliation is blocked because Docker was not
running and no SigNoz/MCP credentials or deployment were available. No live telemetry result is
claimed.

## Phase summary and original reproductions

| Area | Original adversarial reproduction | Regression coverage | Result |
|---|---|---|---|
| Proof consistency | Mutate proof-relevant state while MCP reconciliation is delayed | `test_delayed_reconciliation_discards_stale_verified_and_does_not_cache_it`, bounded mutation and lease-cache tests | Database-triggered run revision, fresh retry, bounded fail-closed publication |
| Verdict ordering | Combine runtime `INCOMPLETE` with telemetry `INCONSISTENT` | `test_verdict_severity_lattice_is_canonical`, stale committed-action tests | One canonical severity lattice; contradiction dominates |
| Proof cancellation | Cancel a follower awaiting shared proof work | `test_cancelling_follower_does_not_cancel_owner_or_shared_cache` | Shielded follower; owner/cache remain intact |
| MCP transport | Exercise the unsupported `headers=` Streamable HTTP call | `test_mcp_transport.py` | Bounded `httpx.AsyncClient` passed as `http_client=` |
| Telemetry correlation | Supply blocked rows from another command/process/build or malformed/ambiguous containers | `test_mcp_reconciliation.py` | Strict typed adapters, exact identity/window/action-set equality, watermark requirement |
| Recovery gateway | Race two idempotency keys against a one-invocation recovery contract | `test_recovery_gateway.py` | Tool, digest, node, role, behavior, capabilities, environment and budget enforced before execution |
| Action atomicity | First mutating action on unseeded service state | `test_action_atomicity.py` | No incomplete ALLOW flush; action/result/state commit atomically |
| Heartbeats | Heartbeat after cancellation, supersession or version mismatch | `test_heartbeat_fencing.py` | Live inherited scopes checked before renewal; expired leases remain terminal |
| Run lifecycle | Race completion and cancellation; cancel completed run; expire root | `test_run_transitions.py` | Conditional transition table, immutable terminal timestamps, root expiry abort policy |
| Replacement lifecycle | Issue correction with a dead intended parent | `test_replacement_lifecycle.py` | Live authorized parent or deterministic supervisor/root fallback with durable states |
| Credential response loss | Drop spawn, replacement and activation responses after commit | `test_credential_recovery.py` | AES-GCM TTL envelopes, exact operation replay, safe rotation, no plaintext persistence |
| Runtime bulkheads | Block eight external proof calls while heartbeats execute | `test_control_plane_runtime.py` | Separate bounded safety/external runtimes, deadlines and stable overload errors |
| Rate limiting | Fifty nodes heartbeat behind one IP; rotate invalid IDs | `test_rate_limits_v2.py` | Authenticated node/run buckets, unauthenticated IP bucket, bounded memory |
| Worker lifecycle | Denied checkpoint, completion rejection, heartbeat loss and blocked stdin | `test_worker_lifecycle.py` | Lease-margin deadlines, JSON `allowed`, completion call, deterministic exits and cancellable release |
| Outbox/invariants | Race two delivery workers for the same pending rows | `test_invariant_outbox.py` | Read discovery plus short writes, claim leases, retry metadata, latched/dead-man gauges |
| Readiness | Concurrent public probes during unhealthy scanners/exporter | `test_health_hardening.py` | Shallow liveness, cached/singleflight readiness, protected detail, sanitized errors |
| Evidence | Verify dirty, stale, wrong-commit, tampered or live-API-mismatched evidence | release-hardening and evidence tests | Atomic private signed artifacts bound to commit/version/schema/freshness/live API |
| Persistence/reset | Configure PostgreSQL URL or unsafe/symlink reset target | schema/reset tests | SQLite-only rejection, Alembic schema 17, structural validation and exact-path reset confirmation |
| API/frontend | Non-ASCII operator header, auth loss, run switch, stale response and double submit | `test_api_frontend_safety.py` and packaged HTTP tests | 401 handling, pagination, immediate protected-state clearing, submission guard and `aria-live` |
| Alerts | Validate only the original three alert definitions | `test_checked_in_signoz_assets_are_strictly_valid` | Added exporter failure, proof inconsistency and recovery-postcondition alerts |
| Release verifier | Runtime `VERIFIED` plus telemetry `UNAVAILABLE` produced canonical overall `UNAVAILABLE` | `test_release_verifier_accepts_canonical_unavailable_telemetry_lattice` | Release verifier now follows the same severity lattice |

## Remediation commits

```text
023ab7d fix: make proof publication revision-consistent
b4bfbac fix: enforce verdict severity ordering
59fe2c2 fix: harden proof single-flight cancellation
dbf006b fix: use supported MCP Streamable HTTP client
d9d8c4f fix: strictly correlate command telemetry
80efa7b fix: make proof trigger DDL statically safe
56e0784 fix: enforce recovery contract before action execution
423c992 fix: make action and service-state mutation atomic
181e955 fix: fence heartbeats on live scope authority
7c4f593 fix: enforce immutable terminal run transitions
fdd476e fix: guarantee achievable replacement lifecycle
34040af fix: make credential exchanges safely recoverable
1d3940a fix: isolate safety execution from external proof I/O
218fa86 fix: make node heartbeat limits identity-aware
a9f3742 fix: complete worker lease and completion lifecycle
0c2b0cf fix: make invariant and outbox processing bounded
840e7d0 fix: harden health and readiness probes
13c337a fix: bind evidence verification to live release state
ed8d887 fix: enforce SQLite-only persistence and migrations
90fc811 fix: constrain destructive reset tooling
cea07cd fix: clear stale protected frontend state
6a1fdd0 fix: satisfy static and dependency security gates
41a66a3 chore: make release verification reproducible
a6bbf1b fix: align release verifier with verdict lattice
476d97b fix: alert on exporter and proof integrity failures
```

## Exact local gate results

```text
python -m compileall -q src scripts tests
PASS

node --check src/tracefence/frontend/app.js
PASS

ruff check src scripts tests
All checks passed!

mypy src/tracefence
Success: no issues found in 51 source files

bandit -q -r src scripts -x tests
PASS (no findings)

pip-audit --progress-spinner off
No known vulnerabilities found

PYTHONPATH=src TRACEFENCE_ENV=test pytest -q
194 passed, 3 upstream deprecation warnings

PYTHONPATH=src TRACEFENCE_ENV=test pytest -q --cov=tracefence --cov-branch \
  --cov-report=term-missing --cov-fail-under=70
194 passed
Total coverage: 77.57%

python -m build
Successfully built tracefence-0.2.0.tar.gz and
tracefence-0.2.0-py3-none-any.whl
```

The clean-wheel environment installed `requirements-lock/runtime.txt` with
`--require-hashes`, installed the wheel with `--no-deps`, and passed CLI, imports, frontend
resources, database initialization, application startup, `/livez`, protected health
authentication, cache-control and security-header checks.

The explicit high-risk matrix ran 52 proof-race, MCP-correlation, proof-flood/heartbeat,
concurrent recovery budget, credential response-loss and process-worker tests: all passed.

## Dependency and supply-chain disposition

- Runtime, development, full MCP/SigNoz, and isolated build sets are hash-locked under
  `requirements-lock/`.
- `mcp==1.28.1` and `pytest==9.0.3` satisfy the patched minimums.
- FastAPI is `0.139.2` with direct Starlette `1.3.1`; the previous applicable Starlette
  advisories are no longer present.
- `reports/dependency-audit.json`: 56 release dependencies, zero known vulnerabilities.
- `reports/sbom.cdx.json`: reproducible validated CycloneDX JSON.
- `reports/secret-scan.json`: PASS, no high-confidence secret findings, and no secret values
  included in the report.
- `casting.yaml.lock` is a source-content integrity lock, not a Foundry deployment receipt.

## Database migration

Only SQLite URLs are accepted. Back up the database, configure the exact SQLite URL, then run:

```bash
TRACEFENCE_DATABASE_URL=sqlite+pysqlite:///./data/tracefence.db \
  python -m alembic upgrade head
```

The application validates schema version 17, Alembic head, primary keys, named and unnamed
foreign keys, unique constraints, checks and indexes at startup. PostgreSQL/HA is not implied.

## Signed evidence and two-run isolation

Two complete scenarios ran against one API process and one fresh migrated schema-17 database.
Both completed with distinct run/command IDs, runtime `VERIFIED`, one stale denial, zero stale
commits, exactly one authorized recovery side effect, zero invariant violations and live-API
artifact equality. Telemetry and overall proof were canonically `UNAVAILABLE` because no SigNoz
API key/exporter was configured.

Evidence uses HMAC-SHA256 as explicitly local shared-key integrity. It is not independent
attestation; Ed25519/KMS signing remains a production evolution item.

## Remaining limitations

- Live Foundry/SigNoz deployment, dashboard/alert provisioning, real trace/log/metric
  reconciliation and alert trigger/recovery are blocked by the unavailable environment.
- The frontend regression suite exercises the state machine, API, packaged assets and HTTP
  security behavior; a cross-browser Playwright matrix is not included.
- HMAC evidence is shared-key integrity, not independent attestation.
- SQLite, process-local rate limiting and single-operator authentication are deliberate bounded
  deployment constraints.
- Real external side effects still need a provider execution outbox, provider idempotency and
  reconciliation.
- OIDC/RBAC, PostgreSQL/HA, KMS/HSM, Kubernetes, multi-region operation and full disaster
  recovery remain production backlog items.
