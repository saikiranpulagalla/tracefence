# TraceFence Build Log

## 2026-07-22 — Enforcement core

- Implemented dynamic registration, one-shot activation, leases and hierarchical versioned
  scopes.
- Implemented command-specific authority and atomic gateway admission for simulated tools.
- Added independent non-compliant worker scenario and deterministic runtime proof.
- Added OpenTelemetry foundations, SigNoz assets and a control-integrity UI.
- Kept telemetry unavailable/partial rather than fabricating Foundry, MCP or SigNoz evidence.

## 2026-07-22 — First audit remediation

- Closed delegated `CANCEL_RUN` escalation.
- Authenticated and payload-bound command/action idempotency.
- Serialized activation-token consumption.
- Bound replacements transactionally to correction commands.
- Prevented expired-lease resurrection and added supervised expiry scanning.
- Added operator protection, run isolation, request limits and secure frontend headers.
- Added fail-closed schema validation and database-level cross-run/shape constraints.

## 2026-07-22 — Proof-contract hardening

- Replaced weak replacement instructions with exact digest-bound manifests.
- Added deterministic recovery actions, postconditions, causal binding and stability verdicts.
- Added exact multi-command attribution for overlapping invalid scopes.
- Restricted scenario seeding to pristine runs and removed reset controls from the UI.
- Added proposal-review payload binding and resulting-command linkage.
- Added graph/action/command/proposal quotas and bounded rate limiting.

## 2026-07-22 — Evidence and observability hardening

- Added durable invariant violations and at-least-once telemetry outbox delivery.
- Added explicit telemetry health state and readiness integration.
- Added signed immutable evidence manifests/pointers tied to clean Git commits.
- Added live API comparison, freshness and expected-commit verification.
- Expanded SigNoz dashboard/alerts with traces, logs and outbox backlog.
- Added worker retry/lease-loss handling and guaranteed exit flush.

## 2026-07-22 — Release gate

- Moved blocking services to a bounded executor while preserving SQLite write linearization.
- Added CI with Ruff, strict mypy, Bandit, pip-audit, branch coverage and clean-wheel install.
- Added Dependabot for Python and GitHub Actions.
- Removed stale tracked evidence and documented generated signed bundles.
- Fixed missing `X-Frame-Options: DENY` and future Ruff unused-import issues.
- Reached 99 passing tests and 73.81% branch coverage.
- Built and inspected the wheel, installed it into an isolated target and verified the running
  packaged API, readiness and frontend assets.

## Pending external release gate

- Generate `casting.yaml.lock` on the target Foundry installation.
- Run the complete telemetry-enabled scenario against live SigNoz.
- Provision and verify the dashboard and alerts through MCP.
- Require telemetry and overall proof verdicts to reach `VERIFIED`.

## 2026-07-24 — Adversarial runtime-integrity remediation

- Added authoritative proof revisions, bounded retry, revision/lease-aware caching and a single
  verdict severity lattice.
- Added strict command/run/process/build telemetry adapters, exporter watermark requirements,
  supported MCP Streamable HTTP transport and cancellation-safe proof single-flight.
- Enforced immutable recovery manifests and invocation budgets before side effects.
- Added heartbeat scope fencing, immutable terminal run transitions, root-expiry terminalization,
  achievable replacement lifecycle and encrypted short-lived credential response recovery.
- Isolated safety work from external proof I/O, made authenticated heartbeat limits
  identity-aware, bounded invariant/outbox processing and hardened readiness.
- Added SQLite-only enforcement, Alembic schema 17, constrained reset tooling, protected frontend
  state clearing and worker completion/lease-loss lifecycle tests.
- Verified 192 tests, 77.41% total branch-aware coverage, Ruff, strict mypy, Bandit, pip-audit,
  wheel/sdist construction and clean wheel installation.
- Generated four hash-locked dependency sets, a CycloneDX SBOM, a zero-advisory dependency report,
  a redacted secret-scan report and a source-content `casting.yaml.lock`.
- Live Foundry/SigNoz telemetry reconciliation remains blocked and is not reported as verified.
