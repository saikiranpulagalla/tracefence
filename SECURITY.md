# TraceFence Security Model

## Trust boundary

TraceFence trusts the control-plane database and Action Gateway as the authoritative enforcement
boundary. Workers, prompts, models, peer recommendations and proposed remediation text are
untrusted. SigNoz is an independent evidence plane; it never grants action authority.

## Identities and credentials

### Human operator

Protected operator APIs require `X-Operator-Key`. The raw key is never stored in the database or
browser source. Commands and proposal reviews record a bounded fingerprint rather than a shared
literal label.

The MVP still has one operator trust domain. It does not provide an identity provider, individual
user accounts, session expiry or role-based access control.

### Nodes

- Activation and permanent node tokens are generated with cryptographically secure randomness.
- Only HMAC-SHA256 digests are stored.
- Token comparison uses constant-time digest comparison.
- Activation secrets are one-shot, expiry-bound and consumed under a serialized transaction.
- Worker activation secrets are passed over stdin rather than process arguments.

### Evidence signing

`TRACEFENCE_EVIDENCE_SIGNING_KEY` is a separate HMAC key. Startup rejects reuse of either the
operator credential or node-token hash secret. Evidence verification checks key identity,
signature, checksums, schema version, commit binding and optional freshness.

## Startup fail-closed policy

Outside `TRACEFENCE_ENV=test`, startup rejects:

- missing or short operator credentials;
- missing or short explicit token-hash secrets;
- missing or short evidence-signing keys;
- placeholder-like values;
- reused trust-domain secrets;
- invalid booleans/integers;
- unsafe lease/heartbeat relationships;
- invalid worker, quota, request-size, rate-limit or telemetry settings.

The API binds to loopback by default.

## Authority

- Human operator: may control the selected single-tenant deployment.
- Root coordinator: may control its run and descendants.
- Delegated parent: requires `control:descendants` and may control strict descendants only.
- Peer worker: may propose evidence but cannot control a sibling.
- `CANCEL_RUN`: operator or root only and root target only.

Authorization uses authoritative parent links, not the denormalized lineage display path. Cycle or
cross-run corruption fails closed.

## Idempotency and replay

Command replay identity is bound to:

```text
run + issuer fingerprint + idempotency key + canonical request digest
```

Action replay identity is bound to:

```text
node + idempotency key + tool + canonical arguments/request digest
```

Authentication and authorization happen before replay lookup. Reusing a key with a different
payload returns `IDEMPOTENCY_PAYLOAD_MISMATCH`; replay responses are constructed only from the
stored record.

## Replacement safety

A correction command freezes a signed-by-digest replacement manifest with exact:

- role;
- behavior;
- instruction and version;
- capabilities;
- expected tool and arguments digest;
- invocation bound;
- postconditions and stability window;
- child budget.

Replacement creation must match the manifest exactly and is transactionally linked to the
correction command. Extra capabilities, altered behavior, changed instructions, incorrect role
or excess children fail closed.

## Recovery proof safety

A successful tool call is not considered recovery. Proof requires:

1. the exact authorized action committed;
2. request, arguments and result digests are consistent;
3. current authoritative postconditions hold;
4. state is causally linked through `last_action_id` where required;
5. state remained unchanged for the configured stability window;
6. no contradictory committed side effect exists.

The normal API cannot reseed a run after activity begins. Development scenario seeding is allowed
only for a pristine newly created run with no commands/actions and initial service-state rows.

## Action Gateway

All protected side effects require:

- valid node token;
- active run and node state;
- live lease;
- every inherited scope active at the snapshotted version;
- exact tool capability;
- valid arguments;
- action quota availability;
- exact replay binding.

A stale denial records every exact command/scope/version match and acknowledges all applicable
overlapping commands.

## Database integrity

Schema version **13** fails closed against missing tables, columns, indexes, foreign keys or check
constraints. The database independently rejects malformed or cross-run:

- root/scope ownership;
- parent, supersedes and correction links;
- command issuer/target/replacement shapes;
- proposal review/command links;
- acknowledgements;
- action-command/scope/version attribution;
- invariant and outbox references;
- service-state counters and statuses.

The database is authoritative, but JSON manifests and snapshots are still validated by strict
Pydantic models in the service layer.

## Leases and worker failure

- A late heartbeat cannot revive an expired lease.
- Expired activation intents are closed automatically.
- Workers retry transient heartbeat failures with bounded backoff/jitter.
- Lease loss stops further cooperative work and produces terminal telemetry.
- The Action Gateway remains the final enforcement boundary even for a non-cooperative worker.

## API hardening

- Protected reads and writes require operator or node authentication as appropriate.
- Request bodies are counted while streaming; chunked/misleading `Content-Length` cannot bypass
  the configured limit.
- Process-local rate-limit buckets are bounded and do not trust caller-supplied node IDs.
- CORS is limited to configured/local origins.
- Browser responses include CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy` and cross-origin opener isolation.
- The browser source contains no operator secret.
- Dangerous commands use an operator preflight/confirmation surface.

## Telemetry integrity

- Tokens, signing keys and full sensitive payloads are excluded from telemetry.
- Stale-action spans/logs include command, scope and version attribution.
- Metrics avoid run/node/command IDs as labels.
- Telemetry exporter state is explicit and exposed through readiness.
- Force-flush failure prevents outbox delivery acknowledgement.
- Missing, ambiguous or contradictory MCP evidence never upgrades to `VERIFIED`.

## Durable safety violations

The invariant auditor persistently detects committed actions associated with stale control state.
It creates a unique violation row and telemetry-outbox event independently of proof generation.
Export is at-least-once and is marked delivered only after a successful provider flush.

This outbox covers safety-event telemetry. It is not yet the full execution outbox required for
real external tool calls.

## Evidence integrity

Evidence generation requires:

- a Git repository with committed `HEAD`;
- a clean worktree;
- an independent signing key.

The signed manifest binds every file to the Git commit, schema and run/command identity. The
verifier rejects unsigned legacy evidence, path traversal, checksum/signature mismatch, schema
drift, unexpected commits and stale/future timestamps. Optional live verification compares the
stored bundle with authenticated API state.

## External side effects

SQLite transactionality cannot atomically cover a cloud, payment or infrastructure provider.
Production adapters must use:

```text
live scope validation + provider idempotency reservation + durable execution outbox
→ external call with a short-lived scoped permit
→ provider status/result reconciliation
→ deterministic postcondition verification
```

Ambiguous timeouts must not be interpreted as success.

## Residual limitations

- Single human operator rather than per-user identity/RBAC.
- SQLite and one process rather than PostgreSQL/multi-replica coordination.
- Process-local rate limiting.
- No remote attestation of worker binaries or model configuration.
- No revocation of independent production credentials outside the gateway.
- No complete external-tool execution outbox/compensation framework.
- Live Foundry/SigNoz verification remains an environmental release gate.

Report vulnerabilities privately and do not include real credentials, production identifiers or
sensitive evidence in issues or demonstration artifacts.
