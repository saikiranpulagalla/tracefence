# Query Builder checks

1. Control commands:
   - signal: traces
   - span name: `tracefence.control.command_issue`
   - group by: `tracefence.command.type`, `tracefence.command.reason_code`

2. Blocked stale actions:
   - signal: traces
   - filter: `tracefence.action.decision = DENY`
   - filter: `tracefence.action.denial_reason IN (SCOPE_CANCELLED, SCOPE_SUPERSEDED, SCOPE_VERSION_MISMATCH)`
   - group by: `tracefence.node.role`, `tracefence.action.tool`

3. Gateway latency:
   - signal: metrics
   - metric: `tracefence_action_gateway_duration_ms`
   - aggregations: p50, p95, p99
   - group by: `action_decision`

4. Hard safety invariant:
   - signal: metrics
   - metric: `tracefence_stale_actions_committed_total`
   - expected value: zero
