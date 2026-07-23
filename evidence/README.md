# Generated evidence

This directory is intentionally empty in source control except for this note.

`python scripts/run_scenario.py` creates an immutable timestamped bundle and a signed
`latest.json` pointer. Generation fails unless the Git worktree is clean and a dedicated
`TRACEFENCE_EVIDENCE_SIGNING_KEY` is configured. Generated bundles are ignored by Git so
runtime evidence cannot silently become stale documentation.

A release bundle contains the graph, command, actions, service state, proof, invariant
violations, worker output, a checksum manifest, the generating Git commit and HMAC-SHA256
signatures. Verify it with:

```bash
PYTHONPATH=src python scripts/verify_end_to_end.py \
  --bundle evidence/latest.json \
  --expected-commit "$(git rev-parse HEAD)" \
  --max-age-seconds 3600
```

Add `--api-url` and `--operator-key` to compare the stored evidence with the authenticated
live control plane. Add `--require-telemetry` only after the live SigNoz gate is complete.
