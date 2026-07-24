#!/usr/bin/env bash
set -euo pipefail

if ! command -v foundryctl >/dev/null 2>&1; then
  echo "foundryctl is required. Install it from the official SigNoz Foundry instructions." >&2
  exit 1
fi

python_bin="${PYTHON:-python3}"
source_lock="casting.source.lock.json"
deployment_receipt="casting.yaml.lock"
before_receipt="$(
  "$python_bin" scripts/verify_foundry_receipt.py snapshot \
    --receipt "$deployment_receipt"
)"

foundryctl gauge -f casting.yaml
foundryctl cast --no-gauge -f casting.yaml

"$python_bin" scripts/verify_foundry_receipt.py validate \
  --receipt "$deployment_receipt" \
  --source-lock "$source_lock" \
  --before "$before_receipt"

curl -fsS http://localhost:8080 >/dev/null
curl -fsS http://localhost:8000/livez >/dev/null

echo "SigNoz, OTLP receivers and MCP are ready."
echo "Create a SigNoz service-account key, set SIGNOZ_API_KEY, and run make verify-signoz."
