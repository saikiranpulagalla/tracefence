#!/usr/bin/env bash
set -euo pipefail

if ! command -v foundryctl >/dev/null 2>&1; then
  echo "foundryctl is required. Install it from the official SigNoz Foundry instructions." >&2
  exit 1
fi

foundryctl gauge -f casting.yaml
foundryctl cast -f casting.yaml

if [[ ! -f casting.yaml.lock ]]; then
  echo "Foundry completed without producing casting.yaml.lock; do not submit until this is resolved." >&2
  exit 1
fi

curl -fsS http://localhost:8080 >/dev/null
curl -fsS http://localhost:8000/livez >/dev/null

echo "SigNoz, OTLP receivers and MCP are ready."
echo "Create a SigNoz service-account key, set SIGNOZ_API_KEY, and run make verify-signoz."
