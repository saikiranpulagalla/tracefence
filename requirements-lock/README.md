# Reproducible dependency sets

These lock files are generated with `pip-compile --generate-hashes` on Python
3.12. Install them with `pip install --require-hashes -r <file>`.

- `runtime.txt`: application runtime.
- `development.txt`: runtime plus test, lint, type, audit, and build tools.
- `full.txt`: runtime plus SigNoz MCP and OpenTelemetry instrumentation.
- `build.txt`: isolated package-build tools.

Regenerate all four sets after changing a direct dependency, then run
`pip-audit` against the resulting environment.

`scripts/normalize_lock_markers.py` restores MCP's upstream Windows-only
`pywin32` marker after host-platform resolution so the full lock remains
installable on both Windows and Linux CI.
