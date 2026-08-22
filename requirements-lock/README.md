# Reproducible dependency sets

These lock files are generated with `pip-compile --generate-hashes` on CPython
3.12. Install them with `pip install --require-hashes -r <file>`.

## Shared locks

`runtime.txt`, `development.txt`, and `build.txt` are shared locks. They
must reproduce byte-for-byte on each supported native target: Linux/WSL and
Windows.

## Platform full locks

`full-linux.txt` and `full-windows.txt` are both generated from
`requirements-full.txt`, but each must be compiled on its native target.
Linux/WSL must not regenerate the Windows graph, and Windows must not
regenerate the Linux graph.

The current `full-windows.txt` is a bootstrap candidate inherited from the
former full lock. Native Windows CI must regenerate and certify it before it
is treated as a certified Windows lock.

## Toolchains

Lock compilation uses released `pip-tools==7.6.0` with
`pip==26.1.2` in a disposable compiler environment. Security certification
uses the separate, secure environment with `pip==26.2.1`.

For each supported target E, two fresh native compiler environments must
produce the committed locks for E byte-for-byte. Each target full lock must be
audited on its native target; a Linux audit does not certify Windows-only
dependencies.
