# Reproducible dependency sets

These lock files are generated with `pip-compile --generate-hashes` on CPython
3.12. Install them with `pip install --require-hashes -r <file>`.

## Native platform locks

Every compiled lock family is platform-specific:

- `runtime-linux.txt` and `runtime-windows.txt` derive from
  `requirements.txt`.
- `development-linux.txt` and `development-windows.txt` derive from
  `requirements-dev.txt`.
- `build-linux.txt` and `build-windows.txt` derive from
  `requirements-build.in`.
- `full-linux.txt` and `full-windows.txt` derive from
  `requirements-full.txt`.

Linux/WSL must not regenerate a Windows graph, and Windows must not regenerate
a Linux graph. No compiled lock is assumed portable across those targets.
The initial Windows development and build files preserve verified native dependency
graphs as bootstrap candidates; their platform-qualified generated headers require
one native Windows recertification pass.

## Toolchains

Lock compilation uses released `pip-tools==7.6.0` with
`pip==26.1.2` in a disposable compiler environment. Security certification
uses a separate environment with `pip==26.2.1`.

For each lock family F and supported native target E, two fresh compiler
environments must produce `lock(F, E)` byte-for-byte. Linux/WSL and Windows
audit their effective native lock sets separately; one target's audit does not
certify target-specific dependencies on the other.
