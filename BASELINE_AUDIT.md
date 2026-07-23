# TraceFence Baseline Audit

Date: 2026-07-23

Environment:

- Windows
- Python 3.12.13
- pytest 9.0.2
- Ruff 0.15.22
- mypy 1.20.2
- Bandit 1.9.4
- pip-audit 2.10.1
- build 1.5.0

## Command results

### Compilation

Command:

```text
python -m compileall src scripts tests
```

Result: PASS, exit code 0. All discovered Python files compiled.

### Tests

Command:

```text
pytest -q
```

Result: PASS, exit code 0.

```text
99 passed in 15.73s
```

### Branch coverage

Command:

```text
pytest -q --cov=tracefence --cov-branch --cov-report=term-missing
```

Result: PASS, exit code 0.

```text
99 passed in 14.03s
TOTAL  3484 statements  767 missed  984 branches  266 partial  73.66%
```

### Ruff

Command:

```text
ruff check src scripts tests
```

Result: FAIL, exit code 1.

```text
45 errors
34 fixable with --fix
1 additional fix requires --unsafe-fixes
```

Reported rule totals:

```text
ASYNC240  5
ASYNC251  1
B010      2
B017      4
I001     24
UP035     1
UP037     7
UP047     1
```

### mypy

Command:

```text
mypy src/tracefence
```

Result: FAIL, exit code 1.

```text
13 errors in 7 files
47 source files checked
```

Files with errors:

```text
src/tracefence/db/engine.py
src/tracefence/services/proposal_service.py
src/tracefence/services/graph_service.py
src/tracefence/services/action_gateway.py
src/tracefence/services/control_service.py
src/tracefence/signoz/mcp_client.py
src/tracefence/services/proof_service.py
```

### Bandit

Command:

```text
bandit -q -r src scripts -x tests
```

Result: FAIL, exit code 1.

```text
3 low-severity findings
0 medium-severity findings
0 high-severity findings
0 #nosec lines skipped
1 test skipped because it was already specifically disabled
```

Findings:

```text
B105 scripts/provision_signoz.py:14
B105 scripts/verify_signoz.py:44
B404 src/tracefence/evidence.py:7
```

### Dependency audit

Command:

```text
pip-audit
```

Result: NOT COMPLETED.

`pip-audit` was installed, but vulnerability metadata could not be fetched because outbound metadata access was blocked. No dependency-audit pass or vulnerability-free conclusion was recorded.

### Package build

Command:

```text
python -m build
```

The initial isolated build could not download its declared build dependencies in the restricted environment. The same command was rerun with approved PyPI access.

Result: PASS, exit code 0.

```text
Successfully built tracefence-0.2.0.tar.gz
Successfully built tracefence-0.2.0-py3-none-any.whl
```

Generated build outputs and package metadata were removed after recording the result.

## Pre-commit scan results

Installed external secret scanners:

```text
gitleaks: unavailable
trufflehog: unavailable
detect-secrets: unavailable
git-secrets: unavailable
```

Manual filename, credential-pattern, private-key, token-prefix, URL-credential, and Python-AST literal scans:

```text
Unsafe artifact candidates before baseline commands: 0
High-confidence secret-pattern matches: 0
Static sensitive-string literals requiring review: 4
Reviewed environment placeholders: 2
Reviewed empty/test fixtures: 2
Probable real credentials: 0
```

`.env.example` contained empty credential values only.
