PYTHON ?= python
API_URL ?= http://127.0.0.1:9000
EXPECTED_COMMIT ?= $(shell git rev-parse HEAD)
EVIDENCE_MAX_AGE_SECONDS ?= 900

.PHONY: help install install-core install-dev install-full test audit locks release-artifacts api scenario verify reset signoz provision-signoz verify-signoz verify-all clean

help:
	@echo "install-core       Install direct runtime dependencies and editable package"
	@echo "install-dev        Install direct development dependencies and editable package"
	@echo "install-full       Install development plus MCP/SigNoz dependencies"
	@echo "test               Run the complete test suite"
	@echo "audit              Compile, JS syntax, Ruff, mypy, Bandit, pip-audit and coverage"
	@echo "locks              Regenerate four hash-locked dependency sets"
	@echo "release-artifacts  Generate casting.source.lock.json, SBOM and redacted secret-scan report"
	@echo "scenario           Run one distributed scenario against API_URL"
	@echo "verify             Verify signed evidence against commit, freshness and live API"
	@echo "verify-all         Verify evidence and require live telemetry reconciliation"

install-core:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e . --no-deps

install-dev:
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install -e . --no-deps

install-full:
	$(PYTHON) -m pip install -r requirements-dev.txt -r requirements-full.txt
	$(PYTHON) -m pip install -e . --no-deps

install:
	$(PYTHON) -m pip install -e '.[dev,mcp,otel-instrumentation]'

test:
	PYTHONPATH=src $(PYTHON) scripts/run_local_tests.py -q

audit:
	$(PYTHON) -m compileall -q src scripts tests
	node --check src/tracefence/frontend/app.js
	ruff check src scripts tests
	mypy src/tracefence
	bandit -q -r src scripts -x tests
	pip-audit
	PYTHONPATH=src $(PYTHON) scripts/run_local_tests.py -q --cov=tracefence --cov-branch --cov-fail-under=70

locks:
	mkdir -p requirements-lock
	$(PYTHON) -m piptools compile --generate-hashes --resolver=backtracking --output-file requirements-lock/runtime.txt requirements.txt
	$(PYTHON) -m piptools compile --generate-hashes --allow-unsafe --resolver=backtracking --output-file requirements-lock/development.txt requirements-dev.txt
	$(PYTHON) -m piptools compile --generate-hashes --resolver=backtracking --output-file requirements-lock/full.txt requirements-full.txt
	$(PYTHON) scripts/normalize_lock_markers.py
	$(PYTHON) -m piptools compile --generate-hashes --allow-unsafe --resolver=backtracking --output-file requirements-lock/build.txt requirements-build.in

release-artifacts:
	mkdir -p reports
	$(PYTHON) scripts/lock_casting.py
	$(PYTHON) scripts/secret_scan.py --output reports/secret-scan.json
	cyclonedx-py requirements requirements-lock/full.txt --pyproject pyproject.toml --output-reproducible --output-format JSON --output-file reports/sbom.cdx.json --validate
	pip-audit -r requirements-lock/full.txt --require-hashes --progress-spinner off --format json --output reports/dependency-audit.json

api:
	PYTHONPATH=src $(PYTHON) -m uvicorn tracefence.api.main:app --host 127.0.0.1 --port 9000

scenario:
	PYTHONPATH=src $(PYTHON) scripts/run_scenario.py --api-url $(API_URL)

verify:
	PYTHONPATH=src TRACEFENCE_EXPECTED_EVIDENCE_COMMIT=$(EXPECTED_COMMIT) TRACEFENCE_EVIDENCE_MAX_AGE_SECONDS=$(EVIDENCE_MAX_AGE_SECONDS) $(PYTHON) scripts/verify_end_to_end.py --bundle evidence/latest.json --api-url $(API_URL)

reset:
	PYTHONPATH=src $(PYTHON) scripts/reset_state.py --yes --data-dir ./data --expected-path ./data/tracefence.db

signoz:
	./scripts/bootstrap_signoz.sh

provision-signoz:
	PYTHONPATH=src $(PYTHON) scripts/provision_signoz.py

verify-signoz:
	PYTHONPATH=src $(PYTHON) scripts/verify_signoz.py --require-alerts

verify-all:
	PYTHONPATH=src TRACEFENCE_EXPECTED_EVIDENCE_COMMIT=$(EXPECTED_COMMIT) TRACEFENCE_EVIDENCE_MAX_AGE_SECONDS=$(EVIDENCE_MAX_AGE_SECONDS) $(PYTHON) scripts/verify_end_to_end.py --bundle evidence/latest.json --api-url $(API_URL) --require-telemetry
	PYTHONPATH=src $(PYTHON) scripts/verify_signoz.py --require-alerts --proof-bundle evidence/latest.json

clean:
	rm -rf data .pytest_cache .ruff_cache .mypy_cache build dist *.egg-info
	find evidence -mindepth 1 ! -name README.md -exec rm -rf {} +
