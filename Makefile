PYTHON ?= python
API_URL ?= http://127.0.0.1:9000
EXPECTED_COMMIT ?= $(shell git rev-parse HEAD)
EVIDENCE_MAX_AGE_SECONDS ?= 900

.PHONY: install install-core install-dev install-full test audit api scenario verify reset signoz provision-signoz verify-signoz verify-all clean

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
	PYTHONPATH=src TRACEFENCE_ENV=test $(PYTHON) -m pytest -q

audit:
	$(PYTHON) -m compileall -q src scripts tests
	node --check src/tracefence/frontend/app.js
	ruff check src scripts tests
	mypy src/tracefence
	bandit -q -r src scripts -x tests
	pip-audit
	PYTHONPATH=src TRACEFENCE_ENV=test $(PYTHON) -m pytest -q --cov=tracefence --cov-branch --cov-fail-under=70

api:
	PYTHONPATH=src $(PYTHON) -m uvicorn tracefence.api.main:app --host 127.0.0.1 --port 9000

scenario:
	PYTHONPATH=src $(PYTHON) scripts/run_scenario.py --api-url $(API_URL)

verify:
	PYTHONPATH=src TRACEFENCE_EXPECTED_EVIDENCE_COMMIT=$(EXPECTED_COMMIT) TRACEFENCE_EVIDENCE_MAX_AGE_SECONDS=$(EVIDENCE_MAX_AGE_SECONDS) $(PYTHON) scripts/verify_end_to_end.py --bundle evidence/latest.json --api-url $(API_URL)

reset:
	PYTHONPATH=src $(PYTHON) scripts/reset_state.py --yes

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
