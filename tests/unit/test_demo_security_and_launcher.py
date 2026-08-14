from __future__ import annotations

import importlib.util
from dataclasses import replace
from pathlib import Path

from fastapi.testclient import TestClient

from tracefence.api import demo_security
from tracefence.api.demo_security import demo_access_allowed
from tracefence.api.main import app
from tracefence.api.routes import demo as demo_routes
from tracefence.config import settings

ROOT = Path(__file__).resolve().parents[2]


def _load_demo_launcher():
    path = ROOT / "scripts" / "run_demo.py"
    spec = importlib.util.spec_from_file_location("tracefence_run_demo", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_access_is_default_off_loopback_and_nonce_bound() -> None:
    assert not demo_access_allowed(
        demo_mode=False,
        environment="development",
        client_host="127.0.0.1",
        supplied_nonce="correct",
        expected_nonce="correct",
    )
    assert not demo_access_allowed(
        demo_mode=True,
        environment="development",
        client_host="192.0.2.1",
        supplied_nonce="correct",
        expected_nonce="correct",
    )
    assert not demo_access_allowed(
        demo_mode=True,
        environment="development",
        client_host="127.0.0.1",
        supplied_nonce="wrong",
        expected_nonce="correct",
    )
    assert demo_access_allowed(
        demo_mode=True,
        environment="development",
        client_host="127.0.0.1",
        supplied_nonce="correct",
        expected_nonce="correct",
    )


def test_demo_launcher_builds_private_external_free_environment(tmp_path) -> None:
    module = _load_demo_launcher()
    inherited = {
        "SIGNOZ_API_KEY": "must-not-survive",
        "SIGNOZ_MCP_URL": "http://127.0.0.1:8000/mcp",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318",
        "OTEL_EXPORTER_OTLP_HEADERS": "authorization=secret",
        "TRACEFENCE_NOTIFICATION_CHANNEL": "live-channel",
    }
    database_path = tmp_path / "tracefence-demo.db"

    environment = module.demo_environment(inherited, database_path)

    assert environment["TRACEFENCE_DEMO_MODE"] == "true"
    assert environment["TRACEFENCE_ENV"] == "development"
    assert environment["TRACEFENCE_DATABASE_URL"].endswith(
        "/tracefence-demo.db"
    )
    assert environment["OTEL_SDK_DISABLED"] == "true"
    assert environment["OTEL_EXPORTER_OTLP_ENDPOINT"] == ""
    assert "SIGNOZ_API_KEY" not in environment
    assert "SIGNOZ_MCP_URL" not in environment
    assert "OTEL_EXPORTER_OTLP_HEADERS" not in environment
    assert "TRACEFENCE_NOTIFICATION_CHANNEL" not in environment
    secrets = [
        environment["TRACEFENCE_OPERATOR_KEY"],
        environment["TRACEFENCE_TOKEN_HASH_SECRET"],
        environment["TRACEFENCE_CREDENTIAL_RECOVERY_KEY"],
        environment["TRACEFENCE_EVIDENCE_SIGNING_KEY"],
    ]
    assert len(set(secrets)) == 4
    assert all(len(value) >= 48 for value in secrets)


def test_demo_routes_are_default_off_cookie_bound_and_fixed(monkeypatch) -> None:
    disabled = replace(settings, demo_mode=False, environment="test")
    monkeypatch.setattr(demo_security, "settings", disabled)
    client = TestClient(app)
    assert client.get("/v1/demo/bootstrap").status_code == 404

    enabled = replace(settings, demo_mode=True, environment="test")
    monkeypatch.setattr(demo_security, "settings", enabled)
    without_cookie = TestClient(app)
    assert (
        without_cookie.post("/v1/demo/checks/cancellation/run").status_code
        == 404
    )

    class FakeController:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def run_check(self, scenario: str):
            self.calls.append(scenario)
            return {
                "scenario": scenario,
                "status": "PASS",
                "run_id": "sanitized-run",
            }

    fake = FakeController()

    async def direct(factory):
        return await factory()

    monkeypatch.setattr(demo_routes, "demo_controller", fake)
    monkeypatch.setattr(demo_routes, "call_blocking_service", direct)
    bootstrap = client.get("/v1/demo/bootstrap")
    assert bootstrap.status_code == 200
    assert set(bootstrap.json()["scenarios"]) == {
        "stale-supersession",
        "cancellation",
        "lease-expiry",
        "idempotent-retry",
        "recovery-manifest-mismatch",
        "sibling-isolation",
        "concurrent-stale-valid",
    }
    cookie = bootstrap.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    response = client.post("/v1/demo/checks/cancellation/run")
    assert response.status_code == 200
    assert fake.calls == ["cancellation"]
