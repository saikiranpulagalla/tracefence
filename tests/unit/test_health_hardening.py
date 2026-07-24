from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

from tracefence.api.routes import health


def _request_state():
    current = datetime.now(UTC).isoformat()
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                lease_scanner_last_success=current,
                lease_scanner_error=None,
                invariant_auditor_last_success=current,
                invariant_auditor_error=None,
                invariant_outbox_pending=0,
            )
        )
    )


async def test_readiness_is_singleflight_and_cached(monkeypatch):
    calls = 0

    def writable() -> bool:
        nonlocal calls
        calls += 1
        return True

    async def healthy_probe() -> bool:
        await asyncio.sleep(0.02)
        return True

    monkeypatch.setattr(health, "_database_ready", lambda: True)
    monkeypatch.setattr(health, "_database_readable", lambda: True)
    monkeypatch.setattr(health, "_database_writable", writable)
    monkeypatch.setattr(health.control_plane_runtime, "probe", healthy_probe)
    request = _request_state()

    results = await asyncio.gather(
        *(health._readiness_payload(request) for _ in range(8))
    )
    await health._readiness_payload(request)

    assert all(ready for _payload, ready in results)
    assert calls == 1


async def test_readiness_sanitizes_internal_scanner_errors(monkeypatch):
    monkeypatch.setattr(health, "_database_ready", lambda: True)
    monkeypatch.setattr(health, "_database_readable", lambda: True)
    monkeypatch.setattr(health, "_database_writable", lambda: True)

    async def healthy_probe() -> bool:
        return True

    monkeypatch.setattr(health.control_plane_runtime, "probe", healthy_probe)
    request = _request_state()
    request.app.state.lease_scanner_error = (
        "OperationalError: database password=do-not-expose"
    )

    payload, ready = await health._readiness_payload(request)

    assert ready is False
    assert payload["lease_scanner"]["error"] is True
    assert "do-not-expose" not in repr(payload)


async def test_readiness_reports_observed_mcp_health_without_remote_probe(
    monkeypatch,
):
    monkeypatch.setattr(health, "_database_ready", lambda: True)
    monkeypatch.setattr(health, "_database_readable", lambda: True)
    monkeypatch.setattr(health, "_database_writable", lambda: True)
    monkeypatch.setattr(
        health,
        "mcp_health",
        lambda: {
            "configured": True,
            "available": False,
            "status": "transport_unavailable",
            "last_success_at": None,
        },
    )

    async def healthy_probe() -> bool:
        return True

    monkeypatch.setattr(health.control_plane_runtime, "probe", healthy_probe)
    request = _request_state()

    payload, _ready = await health._compute_readiness(request)

    assert payload["mcp"] == {
        "configured": True,
        "available": False,
        "status": "transport_unavailable",
        "last_success_at": None,
    }


def test_public_readiness_is_summary_and_detailed_health_is_protected(monkeypatch):
    from fastapi.testclient import TestClient

    from tracefence.api.main import app

    async def ready(_request):
        return (
            {
                "status": "ok",
                "service": "tracefence-control-plane",
                "database_checks": {"readable": True, "writable": True},
            },
            True,
        )

    monkeypatch.setattr(health, "_readiness_payload", ready)
    client = TestClient(app)

    public = client.get("/readyz")
    protected = client.get("/health")

    assert public.status_code == 200
    assert "database_checks" not in public.json()
    assert protected.status_code == 401
    assert protected.headers["cache-control"] == "no-store, private"
