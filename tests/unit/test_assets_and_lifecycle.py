from __future__ import annotations

import importlib.util
import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from tracefence.db.models import Node, Run
from tracefence.domain.enums import NodeStatus, RunStatus
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import SpawnCreate
from tracefence.services.common import utcnow
from tracefence.services.lease_service import LeaseService
from tracefence.services.spawn_service import SpawnService
from tests.helpers import activate, create_seeded_run

ROOT = Path(__file__).resolve().parents[2]


def _load_provision_module():
    path = ROOT / "scripts" / "provision_signoz.py"
    spec = importlib.util.spec_from_file_location("tracefence_provision_signoz", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_verify_module():
    path = ROOT / "scripts" / "verify_signoz.py"
    spec = importlib.util.spec_from_file_location("tracefence_verify_signoz", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_checked_in_signoz_assets_are_strictly_valid():
    module = _load_provision_module()
    dashboard = json.loads((ROOT / "observability" / "dashboard.json").read_text())
    alerts = json.loads((ROOT / "observability" / "alerts.json").read_text())
    module._validate_dashboard(dashboard)
    module._validate_alerts(alerts)
    assert all(item["x"] + item["w"] <= 12 for item in dashboard["layout"])
    assert {
        aggregation["metricName"]
        for widget in dashboard["widgets"]
        for query in widget["query"]["builder"]["queryData"]
        for aggregation in query["aggregations"]
        if "metricName" in aggregation
    } >= {
        "tracefence_stale_action_attempts_total",
        "tracefence_stale_actions_committed_total",
        "tracefence_telemetry_outbox_pending",
    }
    widget_ids = {widget["id"] for widget in dashboard["widgets"]}
    assert {
        "command-traces",
        "blocked-action-traces",
        "denied-action-logs",
    } <= widget_ids


def test_packaged_frontend_has_no_embedded_operator_secret():
    html = (ROOT / "src" / "tracefence" / "frontend" / "index.html").read_text()
    script = (ROOT / "src" / "tracefence" / "frontend" / "app.js").read_text()
    combined = html + script
    assert "dev-operator-key" not in combined
    assert "replace-me" not in combined
    assert "finalHeaders['Content-Type'] = 'application/json'" in script
    assert "...headers" in script
    assert "/v1/scenario/" not in combined
    assert "`/v1/runs/${runId}/services`" in script
    assert "/scenario/seed" not in combined
    assert '<script src="/assets/app.js" defer></script>' in html


async def test_root_completion_closes_run_only_after_valid_descendants_finish(session_factory):
    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, "completion")
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="child", capabilities=[]),
        ),
    )

    with pytest.raises(ConflictError) as exc:
        await spawns.complete(run.root_node_id, run.root_token)
    assert exc.value.code == "RUN_HAS_LIVE_NODES"

    await spawns.complete(child.node_id, child.node_token)
    await spawns.complete(run.root_node_id, run.root_token)
    with session_factory() as session:
        row = session.get(Run, run.run_id)
        assert row.status == RunStatus.COMPLETED
        assert row.finished_at is not None
        assert session.get(Node, run.root_node_id).status == NodeStatus.COMPLETED


async def test_manual_lease_expiry_is_scoped_to_requested_run(session_factory):
    spawns = SpawnService(session_factory)
    leases = LeaseService(session_factory)
    run_a = await create_seeded_run(session_factory, "lease-a")
    run_b = await create_seeded_run(session_factory, "lease-b")
    node_a = await activate(
        spawns,
        await spawns.create_spawn(
            run_a.root_node_id,
            run_a.root_token,
            SpawnCreate(role="a", capabilities=[]),
        ),
    )
    node_b = await activate(
        spawns,
        await spawns.create_spawn(
            run_b.root_node_id,
            run_b.root_token,
            SpawnCreate(role="b", capabilities=[]),
        ),
    )
    with session_factory() as session, session.begin():
        for node_id in (node_a.node_id, node_b.node_id):
            node = session.get(Node, node_id)
            node.lease_expires_at = utcnow() - timedelta(seconds=1)

    assert await leases.expire_stale_nodes(run_a.run_id) == 1
    with session_factory() as session:
        assert session.get(Node, node_a.node_id).status == NodeStatus.LEASE_EXPIRED
        assert session.get(Node, node_b.node_id).status == NodeStatus.ACTIVE


class _TextContent:
    def __init__(self, text: str):
        self.text = text


class _ResourceResult:
    def __init__(self, text: str):
        self.contents = [_TextContent(text)]


def test_provisioner_normalizes_resource_and_tool_results_without_stringifying_models():
    module = _load_provision_module()
    assert module._normalize_result(_ResourceResult('{"status":"ok"}')) == {
        "status": "ok"
    }
    assert module._tool_failed({"isError": True, "content": []})
    assert not module._tool_failed({"content": [{"text": "created"}]})


def test_dashboard_validator_rejects_layout_outside_twelve_column_grid():
    module = _load_provision_module()
    dashboard = json.loads((ROOT / "observability" / "dashboard.json").read_text())
    dashboard["layout"][0]["x"] = 11
    dashboard["layout"][0]["w"] = 2
    with pytest.raises(ValueError, match="12-column"):
        module._validate_dashboard(dashboard)


async def test_unactivated_spawn_expires_and_no_longer_blocks_root_completion(
    session_factory,
):
    spawns = SpawnService(session_factory)
    leases = LeaseService(session_factory)
    run = await create_seeded_run(session_factory, "pending-expiry")
    created = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="never-activated", capabilities=[]),
    )
    from tracefence.db.models import SpawnIntent

    with session_factory() as session, session.begin():
        intent = session.execute(
            select(SpawnIntent).where(SpawnIntent.child_node_id == created.child_node_id)
        ).scalar_one()
        intent.expires_at = utcnow() - timedelta(seconds=1)

    assert await leases.expire_stale_nodes(run.run_id) == 1
    await spawns.complete(run.root_node_id, run.root_token)
    with session_factory() as session:
        assert session.get(Node, created.child_node_id).status == NodeStatus.LEASE_EXPIRED
        assert session.get(Run, run.run_id).status == RunStatus.COMPLETED


async def test_streaming_request_size_limit_rejects_chunked_body():
    from tracefence.api.middleware import RequestSizeLimitMiddleware

    called = False

    async def downstream(scope, receive, send):
        nonlocal called
        called = True
        while True:
            message = await receive()
            if message["type"] == "http.request" and not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages = iter(
        [
            {"type": "http.request", "body": b"1234", "more_body": True},
            {"type": "http.request", "body": b"5678", "more_body": False},
        ]
    )
    sent = []

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    middleware = RequestSizeLimitMiddleware(downstream, max_bytes=6)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [],
            "http_version": "1.1",
            "scheme": "http",
            "query_string": b"",
            "server": ("test", 80),
            "client": ("test", 1),
        },
        receive,
        send,
    )
    assert called
    assert sent[0]["status"] == 413


def test_json_log_formatter_escapes_messages_and_exposes_structured_fields():
    import logging

    from tracefence.logging_config import JsonFormatter

    record = logging.LogRecord(
        name="tracefence.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg='unsafe "quoted" message\nnext-line',
        args=(),
        exc_info=None,
    )
    record.event = "test_event"
    record.command_id = "command-1"
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == 'unsafe "quoted" message\nnext-line'
    assert payload["event"] == "test_event"
    assert payload["command_id"] == "command-1"


def test_alert_deployment_digest_is_channel_bound_and_shared_by_provision_and_verify():
    provision = _load_provision_module()
    verify = _load_verify_module()
    alerts = json.loads((ROOT / "observability" / "alerts.json").read_text())
    dashboard = json.loads((ROOT / "observability" / "dashboard.json").read_text())
    spec_digest = provision._json_digest({"dashboard": dashboard, "alerts": alerts})

    payload_a, digest_a = provision._prepare_alert_payload(
        alerts[0], "channel-a", spec_digest
    )
    _, digest_b = provision._prepare_alert_payload(
        alerts[0], "channel-b", spec_digest
    )

    assert digest_a != digest_b
    assert payload_a["annotations"]["tracefence_deployment_digest"] == digest_a
    assert verify._deployment_digest(alerts[0], "channel-a", spec_digest) == digest_a


async def test_readiness_fails_closed_when_database_or_scanner_is_unhealthy(monkeypatch):
    from types import SimpleNamespace

    from tracefence.api.routes import health

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                lease_scanner_last_success=None,
                lease_scanner_error=None,
                invariant_auditor_last_success=None,
                invariant_auditor_error=None,
            )
        )
    )
    monkeypatch.setattr(health, "_database_ready", lambda: False)
    payload, ready = await health._readiness_payload(request)
    assert ready is False
    assert payload["status"] == "degraded"
    assert payload["database"] == "unavailable"

    monkeypatch.setattr(health, "_database_ready", lambda: True)
    request.app.state.lease_scanner_error = "scanner failed"
    payload, ready = await health._readiness_payload(request)
    assert ready is False
    assert payload["lease_scanner"]["error"] == "scanner failed"


async def test_readiness_waits_for_first_successful_lease_scan(monkeypatch):
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from tracefence.api.routes import health

    async def healthy_probe() -> bool:
        return True

    monkeypatch.setattr(health.control_plane_runtime, "probe", healthy_probe)
    _readiness_payload = health._readiness_payload

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                lease_scanner_last_success=None,
                lease_scanner_error=None,
                invariant_auditor_last_success=None,
                invariant_auditor_error=None,
            )
        )
    )
    payload, ready = await _readiness_payload(request)
    assert ready is False
    assert payload["status"] == "degraded"

    current = datetime.now(UTC).isoformat()
    request.app.state.lease_scanner_last_success = current
    payload, ready = await _readiness_payload(request)
    assert ready is False

    request.app.state.invariant_auditor_last_success = current
    payload, ready = await _readiness_payload(request)
    assert ready is True
    assert payload["status"] == "ok"


def test_packaged_fastapi_surface_serves_assets_with_security_headers():
    from fastapi.testclient import TestClient

    from tracefence.api.main import app

    client = TestClient(app)
    live = client.get("/livez")
    home = client.get("/")
    script = client.get("/assets/app.js")

    assert live.status_code == 200
    assert live.json()["status"] == "alive"
    assert home.status_code == 200
    assert '<script src="/assets/app.js" defer></script>' in home.text
    assert script.status_code == 200
    assert "function renderGraph" in script.text
    for response in (live, home, script):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'self'" in response.headers["content-security-policy"]
        assert response.headers["x-frame-options"] == "DENY"
