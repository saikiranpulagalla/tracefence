from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from tracefence.telemetry.schema import (
    MetricDiscoveryError,
    MetricReference,
    classify_metric_discovery,
    extract_metric_references,
    wait_for_metric_discovery,
)

ROOT = Path(__file__).resolve().parents[2]


def _load_provision_module():
    path = ROOT / "scripts" / "provision_signoz.py"
    spec = importlib.util.spec_from_file_location("tracefence_provision_metrics", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_verify_module():
    path = ROOT / "scripts" / "verify_signoz.py"
    spec = importlib.util.spec_from_file_location("tracefence_verify_metrics", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dashboard() -> dict[str, object]:
    return json.loads((ROOT / "observability" / "dashboard.json").read_text(encoding="utf-8"))


def _alerts() -> list[dict[str, object]]:
    return json.loads((ROOT / "observability" / "alerts.json").read_text(encoding="utf-8"))


def _first_metric_mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        if isinstance(value.get("metricName"), str):
            return value
        for nested in value.values():
            found = _first_metric_mapping(nested)
            if found:
                return found
    if isinstance(value, list):
        for nested in value:
            found = _first_metric_mapping(nested)
            if found:
                return found
    return {}


def _startup_metrics() -> set[str]:
    return {
        "tracefence_active_nodes",
        "tracefence_unacknowledged_live_nodes",
        "tracefence_orphan_nodes",
        "tracefence_telemetry_outbox_pending",
    }


def _catalog_payload(metric_names: set[str]) -> dict[str, object]:
    return {
        "status": "success",
        "data": {"metrics": [{"metricName": value} for value in sorted(metric_names)]},
    }


class _TextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


def _complete_note() -> str:
    return "note: returned 0 rows (limit 100) -- all matching results returned (hasMore=false)."


def _catalog_result(payload: dict[str, object]) -> SimpleNamespace:
    return SimpleNamespace(
        structuredContent=None,
        content=[_TextBlock(json.dumps(payload)), _TextBlock(_complete_note())],
        isError=False,
    )


def test_missing_startup_required_metric_is_fatal_but_clean_failure_metrics_are_not() -> None:
    references = extract_metric_references(_dashboard(), _alerts())
    preflight = classify_metric_discovery(
        references,
        _startup_metrics(),
    )

    assert preflight.startup_required_missing == ()
    assert "tracefence_stale_actions_committed_total" in preflight.failure_only_not_yet_observed
    assert "tracefence_action_gateway_duration_ms" in preflight.event_driven_not_yet_observed

    missing = classify_metric_discovery(references, set())
    assert "tracefence_active_nodes" in missing.startup_required_missing
    assert "tracefence_stale_actions_committed_total" not in missing.startup_required_missing


async def test_metric_discovery_retries_until_startup_metrics_appear() -> None:
    references = (
        MetricReference("tracefence_active_nodes", "latest", "max"),
    )
    attempts = 0
    clock = 0.0

    async def fetch() -> set[str]:
        nonlocal attempts
        attempts += 1
        return set() if attempts == 1 else {"tracefence_active_nodes"}

    def monotonic() -> float:
        return clock

    async def sleep(seconds: float) -> None:
        nonlocal clock
        clock += seconds

    preflight = await wait_for_metric_discovery(
        fetch,
        references,
        deadline_seconds=5,
        poll_seconds=1,
        monotonic=monotonic,
        sleep=sleep,
    )

    assert attempts == 2
    assert preflight.startup_required_missing == ()


async def test_metric_discovery_times_out_deterministically() -> None:
    references = (
        MetricReference("tracefence_active_nodes", "latest", "max"),
    )
    clock = 0.0
    attempts = 0

    async def fetch() -> set[str]:
        nonlocal attempts
        attempts += 1
        return set()

    def monotonic() -> float:
        return clock

    async def sleep(seconds: float) -> None:
        nonlocal clock
        clock += seconds

    preflight = await wait_for_metric_discovery(
        fetch,
        references,
        deadline_seconds=2,
        poll_seconds=1,
        monotonic=monotonic,
        sleep=sleep,
    )

    assert attempts == 3
    assert preflight.startup_required_missing == ("tracefence_active_nodes",)


class _FakeSession:
    def __init__(self, _read_stream: object, _write_stream: object, state: dict[str, object]) -> None:
        self._state = state

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type: object, _exc: object, _traceback: object) -> bool:
        return False

    async def initialize(self) -> None:
        self._state["initialized"] = True

    async def list_tools(self):
        names = {
            "signoz_list_metrics",
            "signoz_query_metrics",
            "signoz_list_dashboards",
            "signoz_get_dashboard",
            "signoz_create_dashboard",
        }
        return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in sorted(names)])

    async def read_resource(self, _uri: str) -> object:
        return SimpleNamespace(content=[])

    async def call_tool(self, name: str, arguments: dict[str, object]) -> object:
        calls = self._state.setdefault("calls", [])
        assert isinstance(calls, list)
        calls.append((name, arguments))
        if name == "signoz_list_metrics":
            if self._state.get("metric_list_error"):
                return SimpleNamespace(structuredContent=None, content=[], isError=True)
            payload = self._state.get("metric_catalog_payload")
            if not isinstance(payload, dict):
                payload = _catalog_payload(self._state["metrics"])
            return _catalog_result(payload)
        if name == "signoz_query_metrics":
            if self._state.get("metric_query_error"):
                return SimpleNamespace(structuredContent=None, content=[], isError=True)
            return SimpleNamespace(
                structuredContent={
                    "results": [
                        {"metric_name": "tracefence_active_nodes", "value": value}
                        for value in self._state.get("query_values", [0.0])
                    ]
                },
                content=[],
                isError=False,
            )
        if name == "signoz_list_dashboards":
            return SimpleNamespace(structuredContent={"dashboards": []}, content=[], isError=False)
        if name.startswith("signoz_create_") or name.startswith("signoz_update_"):
            self._state["mutation_called"] = True
            return SimpleNamespace(structuredContent={"id": "created"}, content=[], isError=False)
        raise AssertionError(f"unexpected MCP tool call: {name}")


def _install_fake_mcp(monkeypatch: pytest.MonkeyPatch, state: dict[str, object]) -> None:
    monkeypatch.setenv("TRACEFENCE_BUILD_COMMIT", "a" * 40)

    @asynccontextmanager
    async def streamable_http_client(_url: str, *, http_client: object):
        assert http_client is not None
        yield object(), object(), lambda: "fake-session"

    class ClientSession:
        def __init__(self, read_stream: object, write_stream: object) -> None:
            self._session = _FakeSession(read_stream, write_stream, state)

        async def __aenter__(self):
            return await self._session.__aenter__()

        async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return await self._session.__aexit__(exc_type, exc, traceback)

    fake_mcp = ModuleType("mcp")
    fake_mcp.__path__ = []
    fake_mcp.ClientSession = ClientSession
    fake_client = ModuleType("mcp.client")
    fake_client.__path__ = []
    fake_streamable = ModuleType("mcp.client.streamable_http")
    fake_streamable.streamable_http_client = streamable_http_client
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.client", fake_client)
    monkeypatch.setitem(sys.modules, "mcp.client.streamable_http", fake_streamable)


async def test_provisioning_stops_before_any_mutation_when_startup_telemetry_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state: dict[str, object] = {"metrics": set()}
    _install_fake_mcp(monkeypatch, state)
    module = _load_provision_module()
    module.METRIC_DISCOVERY_DEADLINE_SECONDS = 0
    module.METRIC_DISCOVERY_POLL_SECONDS = 0.1

    @asynccontextmanager
    async def fake_http_client(_api_key: str):
        yield object()

    monkeypatch.setattr(module, "create_mcp_http_client", fake_http_client)
    monkeypatch.setenv("SIGNOZ_API_KEY", "test-key")

    dashboard_path = tmp_path / "dashboard.json"
    alerts_path = tmp_path / "alerts.json"
    evidence_path = tmp_path / "provisioning.json"
    dashboard_path.write_text(json.dumps(_dashboard()), encoding="utf-8")
    alerts_path.write_text(json.dumps(_alerts()), encoding="utf-8")

    with pytest.raises(RuntimeError, match="startup telemetry is not visible"):
        await module.provision(
            dashboard_path,
            alerts_path,
            evidence_path,
            skip_alerts=True,
            update_existing=False,
        )

    assert state.get("initialized") is True
    assert state.get("mutation_called") is None
    calls = state.get("calls", [])
    assert [name for name, _arguments in calls] == [
        "signoz_list_metrics",
        "signoz_query_metrics",
    ]
    saved = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert "tracefence_active_nodes" in saved["startup_required_missing"]
    assert "tracefence_stale_actions_committed_total" in saved["failure_only_not_yet_observed"]


async def test_unknown_dashboard_metric_fails_before_mcp_connection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state: dict[str, object] = {"metrics": set(), "connected": False}
    _install_fake_mcp(monkeypatch, state)
    module = _load_provision_module()

    @asynccontextmanager
    async def fake_http_client(_api_key: str):
        state["connected"] = True
        yield object()

    monkeypatch.setattr(module, "create_mcp_http_client", fake_http_client)
    monkeypatch.setenv("SIGNOZ_API_KEY", "test-key")
    dashboard = _dashboard()
    _first_metric_mapping(dashboard)["metricName"] = "tracefence_typo_metric"
    dashboard_path = tmp_path / "dashboard.json"
    alerts_path = tmp_path / "alerts.json"
    dashboard_path.write_text(json.dumps(dashboard), encoding="utf-8")
    alerts_path.write_text(json.dumps(_alerts()), encoding="utf-8")

    with pytest.raises(ValueError, match="Unknown TraceFence metric"):
        await module.provision(
            dashboard_path,
            alerts_path,
            tmp_path / "evidence.json",
            skip_alerts=True,
            update_existing=False,
        )

    assert state["connected"] is False


async def test_unknown_alert_metric_fails_before_mcp_connection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state: dict[str, object] = {"metrics": set(), "connected": False}
    _install_fake_mcp(monkeypatch, state)
    module = _load_provision_module()

    @asynccontextmanager
    async def fake_http_client(_api_key: str):
        state["connected"] = True
        yield object()

    monkeypatch.setattr(module, "create_mcp_http_client", fake_http_client)
    monkeypatch.setenv("SIGNOZ_API_KEY", "test-key")
    alerts = _alerts()
    _first_metric_mapping(alerts)["metricName"] = "tracefence_typo_metric"
    dashboard_path = tmp_path / "dashboard.json"
    alerts_path = tmp_path / "alerts.json"
    dashboard_path.write_text(json.dumps(_dashboard()), encoding="utf-8")
    alerts_path.write_text(json.dumps(alerts), encoding="utf-8")

    with pytest.raises(ValueError, match="Unknown TraceFence metric"):
        await module.provision(
            dashboard_path,
            alerts_path,
            tmp_path / "evidence.json",
            skip_alerts=True,
            update_existing=False,
        )

    assert state["connected"] is False


async def test_provisioning_records_clean_event_and_failure_metric_absence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state: dict[str, object] = {"metrics": _startup_metrics()}
    _install_fake_mcp(monkeypatch, state)
    module = _load_provision_module()

    @asynccontextmanager
    async def fake_http_client(_api_key: str):
        yield object()

    monkeypatch.setattr(module, "create_mcp_http_client", fake_http_client)
    monkeypatch.setenv("SIGNOZ_API_KEY", "test-key")
    dashboard_path = tmp_path / "dashboard.json"
    alerts_path = tmp_path / "alerts.json"
    evidence_path = tmp_path / "provisioning.json"
    dashboard_path.write_text(json.dumps(_dashboard()), encoding="utf-8")
    alerts_path.write_text(json.dumps(_alerts()), encoding="utf-8")

    assert await module.provision(
        dashboard_path,
        alerts_path,
        evidence_path,
        skip_alerts=True,
        update_existing=False,
    ) == 0

    saved = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert saved["startup_required_missing"] == []
    assert "tracefence_action_gateway_duration_ms" in saved["event_driven_not_yet_observed"]
    assert "tracefence_stale_actions_committed_total" in saved[
        "failure_only_not_yet_observed"
    ]
    assert set(saved["observed_metrics"]) == _startup_metrics()
    assert isinstance(saved["metric_catalog_digest"], str)
    assert len(saved["metric_catalog_digest"]) == 64
    assert state.get("mutation_called") is True


async def test_current_metric_query_must_return_data_before_any_provisioning_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state: dict[str, object] = {
        "metrics": _startup_metrics(),
        "query_values": [],
    }
    _install_fake_mcp(monkeypatch, state)
    module = _load_provision_module()
    module.METRIC_DISCOVERY_DEADLINE_SECONDS = 0
    module.METRIC_DISCOVERY_POLL_SECONDS = 0.1

    @asynccontextmanager
    async def fake_http_client(_api_key: str):
        yield object()

    monkeypatch.setattr(module, "create_mcp_http_client", fake_http_client)
    monkeypatch.setenv("SIGNOZ_API_KEY", "test-key")
    dashboard_path = tmp_path / "dashboard.json"
    alerts_path = tmp_path / "alerts.json"
    evidence_path = tmp_path / "provisioning.json"
    dashboard_path.write_text(json.dumps(_dashboard()), encoding="utf-8")
    alerts_path.write_text(json.dumps(_alerts()), encoding="utf-8")

    with pytest.raises(RuntimeError, match="current TraceFence metric query returned no data"):
        await module.provision(
            dashboard_path,
            alerts_path,
            evidence_path,
            skip_alerts=True,
            update_existing=False,
        )

    assert state.get("mutation_called") is None
    saved = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert saved["live_metric_query_succeeded"] is False


async def test_metric_tool_error_stops_before_any_mutation_and_records_typed_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state: dict[str, object] = {"metrics": _startup_metrics(), "metric_list_error": True}
    _install_fake_mcp(monkeypatch, state)
    module = _load_provision_module()

    @asynccontextmanager
    async def fake_http_client(_api_key: str):
        yield object()

    monkeypatch.setattr(module, "create_mcp_http_client", fake_http_client)
    monkeypatch.setenv("SIGNOZ_API_KEY", "test-key")
    dashboard_path = tmp_path / "dashboard.json"
    alerts_path = tmp_path / "alerts.json"
    evidence_path = tmp_path / "provisioning.json"
    dashboard_path.write_text(json.dumps(_dashboard()), encoding="utf-8")
    alerts_path.write_text(json.dumps(_alerts()), encoding="utf-8")

    with pytest.raises(RuntimeError, match="signoz_list_metrics returned an MCP error"):
        await module.provision(
            dashboard_path,
            alerts_path,
            evidence_path,
            skip_alerts=True,
            update_existing=False,
        )

    assert state.get("mutation_called") is None
    saved = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert saved["metric_discovery_error_code"] == "MCP_METRIC_DISCOVERY_FAILED"


class _MetricOnlySession:
    def __init__(self, metric_names: set[str]) -> None:
        self._metric_names = metric_names

    async def call_tool(self, name: str, arguments: dict[str, object]) -> object:
        if name == "signoz_query_metrics":
            return SimpleNamespace(
                structuredContent={
                    "results": [{"metric_name": "tracefence_active_nodes", "value": 0.0}]
                },
                content=[],
                isError=False,
            )
        assert name == "signoz_list_metrics"
        assert arguments["searchText"] == "tracefence_"
        return SimpleNamespace(
            structuredContent=None,
            content=[
                _TextBlock(json.dumps(_catalog_payload(self._metric_names))),
                _TextBlock(_complete_note()),
            ],
            isError=False,
        )


async def test_verifier_allows_clean_event_and_failure_metric_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_verify_module()
    monkeypatch.setenv("TRACEFENCE_BUILD_COMMIT", "a" * 40)
    module.METRIC_DISCOVERY_DEADLINE_SECONDS = 0
    module.METRIC_DISCOVERY_POLL_SECONDS = 0.1
    failures: list[str] = []
    references = extract_metric_references(_dashboard(), _alerts())

    await module._verify_metric_preflight(
        _MetricOnlySession(_startup_metrics()),
        references,
        failures,
    )

    assert failures == []


async def test_hung_metric_discovery_fetch_is_bounded() -> None:
    references = (
        MetricReference("tracefence_active_nodes", "latest", "max"),
    )
    started = asyncio.Event()

    async def fetch() -> set[str]:
        started.set()
        await asyncio.Event().wait()
        return set()

    with pytest.raises(MetricDiscoveryError, match="bounded deadline"):
        await wait_for_metric_discovery(
            fetch,
            references,
            deadline_seconds=0,
            poll_seconds=0.1,
        )
    assert started.is_set()


def test_raw_query_forms_cannot_bypass_catalog_metric_validation() -> None:
    module = _load_provision_module()
    dashboard = _dashboard()
    dashboard["widgets"][0]["query"]["queryType"] = "promql"
    with pytest.raises(ValueError, match="catalog-validated builder"):
        module._validate_dashboard(dashboard)

    alerts = _alerts()
    alerts[0]["condition"]["compositeQuery"]["queries"][0]["type"] = "promql"
    with pytest.raises(ValueError, match="builder metric query"):
        module._validate_alerts(alerts)


def test_startup_metric_filter_requires_exact_expected_build_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_provision_module()
    monkeypatch.setenv("TRACEFENCE_BUILD_COMMIT", "b" * 40)

    assert ("tracefence.build.commit = '" + "b" * 40 + "'") in module._startup_metric_filter()

    monkeypatch.delenv("TRACEFENCE_BUILD_COMMIT")
    with pytest.raises(RuntimeError, match="TRACEFENCE_BUILD_COMMIT is required"):
        module._startup_metric_filter()


async def test_malformed_metric_catalog_stops_before_mutation_and_records_schema_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state: dict[str, object] = {
        "metrics": _startup_metrics(),
        "metric_catalog_payload": {"status": "success", "data": {"metrics": "invalid"}},
    }
    _install_fake_mcp(monkeypatch, state)
    module = _load_provision_module()

    @asynccontextmanager
    async def fake_http_client(_api_key: str):
        yield object()

    monkeypatch.setattr(module, "create_mcp_http_client", fake_http_client)
    monkeypatch.setenv("SIGNOZ_API_KEY", "test-key")
    dashboard_path = tmp_path / "dashboard.json"
    alerts_path = tmp_path / "alerts.json"
    evidence_path = tmp_path / "provisioning.json"
    dashboard_path.write_text(json.dumps(_dashboard()), encoding="utf-8")
    alerts_path.write_text(json.dumps(_alerts()), encoding="utf-8")

    with pytest.raises(RuntimeError, match="invalid metric catalog response"):
        await module.provision(
            dashboard_path,
            alerts_path,
            evidence_path,
            skip_alerts=True,
            update_existing=False,
        )

    assert state.get("mutation_called") is None
    saved = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert saved["metric_discovery_error_code"] == "MCP_METRIC_DISCOVERY_SCHEMA_ERROR"


def test_no_metric_discovery_zero_seeding_or_synthetic_failures_are_introduced() -> None:
    source = (ROOT / "src" / "tracefence" / "telemetry" / "instruments.py").read_text(
        encoding="utf-8"
    )

    assert ".add(" not in source
