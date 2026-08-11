from __future__ import annotations

import copy
import importlib
import importlib.util
import json
import sys
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from tracefence.telemetry.schema import extract_metric_references

ROOT = Path(__file__).resolve().parents[2]
CHANNEL = "test-tracefence-channel"
BUILD_COMMIT = "a" * 40


def _load_verify_module() -> ModuleType:
    path = ROOT / "scripts" / "verify_signoz.py"
    spec = importlib.util.spec_from_file_location("tracefence_verify_alerts", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dashboard() -> dict[str, Any]:
    dashboard = json.loads((ROOT / "observability" / "dashboard.json").read_text(encoding="utf-8"))
    assert isinstance(dashboard, dict)
    return copy.deepcopy(dashboard)


def _alerts() -> list[dict[str, Any]]:
    alerts = json.loads((ROOT / "observability" / "alerts.json").read_text(encoding="utf-8"))
    assert isinstance(alerts, list)
    assert all(isinstance(alert, dict) for alert in alerts)
    return copy.deepcopy(alerts)


def _validate_templates(alerts: object) -> dict[str, dict[str, Any]]:
    """Exercise the shared checked-in alert-template validation contract."""

    module = importlib.import_module("tracefence.signoz.alert_templates")
    validated = module.validate_alert_templates(
        alerts,
        channel_placeholder="${TRACEFENCE_NOTIFICATION_CHANNEL}",
    )
    assert isinstance(validated, dict)
    return validated


def _invalid_alert_templates(kind: str) -> list[dict[str, Any]]:
    alerts = _alerts()
    if kind == "missing":
        del alerts[0]["alert"]
    elif kind == "empty":
        alerts[0]["alert"] = ""
    elif kind == "whitespace":
        alerts[0]["alert"] = "   "
    elif kind == "non-string":
        alerts[0]["alert"] = 17
    elif kind == "duplicate":
        alerts[1]["alert"] = alerts[0]["alert"]
    elif kind == "malformed":
        del alerts[0]["condition"]
    else:
        raise AssertionError(f"unknown invalid-template kind: {kind}")
    return alerts


class _TextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


def _metric_catalog_result(metric_names: set[str]) -> SimpleNamespace:
    payload = {
        "status": "success",
        "data": {"metrics": [{"metricName": name} for name in sorted(metric_names)]},
    }
    note = "note: returned 0 rows (limit 100) -- all matching results returned (hasMore=false)."
    return SimpleNamespace(
        structuredContent=None,
        content=[_TextBlock(json.dumps(payload)), _TextBlock(note)],
        isError=False,
    )


@dataclass
class _VerifierState:
    module: ModuleType
    dashboard: dict[str, Any]
    alert_templates: list[dict[str, Any]]
    spec_digest: str
    channel: str = CHANNEL
    omitted_names: set[str] = field(default_factory=set)
    stale_names: set[str] = field(default_factory=set)
    tool_error_names: set[str] = field(default_factory=set)
    include_unrelated_rule: bool = False
    duplicate_deployed_name: str | None = None
    unexpected_alert_list_field: bool = False
    incidental_nested_name: str | None = None
    extra_unrelated_rule_count: int = 0
    inconsistent_total_on_second_page: bool = False
    invalid_next_offset: int | None = None
    duplicate_rule_id_on_second_page: bool = False
    digest_in_unrelated_nested_name: str | None = None
    mismatched_return_identity_name: str | None = None
    mismatched_return_rule_id_name: str | None = None
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    mutation_calls: list[str] = field(default_factory=list)
    probe_urls: list[str] = field(default_factory=list)
    probe_client_entries: int = 0
    mcp_transport_entries: int = 0
    mcp_http_client_entries: int = 0
    rule_ids: dict[str, str] = field(init=False)
    name_by_rule_id: dict[str, str] = field(init=False)
    observed_metrics: set[str] = field(init=False)

    def __post_init__(self) -> None:
        self.rule_ids = {
            alert["alert"]: f"rule-{index}"
            for index, alert in enumerate(self.alert_templates, start=1)
        }
        self.name_by_rule_id = {rule_id: name for name, rule_id in self.rule_ids.items()}
        if self.incidental_nested_name is not None:
            self.name_by_rule_id["incidental-rule"] = self.incidental_nested_name
        self.observed_metrics = {
            reference.name
            for reference in extract_metric_references(self.dashboard, self.alert_templates)
        }

    def expected_digest(self, name: str) -> str:
        template = next(alert for alert in self.alert_templates if alert["alert"] == name)
        return self.module._deployment_digest(template, self.channel, self.spec_digest)

    def deployed_names(self) -> list[str]:
        return [name for name in self.rule_ids if name not in self.omitted_names]


def _alert_summary(rule_id: str, alert_name: str) -> dict[str, Any]:
    """A complete direct AlertRuleSummary from the official list contract."""

    return {
        "ruleId": rule_id,
        "alert": alert_name,
        "alertType": "metric",
        "ruleType": "threshold_rule",
        "state": "inactive",
        "disabled": False,
    }


def _install_fake_runtime(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    state: _VerifierState,
    *,
    configure_channel: bool,
) -> None:
    monkeypatch.setenv("TRACEFENCE_BUILD_COMMIT", BUILD_COMMIT)
    monkeypatch.setenv("SIGNOZ_API_KEY", "unit-test-signoz-api-key")
    if configure_channel:
        monkeypatch.setenv("TRACEFENCE_NOTIFICATION_CHANNEL", state.channel)
    else:
        monkeypatch.delenv("TRACEFENCE_NOTIFICATION_CHANNEL", raising=False)

    class _ProbeClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> _ProbeClient:
            state.probe_client_entries += 1
            return self

        async def __aexit__(
            self,
            _exc_type: object,
            _exc: object,
            _traceback: object,
        ) -> bool:
            return False

        async def get(self, url: str) -> SimpleNamespace:
            state.probe_urls.append(url)
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(module.httpx, "AsyncClient", _ProbeClient)

    @asynccontextmanager
    async def fake_http_client(_api_key: str):
        state.mcp_http_client_entries += 1
        yield object()

    monkeypatch.setattr(module, "create_mcp_http_client", fake_http_client)

    class _FakeSession:
        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(
            self,
            _exc_type: object,
            _exc: object,
            _traceback: object,
        ) -> bool:
            return False

        async def initialize(self) -> None:
            return None

        async def list_tools(self) -> SimpleNamespace:
            names = set(module.REQUIRED_TOOLS) | {"signoz_get_alert"}
            return SimpleNamespace(
                tools=[SimpleNamespace(name=name) for name in sorted(names)]
            )

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> SimpleNamespace:
            state.calls.append((name, arguments))
            if name == "signoz_list_metrics":
                return _metric_catalog_result(state.observed_metrics)
            if name == "signoz_query_metrics":
                return SimpleNamespace(
                    structuredContent={
                        "results": [
                            {"metric_name": "tracefence_active_nodes", "value": 0.0}
                        ]
                    },
                    content=[],
                    isError=False,
                )
            if name == "signoz_list_dashboards":
                return SimpleNamespace(
                    structuredContent={
                        "dashboards": [
                            {"id": "dashboard-1", "title": module.DASHBOARD_TITLE}
                        ]
                    },
                    content=[],
                    isError=False,
                )
            if name == "signoz_get_dashboard":
                return SimpleNamespace(
                    structuredContent={
                        "id": "dashboard-1",
                        "title": module.DASHBOARD_TITLE,
                        "tags": [f"tracefence-spec:{state.spec_digest[:16]}"],
                    },
                    content=[],
                    isError=False,
                )
            if name == "signoz_list_alert_rules":
                rows = [
                    _alert_summary(state.rule_ids[title], title)
                    for title in state.deployed_names()
                ]
                if state.duplicate_deployed_name is not None:
                    rows.append(
                        _alert_summary("duplicate-rule", state.duplicate_deployed_name)
                    )
                    state.name_by_rule_id["duplicate-rule"] = state.duplicate_deployed_name
                if state.include_unrelated_rule:
                    rows.append(_alert_summary("unrelated-rule", "Unrelated alert"))
                rows.extend(
                    _alert_summary(f"unrelated-page-rule-{index}", f"Unrelated page alert {index}")
                    for index in range(state.extra_unrelated_rule_count)
                )
                offset = arguments.get("offset")
                limit = arguments.get("limit")
                assert type(offset) is int and type(limit) is int
                assert 0 <= offset and 1 <= limit <= 1000
                total = len(rows)
                page_rows = rows[offset : offset + limit]
                if state.duplicate_rule_id_on_second_page and offset > 0 and page_rows:
                    page_rows[0] = rows[0]
                has_more = offset + limit < total
                next_offset = offset + limit if has_more else -1
                payload: dict[str, Any] = {
                    "data": page_rows,
                    "pagination": {
                        "total": total,
                        "offset": offset,
                        "limit": limit,
                        "hasMore": has_more,
                        "nextOffset": next_offset,
                    },
                }
                if state.inconsistent_total_on_second_page and offset > 0:
                    payload["pagination"]["total"] = total + 1
                if state.invalid_next_offset is not None:
                    payload["pagination"]["nextOffset"] = state.invalid_next_offset
                if state.incidental_nested_name is not None:
                    payload["pagination"]["incidentalMetadata"] = {
                        "ruleId": "incidental-rule",
                        "alert": state.incidental_nested_name,
                    }
                if state.unexpected_alert_list_field:
                    payload["nextCursor"] = "unexpected"
                return SimpleNamespace(
                    structuredContent=payload, content=[], isError=False
                )
            if name == "signoz_get_alert":
                if set(arguments) != {"ruleId"}:
                    raise AssertionError(
                        "signoz_get_alert requires exactly the official ruleId argument"
                    )
                rule_id = arguments.get("ruleId")
                assert isinstance(rule_id, str)
                alert_name = state.name_by_rule_id[rule_id]
                if alert_name in state.tool_error_names:
                    return SimpleNamespace(structuredContent=None, content=[], isError=True)
                digest = (
                    "stale-deployment-digest"
                    if alert_name in state.stale_names
                    else state.expected_digest(alert_name)
                )
                returned_title = (
                    "Unexpected alert identity"
                    if alert_name == state.mismatched_return_identity_name
                    else alert_name
                )
                returned_rule_id = (
                    "unexpected-rule-id"
                    if alert_name == state.mismatched_return_rule_id_name
                    else rule_id
                )
                annotations = {"tracefence_deployment_digest": digest}
                payload = {
                    "ruleId": returned_rule_id,
                    "alert": returned_title,
                    "annotations": annotations,
                    "labels": {"tracefence_deployment": digest[:16]},
                }
                if alert_name == state.digest_in_unrelated_nested_name:
                    annotations["tracefence_deployment_digest"] = "stale-deployment-digest"
                    payload["audit"] = {
                        "tracefence_deployment_digest": state.expected_digest(alert_name)
                    }
                return SimpleNamespace(
                    structuredContent={"status": "success", "data": payload},
                    content=[],
                    isError=False,
                )
            if name.startswith(("signoz_create_", "signoz_update_", "signoz_delete_")):
                state.mutation_calls.append(name)
                raise AssertionError(f"verification must not mutate SigNoz with {name}")
            raise AssertionError(f"unexpected MCP tool call: {name}")

    @asynccontextmanager
    async def streamable_http_client(_url: str, *, http_client: object):
        assert http_client is not None
        state.mcp_transport_entries += 1
        yield object(), object(), lambda: "fake-session"

    class ClientSession:
        def __init__(self, _read_stream: object, _write_stream: object) -> None:
            self._session = _FakeSession()

        async def __aenter__(self) -> _FakeSession:
            return await self._session.__aenter__()

        async def __aexit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> bool:
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


async def _run_verify(
    monkeypatch: pytest.MonkeyPatch,
    alert_templates: list[dict[str, Any]],
    *,
    require_alerts: bool = True,
    configure_channel: bool = True,
    state_templates: list[dict[str, Any]] | None = None,
    omitted_names: set[str] | None = None,
    stale_names: set[str] | None = None,
    tool_error_names: set[str] | None = None,
    include_unrelated_rule: bool = False,
    duplicate_deployed_name: str | None = None,
    unexpected_alert_list_field: bool = False,
    incidental_nested_name: str | None = None,
    extra_unrelated_rule_count: int = 0,
    inconsistent_total_on_second_page: bool = False,
    invalid_next_offset: int | None = None,
    duplicate_rule_id_on_second_page: bool = False,
    digest_in_unrelated_nested_name: str | None = None,
    mismatched_return_identity_name: str | None = None,
    mismatched_return_rule_id_name: str | None = None,
) -> tuple[ModuleType, _VerifierState, int]:
    module = _load_verify_module()
    dashboard = _dashboard()
    spec_digest = module._json_digest({"dashboard": dashboard, "alerts": alert_templates})
    fake_templates = state_templates if state_templates is not None else alert_templates
    fake_spec_digest = module._json_digest({"dashboard": dashboard, "alerts": fake_templates})
    state = _VerifierState(
        module=module,
        dashboard=dashboard,
        alert_templates=fake_templates,
        spec_digest=fake_spec_digest,
        omitted_names=set() if omitted_names is None else omitted_names,
        stale_names=set() if stale_names is None else stale_names,
        tool_error_names=set() if tool_error_names is None else tool_error_names,
        include_unrelated_rule=include_unrelated_rule,
        duplicate_deployed_name=duplicate_deployed_name,
        unexpected_alert_list_field=unexpected_alert_list_field,
        incidental_nested_name=incidental_nested_name,
        extra_unrelated_rule_count=extra_unrelated_rule_count,
        inconsistent_total_on_second_page=inconsistent_total_on_second_page,
        invalid_next_offset=invalid_next_offset,
        duplicate_rule_id_on_second_page=duplicate_rule_id_on_second_page,
        digest_in_unrelated_nested_name=digest_in_unrelated_nested_name,
        mismatched_return_identity_name=mismatched_return_identity_name,
        mismatched_return_rule_id_name=mismatched_return_rule_id_name,
    )
    monkeypatch.setattr(
        module,
        "_local_spec",
        lambda: (spec_digest, copy.deepcopy(dashboard), copy.deepcopy(alert_templates)),
    )
    module.METRIC_DISCOVERY_DEADLINE_SECONDS = 0
    module.METRIC_DISCOVERY_POLL_SECONDS = 0.1
    _install_fake_runtime(
        monkeypatch,
        module,
        state,
        configure_channel=configure_channel,
    )
    result = await module.verify(
        "https://unit.test/signoz",
        "https://unit.test/mcp",
        require_alerts=require_alerts,
        proof_bundle=None,
        evidence_signing_key=None,
    )
    return module, state, result


def _fetched_alert_names(state: _VerifierState) -> list[str]:
    return [
        state.name_by_rule_id[arguments["ruleId"]]
        for name, arguments in state.calls
        if name == "signoz_get_alert"
    ]


def _assert_read_only(state: _VerifierState) -> None:
    assert state.mutation_calls == []
    assert not any(
        name.startswith(("signoz_create_", "signoz_update_", "signoz_delete_"))
        for name, _arguments in state.calls
    )


def _alert_rule_page(
    rows: list[dict[str, Any]],
    *,
    total: int | None = None,
    offset: int = 0,
    limit: int = 1000,
    has_more: bool = False,
    next_offset: int = -1,
) -> dict[str, Any]:
    return {
        "data": rows,
        "pagination": {
            "total": len(rows) if total is None else total,
            "offset": offset,
            "limit": limit,
            "hasMore": has_more,
            "nextOffset": next_offset,
        },
    }


def test_official_alert_rule_page_contract_is_accepted() -> None:
    module = _load_verify_module()
    payload = _alert_rule_page([_alert_summary("rule-1", "TraceFence Example")])

    page = module._parse_alert_rule_page(payload)

    assert page.rows == ({"id": "rule-1", "title": "TraceFence Example"},)
    assert page.total == 1
    assert page.offset == 0
    assert page.limit == 1000
    assert page.has_more is False
    assert page.next_offset == -1


@pytest.mark.parametrize(
    ("mutate", "expected_message"),
    [
        (lambda payload: payload.__setitem__("nextCursor", "unexpected"), "unexpected fields"),
        (lambda payload: payload.__setitem__("data", {}), "data must be an array"),
        (lambda payload: payload["pagination"].__setitem__("total", True), "total must be an integer"),
        (lambda payload: payload["pagination"].pop("offset"), "missing required fields"),
        (lambda payload: payload["pagination"].__setitem__("limit", 0), "limit must be between"),
        (lambda payload: payload["pagination"].__setitem__("nextOffset", 0), "final.*page"),
        (lambda payload: payload["data"][0].__setitem__("unexpected", "field"), "unexpected fields"),
        (lambda payload: payload["data"][0].__delitem__("alertType"), "missing required fields"),
    ],
)
def test_official_alert_rule_page_contract_rejects_malformed_values(
    mutate: Any,
    expected_message: str,
) -> None:
    module = _load_verify_module()
    payload = _alert_rule_page([_alert_summary("rule-1", "TraceFence Example")])
    mutate(payload)

    with pytest.raises(module._AlertRuleResponseSchemaError, match=expected_message):
        module._parse_alert_rule_page(payload)


def test_incomplete_official_alert_rule_page_requires_a_valid_next_offset() -> None:
    module = _load_verify_module()
    payload = _alert_rule_page(
        [_alert_summary(f"rule-{index}", f"TraceFence {index}") for index in range(1000)],
        total=1001,
        has_more=True,
        next_offset=0,
    )

    with pytest.raises(module._AlertRuleResponseSchemaError, match="nextOffset"):
        module._parse_alert_rule_page(payload)


def test_shared_template_validator_derives_the_checked_in_alert_names() -> None:
    alerts = _alerts()

    templates_by_name = _validate_templates(alerts)

    assert set(templates_by_name) == {alert["alert"] for alert in alerts}
    assert len(templates_by_name) == 6


@pytest.mark.parametrize(
    "kind",
    ("missing", "empty", "whitespace", "non-string", "duplicate", "malformed"),
)
def test_shared_template_validator_rejects_invalid_checked_in_alert_shapes(kind: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        _validate_templates(_invalid_alert_templates(kind))


@pytest.mark.parametrize(
    "kind",
    ("missing", "empty", "non-string", "duplicate", "malformed"),
)
async def test_invalid_alert_templates_fail_before_http_or_mcp_access(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    invalid_templates = _invalid_alert_templates(kind)
    _module, state, result = await _run_verify(
        monkeypatch,
        invalid_templates,
        state_templates=_alerts(),
    )

    assert result == 1
    assert state.probe_client_entries == 0
    assert state.probe_urls == []
    assert state.mcp_http_client_entries == 0
    assert state.mcp_transport_entries == 0
    assert state.calls == []
    _assert_read_only(state)


async def test_verifier_fetches_and_reports_every_checked_in_alert(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alerts = _alerts()
    expected_names = {alert["alert"] for alert in alerts}

    _module, state, result = await _run_verify(monkeypatch, alerts)

    assert result == 0
    assert Counter(_fetched_alert_names(state)) == Counter({name: 1 for name in expected_names})
    assert [name for name, _arguments in state.calls].count("signoz_list_alert_rules") == 1
    output = capsys.readouterr().out
    for name in expected_names:
        assert f"PASS Alert {name}" in output
    _assert_read_only(state)


async def test_verifier_uses_the_exact_official_rule_id_get_alert_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()
    expected_names = {alert["alert"] for alert in alerts}

    _module, state, result = await _run_verify(monkeypatch, alerts)

    get_alert_calls = [
        arguments
        for name, arguments in state.calls
        if name == "signoz_get_alert"
    ]
    assert result == 0
    assert len(get_alert_calls) == len(expected_names)
    assert all(set(arguments) == {"ruleId"} for arguments in get_alert_calls)
    assert {arguments["ruleId"] for arguments in get_alert_calls} == set(
        state.rule_ids.values()
    )
    assert all("id" not in arguments for arguments in get_alert_calls)
    _assert_read_only(state)


async def test_a_seventh_valid_checked_in_alert_is_automatically_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()
    seventh = copy.deepcopy(alerts[0])
    seventh["alert"] = "TraceFence Additional Test Alert"
    alerts.append(seventh)
    expected_names = {alert["alert"] for alert in alerts}

    _module, state, result = await _run_verify(monkeypatch, alerts)

    assert result == 0
    assert len(expected_names) == 7
    assert Counter(_fetched_alert_names(state)) == Counter({name: 1 for name in expected_names})
    _assert_read_only(state)


async def test_missing_one_deployed_alert_fails_and_does_not_hide_the_omission(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alerts = _alerts()
    expected_names = {alert["alert"] for alert in alerts}
    missing_name = alerts[-1]["alert"]

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        omitted_names={missing_name},
    )

    assert result == 1
    assert missing_name in capsys.readouterr().err
    assert Counter(_fetched_alert_names(state)) == Counter(
        {name: 1 for name in expected_names - {missing_name}}
    )
    _assert_read_only(state)


async def test_stale_deployment_digest_for_one_alert_fails_after_fetching_all(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alerts = _alerts()
    expected_names = {alert["alert"] for alert in alerts}
    stale_name = alerts[-1]["alert"]

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        stale_names={stale_name},
    )

    assert result == 1
    assert stale_name in capsys.readouterr().err
    assert Counter(_fetched_alert_names(state)) == Counter({name: 1 for name in expected_names})
    _assert_read_only(state)


async def test_get_alert_mcp_error_for_one_alert_fails_after_fetching_all(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alerts = _alerts()
    expected_names = {alert["alert"] for alert in alerts}
    failed_name = alerts[-1]["alert"]

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        tool_error_names={failed_name},
    )

    assert result == 1
    assert failed_name in capsys.readouterr().err
    assert Counter(_fetched_alert_names(state)) == Counter({name: 1 for name in expected_names})
    _assert_read_only(state)


async def test_unrelated_deployed_alert_is_ignored_without_reducing_required_fetches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()
    expected_names = {alert["alert"] for alert in alerts}

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        include_unrelated_rule=True,
    )

    assert result == 0
    assert Counter(_fetched_alert_names(state)) == Counter({name: 1 for name in expected_names})
    assert "Unrelated alert" not in _fetched_alert_names(state)
    _assert_read_only(state)


async def test_duplicate_deployed_expected_title_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        duplicate_deployed_name=alerts[0]["alert"],
    )

    assert result == 1
    _assert_read_only(state)


async def test_offset_pagination_fetches_all_pages_before_alerts_are_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()
    expected_names = {alert["alert"] for alert in alerts}

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        extra_unrelated_rule_count=1000,
    )

    assert result == 0
    list_calls = [arguments for name, arguments in state.calls if name == "signoz_list_alert_rules"]
    assert list_calls == [{"limit": 1000, "offset": 0}, {"limit": 1000, "offset": 1000}]
    assert Counter(_fetched_alert_names(state)) == Counter({name: 1 for name in expected_names})
    _assert_read_only(state)


async def test_inconsistent_offset_page_total_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alerts = _alerts()
    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        extra_unrelated_rule_count=1000,
        inconsistent_total_on_second_page=True,
    )

    assert result == 1
    stderr = capsys.readouterr().err
    for alert in alerts:
        assert alert["alert"] in stderr
    _assert_read_only(state)


async def test_non_progressing_offset_page_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alerts = _alerts()
    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        extra_unrelated_rule_count=1000,
        invalid_next_offset=0,
    )

    assert result == 1
    stderr = capsys.readouterr().err
    for alert in alerts:
        assert alert["alert"] in stderr
    assert _fetched_alert_names(state) == []
    _assert_read_only(state)


async def test_duplicate_alert_rule_id_across_offset_pages_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alerts = _alerts()
    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        extra_unrelated_rule_count=1000,
        duplicate_rule_id_on_second_page=True,
    )

    assert result == 1
    assert "duplicate alert-rule ruleId across pages" in capsys.readouterr().err
    assert _fetched_alert_names(state) == []
    _assert_read_only(state)


async def test_unexpected_alert_rule_list_field_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alerts = _alerts()
    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        unexpected_alert_list_field=True,
    )

    assert result == 1
    stderr = capsys.readouterr().err
    for alert in alerts:
        assert alert["alert"] in stderr
    assert _fetched_alert_names(state) == []
    _assert_read_only(state)


async def test_incidental_nested_alert_metadata_cannot_satisfy_rule_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()
    expected_name = alerts[-1]["alert"]

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        omitted_names={expected_name},
        incidental_nested_name=expected_name,
    )

    assert result == 1
    _assert_read_only(state)


async def test_nested_digest_cannot_satisfy_alert_deployment_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()
    expected_name = alerts[-1]["alert"]

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        digest_in_unrelated_nested_name=expected_name,
    )

    assert result == 1
    _assert_read_only(state)


async def test_get_alert_identity_must_match_the_listed_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()
    expected_name = alerts[-1]["alert"]

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        mismatched_return_identity_name=expected_name,
    )

    assert result == 1
    _assert_read_only(state)


async def test_get_alert_rule_id_must_match_the_listed_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()
    expected_name = alerts[-1]["alert"]

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        mismatched_return_rule_id_name=expected_name,
    )

    assert result == 1
    _assert_read_only(state)


async def test_alert_verification_disabled_does_not_read_or_mutate_alert_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alerts = _alerts()

    _module, state, result = await _run_verify(
        monkeypatch,
        alerts,
        require_alerts=False,
        configure_channel=False,
    )

    assert result == 0
    assert not any(
        name in {"signoz_list_alert_rules", "signoz_get_alert"}
        for name, _arguments in state.calls
    )
    _assert_read_only(state)
