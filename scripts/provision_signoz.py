from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
from collections.abc import Iterator
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from tracefence.evidence import _atomic_private_write
from tracefence.signoz.alert_templates import (
    ALERT_CHANNEL_PLACEHOLDER,
    validate_alert_templates,
)
from tracefence.signoz.mcp_client import (
    MCPToolResultError,
    ResponseSchemaError,
    normalize_metric_catalog_names,
    normalize_metric_query_values,
)
from tracefence.signoz.mcp_transport import create_mcp_http_client
from tracefence.telemetry.schema import (
    MetricDiscoveryError,
    MetricDiscoveryObservation,
    MetricPreflight,
    MetricReference,
    extract_metric_references,
    validate_metric_references,
    wait_for_metric_discovery,
)

DASHBOARD_TITLE = "TraceFence Control Integrity"
REQUIRED_TOOLS = {
    "signoz_list_metrics",
    "signoz_query_metrics",
    "signoz_list_dashboards",
    "signoz_get_dashboard",
    "signoz_create_dashboard",
    "signoz_list_alert_rules",
    "signoz_get_alert",
    "signoz_list_notification_channels",
    "signoz_create_alert",
}
RESOURCE_URIS = (
    "signoz://dashboard/instructions",
    "signoz://dashboard/widgets-instructions",
    "signoz://dashboard/widgets-examples",
    "signoz://dashboard/query-builder-example",
    "signoz://alert/instructions",
    "signoz://alert/examples",
)
METRIC_DISCOVERY_DEADLINE_SECONDS = 60.0
METRIC_DISCOVERY_POLL_SECONDS = 2.0
_STARTUP_SIGNAL_METRIC = "tracefence_active_nodes"
_BUILD_COMMIT_PATTERN = re.compile(r"^[0-9A-Za-z._-]{7,128}$")


class _MetricDiscoverySchemaError(RuntimeError):
    """A metric-discovery response was syntactically unsafe to trust."""


def _json_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _normalize_result(result: Any) -> Any:
    """Normalize MCP call-tool and read-resource results without guessing text.

    The Python SDK exposes call-tool payloads through ``content`` and resource
    payloads through ``contents``. Pydantic result models are converted first so
    both current and older SDK naming conventions are handled consistently.
    """

    if hasattr(result, "model_dump"):
        try:
            dumped = result.model_dump(mode="python", by_alias=True)
        except TypeError:
            dumped = result.model_dump()
        if isinstance(dumped, dict):
            structured = dumped.get("structuredContent") or dumped.get("structured_content")
            if structured is not None:
                return structured
            if "contents" in dumped:
                return _normalize_content_items(dumped["contents"])
            if "content" in dumped:
                return _normalize_content_items(dumped["content"])
            return dumped

    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if structured is not None:
        return structured

    contents = getattr(result, "contents", None)
    if contents is not None:
        return _normalize_content_items(contents)
    content = getattr(result, "content", result)
    return _normalize_content_items(content)


def _normalize_content_items(content: Any) -> Any:
    if isinstance(content, list):
        items = [_normalize_content_item(item) for item in content]
        return items[0] if len(items) == 1 else items
    return _normalize_content_item(content)


def _normalize_content_item(item: Any) -> Any:
    if hasattr(item, "model_dump"):
        try:
            item = item.model_dump(mode="python", by_alias=True)
        except TypeError:
            item = item.model_dump()
    if isinstance(item, dict):
        text = item.get("text")
        if isinstance(text, str):
            return _parse_json_or_text(text)
        blob = item.get("blob")
        if isinstance(blob, str):
            return blob
        return {key: _normalize_content_item(value) for key, value in item.items()}
    text = getattr(item, "text", None)
    if isinstance(text, str):
        return _parse_json_or_text(text)
    return item


def _parse_json_or_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _result_text(result: Any) -> str:
    value = _normalize_result(result)
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)


def _tool_failed(result: Any) -> bool:
    if bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
        return True
    normalized = _normalize_result(result)
    if isinstance(normalized, dict) and bool(
        normalized.get("isError") or normalized.get("is_error")
    ):
        return True
    text = _result_text(result).lower()
    return any(
        marker in text
        for marker in (
            "validation error",
            "validation_failed",
            '"code":"validation',
            '"status":"error"',
            "upstream error",
        )
    )


def _walk(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


def _collect_strings(value: Any, keys: set[str]) -> set[str]:
    found: set[str] = set()
    for item in _walk(value):
        for key in keys:
            candidate = item.get(key)
            if isinstance(candidate, str) and candidate.strip():
                found.add(candidate.strip())
    return found


def _extract_ids(value: Any) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in _walk(value):
        identifier = item.get("id") or item.get("uuid") or item.get("ruleId")
        title = item.get("title") or item.get("name") or item.get("alert")
        if isinstance(identifier, str) and isinstance(title, str):
            rows.append({"id": identifier, "title": title})
    return rows


def _validate_dashboard(dashboard: dict[str, Any]) -> None:
    required = {"title", "layout", "widgets"}
    missing = sorted(required - dashboard.keys())
    if missing:
        raise ValueError(f"Dashboard is missing fields: {', '.join(missing)}")
    if dashboard["title"] != DASHBOARD_TITLE:
        raise ValueError(f"Dashboard title must be {DASHBOARD_TITLE!r}")
    widgets = dashboard["widgets"]
    layout = dashboard["layout"]
    if not isinstance(widgets, list) or not widgets:
        raise ValueError("Dashboard must contain at least one widget")
    widget_ids = [widget.get("id") for widget in widgets]
    if len(widget_ids) != len(set(widget_ids)) or any(not item for item in widget_ids):
        raise ValueError("Dashboard widget IDs must be non-empty and unique")
    layout_ids = [item.get("i") for item in layout]
    if set(layout_ids) != set(widget_ids):
        raise ValueError("Every widget must have exactly one matching layout item")
    for item in layout:
        if not all(isinstance(item.get(key), int) for key in ("x", "y", "w", "h")):
            raise ValueError("Dashboard layout coordinates must be integers")
        if item["x"] < 0 or item["w"] <= 0 or item["x"] + item["w"] > 12:
            raise ValueError(f"Widget {item.get('i')} exceeds the 12-column dashboard grid")
    for widget in widgets:
        if widget.get("panelTypes") not in {
            "graph", "value", "table", "list", "trace", "bar", "pie", "histogram", "row"
        }:
            raise ValueError(f"Unsupported panel type on {widget.get('id')}")
        query = widget.get("query")
        if not isinstance(query, dict) or query.get("queryType") != "builder":
            raise ValueError(
                f"Widget {widget.get('id')} must use the catalog-validated builder query envelope"
            )


def _validate_alerts(alerts: list[dict[str, Any]]) -> None:
    validate_alert_templates(alerts)


def _metric_references(
    dashboard: dict[str, Any], alerts: list[dict[str, Any]]
) -> tuple[MetricReference, ...]:
    references = extract_metric_references(dashboard, alerts)
    validate_metric_references(references)
    return references


def _substitute_channel(value: Any, channel: str) -> Any:
    if isinstance(value, dict):
        return {key: _substitute_channel(item, channel) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute_channel(item, channel) for item in value]
    return channel if value == ALERT_CHANNEL_PLACEHOLDER else value


def _prepare_alert_payload(
    template: dict[str, Any], channel: str, spec_digest: str
) -> tuple[dict[str, Any], str]:
    payload = _substitute_channel(json.loads(json.dumps(template)), channel)
    deployment_digest = _json_digest(
        {"spec_digest": spec_digest, "channel": channel, "alert": payload}
    )
    payload.setdefault("labels", {})["tracefence_spec"] = spec_digest[:16]
    payload["labels"]["tracefence_deployment"] = deployment_digest[:16]
    payload.setdefault("annotations", {})["tracefence_spec_digest"] = spec_digest
    payload["annotations"]["tracefence_deployment_digest"] = deployment_digest
    return payload, deployment_digest


async def _read_resources(session: Any) -> dict[str, str]:
    resources: dict[str, str] = {}
    for uri in RESOURCE_URIS:
        try:
            result = await session.read_resource(uri)
            text = _result_text(result)
            resources[uri] = hashlib.sha256(text.encode()).hexdigest()
        except Exception as exc:
            # The tool schemas still provide strict validation. Resource absence is
            # recorded and treated as a provisioning warning rather than hidden.
            resources[uri] = f"UNAVAILABLE:{type(exc).__name__}:{exc}"
    return resources


async def _list_tracefence_metric_names(session: Any) -> set[str]:
    result = await session.call_tool(
        "signoz_list_metrics",
        arguments={"searchText": "tracefence_", "limit": 100, "timeRange": "1h"},
    )
    if _tool_failed(result):
        raise RuntimeError("signoz_list_metrics returned an MCP error")
    try:
        return normalize_metric_catalog_names(result)
    except (MCPToolResultError, ResponseSchemaError) as exc:
        raise _MetricDiscoverySchemaError(
            "signoz_list_metrics returned an invalid metric catalog response"
        ) from exc


def _required_build_commit() -> str:
    build_commit = os.getenv("TRACEFENCE_BUILD_COMMIT", "").strip()
    if not _BUILD_COMMIT_PATTERN.fullmatch(build_commit):
        raise RuntimeError(
            "TRACEFENCE_BUILD_COMMIT is required and must be a safe build identity "
            "for SigNoz metric discovery"
        )
    return build_commit


def _startup_metric_filter() -> str:
    return (
        "service.name = 'tracefence-control-plane' AND "
        f"tracefence.build.commit = '{_required_build_commit()}'"
    )


async def _current_startup_metric_query_succeeded(session: Any) -> bool:
    result = await session.call_tool(
        "signoz_query_metrics",
        arguments={
            "searchContext": "TraceFence current startup telemetry preflight",
            "metricName": _STARTUP_SIGNAL_METRIC,
            "metricType": "gauge",
            "isMonotonic": False,
            "temporality": "unspecified",
            "timeAggregation": "latest",
            "spaceAggregation": "max",
            "requestType": "scalar",
            "reduceTo": "last",
            "timeRange": "5m",
            "filter": _startup_metric_filter(),
        },
    )
    if _tool_failed(result):
        raise RuntimeError("signoz_query_metrics returned an MCP error")
    try:
        return bool(
            normalize_metric_query_values(
                result,
                expected_metric_name=_STARTUP_SIGNAL_METRIC,
            )
        )
    except (MCPToolResultError, ResponseSchemaError) as exc:
        raise _MetricDiscoverySchemaError(
            "signoz_query_metrics returned an invalid startup telemetry response"
        ) from exc


async def _preflight_metric_discovery(
    session: Any, references: tuple[MetricReference, ...]
) -> MetricPreflight:
    async def fetch() -> MetricDiscoveryObservation:
        metric_names = await _list_tracefence_metric_names(session)
        live_metric_query_succeeded = await _current_startup_metric_query_succeeded(session)
        return MetricDiscoveryObservation(
            observed_metric_names=frozenset(metric_names),
            live_metric_query_succeeded=live_metric_query_succeeded,
        )

    return await wait_for_metric_discovery(
        fetch,
        references,
        deadline_seconds=METRIC_DISCOVERY_DEADLINE_SECONDS,
        poll_seconds=METRIC_DISCOVERY_POLL_SECONDS,
    )


def _record_metric_preflight(evidence: dict[str, Any], preflight: MetricPreflight) -> None:
    evidence.update(preflight.as_evidence())


def _write_evidence(evidence_path: Path, evidence: dict[str, Any]) -> None:
    _atomic_private_write(
        evidence_path,
        (json.dumps(evidence, indent=2, default=str) + "\n").encode("utf-8"),
    )


async def provision(
    dashboard_path: Path,
    alerts_path: Path,
    evidence_path: Path,
    *,
    skip_alerts: bool,
    update_existing: bool,
) -> int:
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError:
        print("FAIL Install the optional MCP dependency: pip install -e '.[mcp]'", file=sys.stderr)
        return 1

    api_key = os.getenv("SIGNOZ_API_KEY", "").strip()
    if not api_key:
        print("FAIL SIGNOZ_API_KEY is required", file=sys.stderr)
        return 1
    _required_build_commit()
    channel = os.getenv("TRACEFENCE_NOTIFICATION_CHANNEL", "").strip()
    if not skip_alerts and not channel:
        print(
            "FAIL TRACEFENCE_NOTIFICATION_CHANNEL must name an existing SigNoz channel "
            "(or pass --skip-alerts)",
            file=sys.stderr,
        )
        return 1

    mcp_url = os.getenv("SIGNOZ_MCP_URL", "http://localhost:8000/mcp")
    dashboard_text, alerts_text = await asyncio.gather(
        asyncio.to_thread(dashboard_path.read_text),
        asyncio.to_thread(alerts_path.read_text),
    )
    dashboard = json.loads(dashboard_text)
    alerts = json.loads(alerts_text)
    _validate_dashboard(dashboard)
    _validate_alerts(alerts)
    metric_references = _metric_references(dashboard, alerts)

    spec_digest = _json_digest({"dashboard": dashboard, "alerts": alerts})
    dashboard = json.loads(json.dumps(dashboard))
    dashboard.setdefault("tags", []).append(f"tracefence-spec:{spec_digest[:16]}")
    evidence: dict[str, Any] = {
        "mcp_url": mcp_url,
        "spec_digest": spec_digest,
        "dashboard": {},
        "alerts": [],
        "resources": {},
    }

    async with AsyncExitStack() as stack:
        http_client = await stack.enter_async_context(create_mcp_http_client(api_key))
        streams = await stack.enter_async_context(
            streamable_http_client(mcp_url, http_client=http_client)
        )
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = {tool.name: tool for tool in listed.tools}
            required = set(REQUIRED_TOOLS)
            if skip_alerts:
                required -= {
                    "signoz_list_alert_rules",
                    "signoz_get_alert",
                    "signoz_list_notification_channels",
                    "signoz_create_alert",
                }
            missing = sorted(required - tools.keys())
            if missing:
                raise RuntimeError(f"Missing SigNoz MCP tools: {', '.join(missing)}")
            evidence["available_tools"] = sorted(tools)
            evidence["resources"] = await _read_resources(session)
            try:
                metric_preflight = await _preflight_metric_discovery(session, metric_references)
            except MetricDiscoveryError:
                evidence["metric_discovery_error_code"] = (
                    "METRIC_DISCOVERY_DEADLINE_EXCEEDED"
                )
                _write_evidence(evidence_path, evidence)
                raise
            except _MetricDiscoverySchemaError:
                evidence["metric_discovery_error_code"] = "MCP_METRIC_DISCOVERY_SCHEMA_ERROR"
                _write_evidence(evidence_path, evidence)
                raise
            except RuntimeError:
                evidence["metric_discovery_error_code"] = "MCP_METRIC_DISCOVERY_FAILED"
                _write_evidence(evidence_path, evidence)
                raise
            _record_metric_preflight(evidence, metric_preflight)
            if metric_preflight.startup_required_missing:
                _write_evidence(evidence_path, evidence)
                raise RuntimeError(
                    "startup telemetry is not visible; missing startup-required metrics: "
                    + ", ".join(metric_preflight.startup_required_missing)
                )
            if not metric_preflight.live_metric_query_succeeded:
                _write_evidence(evidence_path, evidence)
                raise RuntimeError(
                    "startup telemetry is not visible; the current TraceFence metric query "
                    "returned no data"
                )
            if metric_preflight.event_driven_not_yet_observed:
                print(
                    "INFO Declared event-driven metrics have not emitted yet: "
                    + ", ".join(metric_preflight.event_driven_not_yet_observed)
                )
            if metric_preflight.failure_only_not_yet_observed:
                print(
                    "INFO Declared failure-only metrics are absent as expected: "
                    + ", ".join(metric_preflight.failure_only_not_yet_observed)
                )

            dashboard_list = await session.call_tool(
                "signoz_list_dashboards", arguments={"limit": "1000", "offset": "0"}
            )
            existing_dashboards = _extract_ids(_normalize_result(dashboard_list))
            current = next(
                (row for row in existing_dashboards if row["title"] == dashboard["title"]), None
            )
            if current is None:
                result = await session.call_tool(
                    "signoz_create_dashboard",
                    arguments={
                        **dashboard,
                        "searchContext": "Provision the version-controlled TraceFence control integrity dashboard exactly as supplied.",
                    },
                )
                if _tool_failed(result):
                    raise RuntimeError(f"Dashboard creation failed: {_result_text(result)}")
                evidence["dashboard"] = {"status": "created", "result": _normalize_result(result)}
            elif update_existing:
                if "signoz_update_dashboard" not in tools:
                    raise RuntimeError("signoz_update_dashboard is required for --update-existing")
                result = await session.call_tool(
                    "signoz_update_dashboard",
                    arguments={
                        "id": current["id"],
                        "dashboard": dashboard,
                        "searchContext": "Replace the existing TraceFence dashboard with the supplied version-controlled definition.",
                    },
                )
                if _tool_failed(result):
                    raise RuntimeError(f"Dashboard update failed: {_result_text(result)}")
                evidence["dashboard"] = {
                    "status": "updated", "id": current["id"], "result": _normalize_result(result)
                }
            else:
                existing_full = await session.call_tool(
                    "signoz_get_dashboard", arguments={"id": current["id"]}
                )
                existing_text = _result_text(existing_full)
                tag = f"tracefence-spec:{spec_digest[:16]}"
                if tag not in existing_text:
                    raise RuntimeError(
                        "A TraceFence dashboard already exists with a different spec. "
                        "Re-run with --update-existing after reviewing the diff."
                    )
                evidence["dashboard"] = {"status": "unchanged", "id": current["id"]}

            if not skip_alerts:
                channels_result = await session.call_tool(
                    "signoz_list_notification_channels", arguments={"limit": "1000", "offset": "0"}
                )
                channel_names = _collect_strings(
                    _normalize_result(channels_result), {"name", "channelName", "channel_name"}
                )
                if channel not in channel_names:
                    raise RuntimeError(
                        f"Notification channel {channel!r} does not exist. Available: "
                        + ", ".join(sorted(channel_names))
                    )

                rules_result = await session.call_tool(
                    "signoz_list_alert_rules", arguments={"limit": 1000, "offset": 0}
                )
                existing_rules = _extract_ids(_normalize_result(rules_result))
                for template in alerts:
                    payload, deployment_digest = _prepare_alert_payload(
                        template, channel, spec_digest
                    )
                    current_rule = next(
                        (row for row in existing_rules if row["title"] == payload["alert"]), None
                    )
                    if current_rule is not None and not update_existing:
                        current_full = await session.call_tool(
                            "signoz_get_alert", arguments={"ruleId": current_rule["id"]}
                        )
                        if _tool_failed(current_full):
                            raise RuntimeError(
                                f"Could not inspect existing alert {payload['alert']}: "
                                f"{_result_text(current_full)}"
                            )
                        if deployment_digest not in _result_text(current_full):
                            raise RuntimeError(
                                f"Alert {payload['alert']!r} already exists with a different "
                                "deployed payload or notification channel. Re-run with "
                                "--update-existing after reviewing the diff."
                            )
                        evidence["alerts"].append(
                            {
                                "name": payload["alert"],
                                "status": "unchanged",
                                "id": current_rule["id"],
                                "deployment_digest": deployment_digest,
                            }
                        )
                        continue
                    if current_rule is not None:
                        if "signoz_update_alert" not in tools:
                            raise RuntimeError("signoz_update_alert is required for --update-existing")
                        tool_name = "signoz_update_alert"
                        arguments = {"ruleId": current_rule["id"], **payload}
                        status = "updated"
                    else:
                        tool_name = "signoz_create_alert"
                        arguments = payload
                        status = "created"
                    arguments["searchContext"] = (
                        "Provision TraceFence safety alerts from the checked-in v2alpha1 definitions "
                        "using the already verified notification channel."
                    )
                    result = await session.call_tool(tool_name, arguments=arguments)
                    if _tool_failed(result):
                        raise RuntimeError(
                            f"Alert {payload['alert']} {status} failed: {_result_text(result)}"
                        )
                    evidence["alerts"].append(
                        {
                            "name": payload["alert"],
                            "status": status,
                            "deployment_digest": deployment_digest,
                            "result": _normalize_result(result),
                        }
                    )

    _write_evidence(evidence_path, evidence)
    print(f"PASS Dashboard: {evidence['dashboard']['status']}")
    for alert in evidence["alerts"]:
        print(f"PASS Alert {alert['name']}: {alert['status']}")
    print(f"PASS Wrote provisioning evidence to {evidence_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dashboard", type=Path, default=Path("observability/dashboard.json"))
    parser.add_argument("--alerts", type=Path, default=Path("observability/alerts.json"))
    parser.add_argument(
        "--evidence", type=Path, default=Path("evidence/signoz-provisioning.json")
    )
    parser.add_argument("--skip-alerts", action="store_true")
    parser.add_argument("--update-existing", action="store_true")
    args = parser.parse_args()
    try:
        return asyncio.run(
            provision(
                args.dashboard,
                args.alerts,
                args.evidence,
                skip_alerts=args.skip_alerts,
                update_existing=args.update_existing,
            )
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
