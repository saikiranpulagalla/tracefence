from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

DASHBOARD_TITLE = "TraceFence Control Integrity"
ALERT_CHANNEL_TOKEN = "${TRACEFENCE_NOTIFICATION_CHANNEL}"
REQUIRED_TOOLS = {
    "signoz_list_metrics",
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
        if not isinstance(query, dict) or query.get("queryType") not in {
            "builder", "promql", "clickhouse_sql"
        }:
            raise ValueError(f"Widget {widget.get('id')} has no valid query envelope")


def _validate_alerts(alerts: list[dict[str, Any]]) -> None:
    if not alerts:
        raise ValueError("At least one alert template is required")
    names: set[str] = set()
    for alert in alerts:
        for field in (
            "alert", "alertType", "ruleType", "version", "schemaVersion", "condition",
            "evaluation", "notificationSettings", "labels", "annotations",
        ):
            if field not in alert:
                raise ValueError(f"Alert {alert.get('alert', '<unknown>')} is missing {field}")
        name = alert["alert"]
        if name in names:
            raise ValueError(f"Duplicate alert name: {name}")
        names.add(name)
        if alert["ruleType"] != "threshold_rule" or alert["schemaVersion"] != "v2alpha1":
            raise ValueError(f"Alert {name} must use the v2alpha1 threshold-rule schema")
        thresholds = alert["condition"].get("thresholds", {}).get("spec", [])
        if not thresholds:
            raise ValueError(f"Alert {name} has no threshold tier")
        if not any(ALERT_CHANNEL_TOKEN in tier.get("channels", []) for tier in thresholds):
            raise ValueError(f"Alert {name} must use the notification-channel placeholder")


def _substitute_channel(value: Any, channel: str) -> Any:
    if isinstance(value, dict):
        return {key: _substitute_channel(item, channel) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute_channel(item, channel) for item in value]
    return channel if value == ALERT_CHANNEL_TOKEN else value


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
    channel = os.getenv("TRACEFENCE_NOTIFICATION_CHANNEL", "").strip()
    if not skip_alerts and not channel:
        print(
            "FAIL TRACEFENCE_NOTIFICATION_CHANNEL must name an existing SigNoz channel "
            "(or pass --skip-alerts)",
            file=sys.stderr,
        )
        return 1

    mcp_url = os.getenv("SIGNOZ_MCP_URL", "http://localhost:8000/mcp")
    dashboard = json.loads(dashboard_path.read_text())
    alerts = json.loads(alerts_path.read_text())
    _validate_dashboard(dashboard)
    _validate_alerts(alerts)

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

    async with streamable_http_client(
        mcp_url, headers={"SIGNOZ-API-KEY": api_key}
    ) as streams:
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

            metric_result = await session.call_tool(
                "signoz_list_metrics",
                arguments={"searchText": "tracefence_", "limit": 100, "timeRange": "1h"},
            )
            metric_names = _collect_strings(
                _normalize_result(metric_result), {"metricName", "metric_name", "name"}
            )
            expected_metrics = {
                agg["metricName"]
                for widget in dashboard["widgets"]
                for query in widget["query"].get("builder", {}).get("queryData", [])
                for agg in query.get("aggregations", [])
                if agg.get("metricName")
            }
            missing_metrics = sorted(expected_metrics - metric_names)
            if missing_metrics:
                raise RuntimeError(
                    "TraceFence telemetry is not visible in SigNoz yet; missing metrics: "
                    + ", ".join(missing_metrics)
                )
            evidence["metrics"] = sorted(metric_names)

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

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence, indent=2, default=str) + "\n")
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
