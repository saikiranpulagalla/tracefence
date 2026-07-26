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

import httpx

from tracefence.evidence import EvidenceIntegrityError, resolve_evidence_path
from tracefence.signoz.mcp_client import (
    MCPToolResultError,
    ResponseSchemaError,
    normalize_metric_catalog_names,
    normalize_metric_query_values,
)
from tracefence.signoz.mcp_transport import create_mcp_http_client
from tracefence.telemetry.schema import (
    MetricDiscoveryObservation,
    MetricReference,
    extract_metric_references,
    validate_metric_references,
    wait_for_metric_discovery,
)

REQUIRED_TOOLS = {
    "signoz_list_metrics",
    "signoz_search_traces",
    "signoz_search_logs",
    "signoz_query_metrics",
    "signoz_list_dashboards",
    "signoz_get_dashboard",
    "signoz_list_alert_rules",
}
DASHBOARD_TITLE = "TraceFence Control Integrity"
ALERT_NAMES = {
    "TraceFence Stale Action Committed",
    "TraceFence Live Agent Has Not Converged",
}


ALERT_CHANNEL_PLACEHOLDER = "${TRACEFENCE_NOTIFICATION_CHANNEL}"
ROOT = Path(__file__).resolve().parents[1]
METRIC_DISCOVERY_DEADLINE_SECONDS = 60.0
METRIC_DISCOVERY_POLL_SECONDS = 2.0
_STARTUP_SIGNAL_METRIC = "tracefence_active_nodes"
_BUILD_COMMIT_PATTERN = re.compile(r"^[0-9A-Za-z._-]{7,128}$")


class _MetricDiscoverySchemaError(RuntimeError):
    """A metric-discovery response was syntactically unsafe to trust."""


def _json_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _substitute_channel(value: Any, channel: str) -> Any:
    if isinstance(value, dict):
        return {key: _substitute_channel(item, channel) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute_channel(item, channel) for item in value]
    return channel if value == ALERT_CHANNEL_PLACEHOLDER else value


def _deployment_digest(template: dict[str, Any], channel: str, spec_digest: str) -> str:
    payload = _substitute_channel(json.loads(json.dumps(template)), channel)
    return _json_digest({"spec_digest": spec_digest, "channel": channel, "alert": payload})


def _extract_ids(value: Any) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in _walk(value):
        identifier = item.get("id") or item.get("uuid") or item.get("ruleId")
        title = item.get("title") or item.get("name") or item.get("alert")
        if isinstance(identifier, str) and isinstance(title, str):
            rows.append({"id": identifier, "title": title})
    return rows


def _local_spec() -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    dashboard = json.loads((ROOT / "observability" / "dashboard.json").read_text())
    alerts = json.loads((ROOT / "observability" / "alerts.json").read_text())
    return _json_digest({"dashboard": dashboard, "alerts": alerts}), dashboard, alerts


def _normalize(result: Any) -> Any:
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
                return _normalize_items(dumped["contents"])
            if "content" in dumped:
                return _normalize_items(dumped["content"])
            return dumped

    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if structured is not None:
        return structured
    contents = getattr(result, "contents", None)
    if contents is not None:
        return _normalize_items(contents)
    return _normalize_items(getattr(result, "content", result))


def _normalize_items(value: Any) -> Any:
    if isinstance(value, list):
        items = [_normalize_item(item) for item in value]
        return items[0] if len(items) == 1 else items
    return _normalize_item(value)


def _normalize_item(item: Any) -> Any:
    if hasattr(item, "model_dump"):
        try:
            item = item.model_dump(mode="python", by_alias=True)
        except TypeError:
            item = item.model_dump()
    if isinstance(item, dict):
        text = item.get("text")
        if isinstance(text, str):
            return _parse_json_or_text(text)
        return {key: _normalize_item(value) for key, value in item.items()}
    text = getattr(item, "text", None)
    if isinstance(text, str):
        return _parse_json_or_text(text)
    return item


def _parse_json_or_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _tool_failed(result: Any) -> bool:
    if bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
        return True
    normalized = _normalize(result)
    return isinstance(normalized, dict) and bool(
        normalized.get("isError") or normalized.get("is_error")
    )


def _walk(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _strings(value: Any, keys: set[str]) -> set[str]:
    result: set[str] = set()
    for row in _walk(value):
        for key in keys:
            item = row.get(key)
            if isinstance(item, str) and item:
                result.add(item)
    return result


def _metric_references(
    dashboard: dict[str, Any], alerts: list[dict[str, Any]]
) -> tuple[MetricReference, ...]:
    references = extract_metric_references(dashboard, alerts)
    validate_metric_references(references)
    return references


async def _list_tracefence_metric_names(session: Any) -> set[str]:
    metrics = await session.call_tool(
        "signoz_list_metrics",
        arguments={"searchText": "tracefence_", "limit": 100, "timeRange": "1h"},
    )
    if _tool_failed(metrics):
        raise RuntimeError("signoz_list_metrics returned an MCP error")
    try:
        return normalize_metric_catalog_names(metrics)
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
            "searchContext": "TraceFence current startup telemetry verification",
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


async def _verify_metric_preflight(
    session: Any, references: tuple[MetricReference, ...], failures: list[str]
) -> None:
    async def fetch() -> MetricDiscoveryObservation:
        metric_names = await _list_tracefence_metric_names(session)
        live_metric_query_succeeded = await _current_startup_metric_query_succeeded(session)
        return MetricDiscoveryObservation(
            observed_metric_names=frozenset(metric_names),
            live_metric_query_succeeded=live_metric_query_succeeded,
        )

    preflight = await wait_for_metric_discovery(
        fetch,
        references,
        deadline_seconds=METRIC_DISCOVERY_DEADLINE_SECONDS,
        poll_seconds=METRIC_DISCOVERY_POLL_SECONDS,
    )
    if preflight.startup_required_missing:
        failures.append(
            "startup telemetry is not visible; missing startup-required metrics: "
            + ", ".join(preflight.startup_required_missing)
        )
    else:
        print("PASS Startup-required TraceFence metrics are queryable")
    if not preflight.live_metric_query_succeeded:
        failures.append(
            "startup telemetry is not visible; the current TraceFence metric query returned no data"
        )
    if preflight.event_driven_not_yet_observed:
        print(
            "INFO Declared event-driven metrics have not emitted yet: "
            + ", ".join(preflight.event_driven_not_yet_observed)
        )
    if preflight.failure_only_not_yet_observed:
        print(
            "INFO Declared failure-only metrics are absent as expected: "
            + ", ".join(preflight.failure_only_not_yet_observed)
        )


async def verify(
    signoz_url: str,
    mcp_url: str,
    *,
    require_alerts: bool,
    proof_bundle: Path | None,
    evidence_signing_key: str | None,
) -> int:
    failures: list[str] = []
    try:
        spec_digest, dashboard_spec, alert_templates = _local_spec()
        metric_references = _metric_references(dashboard_spec, alert_templates)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL Checked-in observability specification is invalid: {exc}", file=sys.stderr)
        return 1
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        probes = [
            ("SigNoz UI", signoz_url),
            ("SigNoz MCP readiness", mcp_url.removesuffix("/mcp") + "/readyz"),
        ]
        for name, url in probes:
            try:
                response = await client.get(url)
                if response.status_code >= 400:
                    failures.append(f"{name} returned HTTP {response.status_code}")
                else:
                    print(f"PASS {name} reachable at {url}")
            except Exception as exc:
                failures.append(f"{name} unreachable: {exc}")

    api_key = os.getenv("SIGNOZ_API_KEY", "").strip()
    if not api_key:
        failures.append("SIGNOZ_API_KEY is not configured")
    else:
        print("PASS SIGNOZ_API_KEY configured")
    try:
        _required_build_commit()
    except RuntimeError as exc:
        failures.append(str(exc))

    if not failures:
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client

            async with AsyncExitStack() as stack:
                http_client = await stack.enter_async_context(create_mcp_http_client(api_key))
                streams = await stack.enter_async_context(
                    streamable_http_client(mcp_url, http_client=http_client)
                )
                read_stream, write_stream, _ = streams
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    names = {tool.name for tool in tools.tools}
                    required_tools = set(REQUIRED_TOOLS)
                    if require_alerts:
                        required_tools.add("signoz_get_alert")
                    missing_tools = sorted(required_tools - names)
                    if missing_tools:
                        failures.append("Missing MCP tools: " + ", ".join(missing_tools))
                    else:
                        print("PASS Required SigNoz MCP tools available")

                    try:
                        await _verify_metric_preflight(session, metric_references, failures)
                    except RuntimeError as exc:
                        failures.append(str(exc))

                    dashboards = await session.call_tool(
                        "signoz_list_dashboards", arguments={"limit": "1000", "offset": "0"}
                    )
                    if _tool_failed(dashboards):
                        failures.append("signoz_list_dashboards returned an MCP error")
                    dashboard_rows = _extract_ids(_normalize(dashboards))
                    dashboard_row = next(
                        (row for row in dashboard_rows if row["title"] == DASHBOARD_TITLE),
                        None,
                    )
                    if dashboard_row is None:
                        failures.append(f"Dashboard {DASHBOARD_TITLE!r} is missing")
                    else:
                        dashboard_full = await session.call_tool(
                            "signoz_get_dashboard", arguments={"id": dashboard_row["id"]}
                        )
                        if _tool_failed(dashboard_full):
                            failures.append("signoz_get_dashboard returned an MCP error")
                        elif f"tracefence-spec:{spec_digest[:16]}" not in json.dumps(
                            _normalize(dashboard_full), sort_keys=True, default=str
                        ):
                            failures.append(
                                f"Dashboard {DASHBOARD_TITLE!r} exists but its spec digest is stale"
                            )
                        else:
                            print(
                                f"PASS Dashboard {DASHBOARD_TITLE!r} matches the checked-in spec"
                            )

                    if require_alerts:
                        rules = await session.call_tool(
                            "signoz_list_alert_rules", arguments={"limit": 1000, "offset": 0}
                        )
                        if _tool_failed(rules):
                            failures.append("signoz_list_alert_rules returned an MCP error")
                        rule_rows = _extract_ids(_normalize(rules))
                        by_title = {row["title"]: row for row in rule_rows}
                        missing_alerts = sorted(ALERT_NAMES - by_title.keys())
                        if missing_alerts:
                            failures.append("Missing alert rules: " + ", ".join(missing_alerts))
                        channel = os.getenv("TRACEFENCE_NOTIFICATION_CHANNEL", "").strip()
                        if not channel:
                            failures.append(
                                "TRACEFENCE_NOTIFICATION_CHANNEL is required to verify alert payloads"
                            )
                        if not missing_alerts and channel:
                            alert_failures_before = len(failures)
                            templates_by_name = {item["alert"]: item for item in alert_templates}
                            for name in sorted(ALERT_NAMES):
                                result = await session.call_tool(
                                    "signoz_get_alert",
                                    arguments={"ruleId": by_title[name]["id"]},
                                )
                                if _tool_failed(result):
                                    failures.append(f"signoz_get_alert failed for {name}")
                                    continue
                                expected = _deployment_digest(
                                    templates_by_name[name], channel, spec_digest
                                )
                                if expected not in json.dumps(
                                    _normalize(result), sort_keys=True, default=str
                                ):
                                    failures.append(
                                        f"Alert {name!r} exists but its deployed payload/channel digest is stale"
                                    )
                            if len(failures) == alert_failures_before:
                                print(
                                    "PASS Required TraceFence alert rules match the checked-in specs and channel"
                                )
        except ImportError:
            failures.append("MCP Python SDK is not installed; install pip install -e '.[mcp]'")
        except Exception as exc:
            failures.append(f"MCP verification failed: {type(exc).__name__}: {exc}")

    if proof_bundle is not None:
        try:
            resolved_bundle, _manifest = resolve_evidence_path(proof_bundle, signing_key=evidence_signing_key)
            proof = json.loads(resolved_bundle.read_text())["proof"]
            if proof.get("telemetry_verdict") != "VERIFIED":
                failures.append(
                    f"Proof telemetry verdict is {proof.get('telemetry_verdict')}, expected VERIFIED"
                )
            if proof.get("overall_verdict") != "VERIFIED":
                failures.append(
                    f"Proof overall verdict is {proof.get('overall_verdict')}, expected VERIFIED"
                )
            if not proof.get("trace_ids"):
                failures.append("Proof has no SigNoz trace IDs")
            if not failures:
                print("PASS Proof bundle is telemetry-verified and includes trace IDs")
        except (
            EvidenceIntegrityError,
            OSError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
        ) as exc:
            failures.append(f"Invalid proof bundle: {exc}")

    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signoz-url", default=os.getenv("SIGNOZ_URL", "http://localhost:8080"))
    parser.add_argument("--mcp-url", default=os.getenv("SIGNOZ_MCP_URL", "http://localhost:8000/mcp"))
    parser.add_argument("--require-alerts", action="store_true")
    parser.add_argument("--proof-bundle", type=Path)
    args = parser.parse_args()
    return asyncio.run(
        verify(
            args.signoz_url,
            args.mcp_url,
            require_alerts=args.require_alerts,
            proof_bundle=args.proof_bundle,
            evidence_signing_key=os.getenv(
                "TRACEFENCE_EVIDENCE_SIGNING_KEY",
                "",
            ),
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
