from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

from tracefence.config import settings
from tracefence.domain.enums import ProofVerdict


@dataclass(frozen=True, slots=True)
class TelemetryProof:
    verdict: ProofVerdict
    trace_ids: list[str]
    discrepancies: list[str]
    evidence: dict[str, Any]


class SigNozMCPClient:
    """Strict SigNoz MCP adapter.

    The adapter never upgrades free-form text to VERIFIED. Verification requires
    structured or unambiguous evidence for the command span, blocked-action spans,
    correlated logs, and both stale-action counters.
    """

    async def verify_command(
        self,
        *,
        command_id: str,
        expected_stale_attempts: int,
        expected_stale_committed: int,
        start_ms: int | None = None,
        end_ms: int | None = None,
    ) -> TelemetryProof:
        unavailable = self._configuration_error()
        if unavailable is not None:
            return unavailable

        try:
            from mcp import ClientSession  # type: ignore[import-not-found]
            from mcp.client.streamable_http import streamable_http_client  # type: ignore[import-not-found]
        except ImportError:
            return TelemetryProof(
                verdict=ProofVerdict.UNAVAILABLE,
                trace_ids=[],
                discrepancies=["MCP Python SDK is not installed"],
                evidence={},
            )

        try:
            async with httpx.AsyncClient(
                headers={"SIGNOZ-API-KEY": settings.signoz_api_key},
                timeout=httpx.Timeout(connect=3, read=10, write=10, pool=3),
                limits=httpx.Limits(
                    max_connections=4,
                    max_keepalive_connections=2,
                ),
                follow_redirects=False,
            ) as http_client:
                async with streamable_http_client(
                    settings.signoz_mcp_url,
                    http_client=http_client,
                ) as streams:
                    read_stream, write_stream, _ = streams
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        tool_names = {tool.name for tool in tools.tools}
                        required = {
                            "signoz_search_traces",
                            "signoz_search_logs",
                            "signoz_query_metrics",
                        }
                        missing = sorted(required - tool_names)
                        if missing:
                            return TelemetryProof(
                                verdict=ProofVerdict.UNAVAILABLE,
                                trace_ids=[],
                                discrepancies=[
                                    f"Missing SigNoz MCP tools: {', '.join(missing)}"
                                ],
                                evidence={"available_tools": sorted(tool_names)},
                            )

                        time_arguments: dict[str, Any] = {"timeRange": "1h"}
                        if start_ms is not None and end_ms is not None:
                            time_arguments = {"start": start_ms, "end": end_ms}

                        command_result = await session.call_tool(
                            "signoz_search_traces",
                            arguments={
                                "searchContext": "TraceFence command issuance evidence",
                                "operation": "tracefence.control.command_issue",
                                "filter": f"attribute.tracefence.command.id = '{command_id}'",
                                "limit": 100,
                                **time_arguments,
                            },
                        )
                        blocked_result = await session.call_tool(
                            "signoz_search_traces",
                            arguments={
                                "searchContext": "TraceFence stale action block evidence",
                                "operation": "tracefence.action.block",
                                "filter": f"attribute.tracefence.command.id = '{command_id}'",
                                "limit": 100,
                                **time_arguments,
                            },
                        )
                        log_result = await session.call_tool(
                            "signoz_search_logs",
                            arguments={
                                "searchContext": "TraceFence correlated action-denied logs",
                                "searchText": f"action_denied command_id={command_id}",
                                "limit": 100,
                                **time_arguments,
                            },
                        )
                        metric_arguments = {
                            "metricType": "sum",
                            "isMonotonic": True,
                            "temporality": "cumulative",
                            "timeAggregation": "increase",
                            "spaceAggregation": "sum",
                            "requestType": "scalar",
                            "reduceTo": "sum",
                            **time_arguments,
                        }
                        attempts_metric = await session.call_tool(
                            "signoz_query_metrics",
                            arguments={
                                "searchContext": "TraceFence stale action attempt invariant",
                                "metricName": "tracefence_stale_action_attempts_total",
                                **metric_arguments,
                            },
                        )
                        committed_metric = await session.call_tool(
                            "signoz_query_metrics",
                            arguments={
                                "searchContext": "TraceFence stale action commit invariant",
                                "metricName": "tracefence_stale_actions_committed_total",
                                **metric_arguments,
                            },
                        )

                        evidence = {
                            "command_traces": _normalize_tool_result(command_result),
                            "blocked_traces": _normalize_tool_result(blocked_result),
                            "blocked_logs": _normalize_tool_result(log_result),
                            "attempts_metric": _normalize_tool_result(attempts_metric),
                            "committed_metric": _normalize_tool_result(committed_metric),
                            "expected_stale_attempts": expected_stale_attempts,
                            "expected_stale_committed": expected_stale_committed,
                        }
                        return _reconcile_evidence(command_id, evidence)
        except (httpx.TransportError, TimeoutError, OSError) as exc:
            return TelemetryProof(
                verdict=ProofVerdict.UNAVAILABLE,
                trace_ids=[],
                discrepancies=[
                    f"SigNoz MCP transport unavailable: {type(exc).__name__}: {exc}"
                ],
                evidence={},
            )

    @staticmethod
    def _configuration_error() -> TelemetryProof | None:
        if not settings.signoz_api_key:
            return TelemetryProof(
                verdict=ProofVerdict.UNAVAILABLE,
                trace_ids=[],
                discrepancies=["SIGNOZ_API_KEY is not configured"],
                evidence={},
            )
        return None


def _reconcile_evidence(command_id: str, evidence: dict[str, Any]) -> TelemetryProof:
    expected_attempts = int(evidence["expected_stale_attempts"])
    expected_committed = int(evidence["expected_stale_committed"])

    command_count = _result_count(evidence["command_traces"], "tracefence.control.command_issue")
    blocked_trace_count = _result_count(evidence["blocked_traces"], "tracefence.action.block")
    blocked_log_count = _result_count(evidence["blocked_logs"], "action_denied")
    attempts_metric = _metric_value(
        evidence["attempts_metric"], "tracefence_stale_action_attempts_total"
    )
    committed_metric = _metric_value(
        evidence["committed_metric"], "tracefence_stale_actions_committed_total"
    )

    trace_text = _as_text(evidence["command_traces"]) + "\n" + _as_text(
        evidence["blocked_traces"]
    )
    trace_ids = _extract_trace_ids(trace_text)
    discrepancies: list[str] = []
    unresolved: list[str] = []

    # SigNoz MCP may execute mismatched inputs best-effort and append a validation
    # notice. Such results are useful diagnostically but are not trustworthy enough
    # for a cryptographic-style control proof, so fail closed to PARTIAL.
    if "input validation notice" in _as_text(evidence).lower():
        unresolved.append("SigNoz MCP input validation notice")

    if command_count is None:
        unresolved.append("command trace count")
    elif command_count < 1:
        discrepancies.append("No command-issue span was found")

    if blocked_trace_count is None:
        unresolved.append("blocked trace count")
    elif blocked_trace_count != expected_attempts:
        discrepancies.append(
            f"Blocked trace count {blocked_trace_count} != runtime count {expected_attempts}"
        )

    if blocked_log_count is None:
        unresolved.append("blocked log count")
    elif blocked_log_count != expected_attempts:
        discrepancies.append(
            f"Blocked log count {blocked_log_count} != runtime count {expected_attempts}"
        )

    # The counters are intentionally low-cardinality global health signals, not
    # command-labelled audit records. Concurrent commands may therefore add events
    # inside the same query window. Per-command traces and logs must match exactly;
    # metric deltas must be at least the command-local count. For the hard safety
    # invariant, a command expecting zero committed stale actions requires the
    # global window to remain exactly zero.
    if attempts_metric is None:
        unresolved.append("stale-attempt metric value")
    elif attempts_metric < expected_attempts:
        discrepancies.append(
            f"Stale-attempt metric delta {attempts_metric} is below runtime count "
            f"{expected_attempts}"
        )

    if committed_metric is None:
        unresolved.append("stale-committed metric value")
    elif expected_committed == 0 and committed_metric != 0:
        discrepancies.append(
            f"Stale-committed metric delta {committed_metric} violates the zero-commit "
            "safety invariant"
        )
    elif expected_committed > 0 and committed_metric < expected_committed:
        discrepancies.append(
            f"Stale-committed metric delta {committed_metric} is below runtime count "
            f"{expected_committed}"
        )

    if command_id not in _as_text(evidence):
        discrepancies.append("Command ID is absent from returned telemetry evidence")

    if discrepancies:
        return TelemetryProof(
            verdict=ProofVerdict.INCONSISTENT,
            trace_ids=trace_ids,
            discrepancies=discrepancies,
            evidence=evidence,
        )
    if unresolved:
        return TelemetryProof(
            verdict=ProofVerdict.PARTIAL,
            trace_ids=trace_ids,
            discrepancies=[
                "MCP evidence was retrieved but these fields could not be reconciled strictly: "
                + ", ".join(unresolved)
            ],
            evidence=evidence,
        )
    return TelemetryProof(
        verdict=ProofVerdict.VERIFIED,
        trace_ids=trace_ids,
        discrepancies=[],
        evidence=evidence,
    )


def _normalize_tool_result(result: Any) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)

    content = getattr(result, "content", None)
    normalized_content: Any = None
    if isinstance(content, list):
        normalized: list[Any] = []
        for item in content:
            text = getattr(item, "text", None)
            if isinstance(text, str):
                normalized.append(_parse_json_or_text(text))
            else:
                normalized.append(item if isinstance(item, (dict, list)) else str(item))
        normalized_content = normalized
    elif isinstance(content, str):
        normalized_content = _parse_json_or_text(content)
    elif content is not None:
        normalized_content = content

    # Preserve both structured data and textual notices. The SigNoz MCP server can
    # return usable structured rows while appending an input-validation warning to
    # content; discarding that warning could falsely upgrade best-effort evidence to
    # VERIFIED.
    if structured is not None:
        payload: dict[str, Any] = {"structured": structured}
        if normalized_content not in (None, [], ""):
            payload["content"] = normalized_content
        if bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
            payload["isError"] = True
        return payload
    if normalized_content is not None:
        return normalized_content
    return result


def _parse_json_or_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _result_count(payload: Any, marker: str) -> int | None:
    # Prefer concrete returned rows over generic nested count fields, which may
    # describe pagination, groups, or unrelated metadata rather than result rows.
    lists = _candidate_result_lists(payload)
    if lists:
        rows = lists[0]
        if not rows:
            return 0
        matching = [item for item in rows if marker in _as_text(item)]
        return len(matching) if matching else None

    explicit = _find_numeric_by_keys(
        payload,
        {"result_count", "resultCount", "total_count", "totalCount", "total"},
    )
    if explicit is not None:
        return int(explicit)

    text = _as_text(payload)
    if not text.strip():
        return 0
    marker_occurrences = text.count(marker)
    if marker_occurrences:
        return marker_occurrences
    return None


def _metric_value(payload: Any, metric_name: str) -> float | None:
    direct = _find_metric_in_object(payload, metric_name)
    if direct is not None:
        return direct
    text = _as_text(payload)
    pattern = re.compile(
        rf"{re.escape(metric_name)}[^\d-]*(-?\d+(?:\.\d+)?)", re.IGNORECASE
    )
    match = pattern.search(text)
    return float(match.group(1)) if match else None


def _find_metric_in_object(payload: Any, metric_name: str) -> float | None:
    if isinstance(payload, dict):
        if metric_name in payload and isinstance(payload[metric_name], (int, float)):
            return float(payload[metric_name])
        name = payload.get("metric") or payload.get("metric_name") or payload.get("name")
        if name == metric_name:
            for key in ("value", "latest", "total", "count"):
                if isinstance(payload.get(key), (int, float)):
                    return float(payload[key])
        for value in payload.values():
            found = _find_metric_in_object(value, metric_name)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = _find_metric_in_object(item, metric_name)
            if found is not None:
                return found
    return None


def _find_numeric_by_keys(payload: Any, keys: set[str]) -> float | None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in keys and isinstance(value, (int, float)):
                return float(value)
        for value in payload.values():
            found = _find_numeric_by_keys(value, keys)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = _find_numeric_by_keys(item, keys)
            if found is not None:
                return found
    return None


def _candidate_result_lists(payload: Any) -> list[list[Any]]:
    found: list[list[Any]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in {"results", "items", "data", "traces", "logs", "rows"} and isinstance(
                value, list
            ):
                found.append(value)
            else:
                found.extend(_candidate_result_lists(value))
    elif isinstance(payload, list):
        if payload and all(isinstance(item, (dict, list)) for item in payload):
            found.append(payload)
        else:
            for item in payload:
                found.extend(_candidate_result_lists(item))
    return found


def _as_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, sort_keys=True, default=str)
    except TypeError:
        return str(payload)


def _extract_trace_ids(text: str) -> list[str]:
    return sorted(set(re.findall(r"\b[0-9a-f]{32}\b", text.lower())))
