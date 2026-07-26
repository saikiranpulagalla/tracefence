from __future__ import annotations

import json
import math
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, FiniteFloat, ValidationError

from tracefence.config import settings
from tracefence.domain.enums import ProofVerdict
from tracefence.telemetry.instrumentation import instrument_httpx_client


class TelemetryFailureKind(StrEnum):
    CONFIGURATION_UNAVAILABLE = "CONFIGURATION_UNAVAILABLE"
    EXPORTER_UNAVAILABLE = "EXPORTER_UNAVAILABLE"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
    MCP_TOOL_ERROR = "MCP_TOOL_ERROR"
    RESPONSE_SCHEMA_MISMATCH = "RESPONSE_SCHEMA_MISMATCH"
    EVIDENCE_INCONSISTENT = "EVIDENCE_INCONSISTENT"
    INTERNAL_PARSER_DEFECT = "INTERNAL_PARSER_DEFECT"


@dataclass(frozen=True, slots=True)
class ExportWatermark:
    service_name: str
    service_instance_id: str
    process_instance_id: str
    build_commit: str
    schema_version: int
    run_id: str
    command_id: str
    exported_at_ms: int
    sequence: int


@dataclass(frozen=True, slots=True)
class RuntimeBlockedAction:
    action_id: str
    node_id: str
    target_scope_id: str
    snapshot_version: int
    live_version: int
    live_status: str
    denial_reason: str


@dataclass(frozen=True, slots=True)
class TelemetryVerificationContext:
    command_id: str
    run_id: str
    command_created_ms: int
    start_ms: int
    end_ms: int
    command_operation: str
    service_name: str
    service_instance_id: str
    process_instance_id: str
    build_commit: str
    schema_version: int
    blocked_actions: tuple[RuntimeBlockedAction, ...]
    export_watermark: ExportWatermark | None


@dataclass(frozen=True, slots=True)
class TelemetryProof:
    verdict: ProofVerdict
    trace_ids: list[str]
    discrepancies: list[str]
    evidence: dict[str, Any]
    failure_kind: TelemetryFailureKind | None = None


class MCPToolResultError(ValueError):
    pass


class ResponseSchemaError(ValueError):
    pass


class _AdvisoryKind(StrEnum):
    NO_PAGINATION = "NO_PAGINATION"
    PAGE_COMPLETE = "PAGE_COMPLETE"
    PAGE_INCOMPLETE = "PAGE_INCOMPLETE"
    METRICS_DECISION = "METRICS_DECISION"
    DECISION_WARNING = "DECISION_WARNING"
    MALFORMED_METRICS_DECISION = "MALFORMED_METRICS_DECISION"
    BACKEND_WARNING = "BACKEND_WARNING"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class _AdvisoryState:
    kind: _AdvisoryKind


@dataclass(frozen=True, slots=True)
class _QueryBuilderPage:
    query_name: str
    rows: list[Any]
    columns: list[str] | None
    next_cursor: str | None


_health_lock = threading.Lock()
_last_success_at: str | None = None
_last_status = "never_observed"
_last_available: bool | None = None


def mcp_health() -> dict[str, object]:
    """Return the last observed MCP state without doing remote I/O."""

    configured = bool(settings.signoz_mcp_url and settings.signoz_api_key)
    if not configured:
        return {
            "configured": False,
            "available": None,
            "status": "unconfigured",
            "last_success_at": None,
        }
    with _health_lock:
        return {
            "configured": True,
            "available": _last_available,
            "status": _last_status,
            "last_success_at": _last_success_at,
        }


def _record_mcp_health(
    *,
    available: bool,
    status: str,
    successful_query: bool = False,
) -> None:
    global _last_available, _last_status, _last_success_at

    with _health_lock:
        _last_available = available
        _last_status = status
        if successful_query:
            _last_success_at = datetime.now(UTC).isoformat()


class _StrictEvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _IdentityRow(_StrictEvidenceModel):
    service_name: str = Field(min_length=1)
    service_instance_id: str = Field(min_length=1)
    process_instance_id: str = Field(min_length=1)
    build_commit: str = Field(min_length=1)
    schema_version: int = Field(ge=1)


class _CommandTraceRow(_IdentityRow):
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    command_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    timestamp_ms: int = Field(ge=0)


class _BlockedTraceRow(_IdentityRow):
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    command_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    target_scope_id: str = Field(min_length=1)
    snapshot_version: int = Field(ge=1)
    live_version: int = Field(ge=1)
    live_status: str = Field(min_length=1)
    denial_reason: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    timestamp_ms: int = Field(ge=0)


class _BlockedLogRow(_IdentityRow):
    command_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    target_scope_id: str = Field(min_length=1)
    snapshot_version: int = Field(ge=1)
    live_version: int = Field(ge=1)
    live_status: str = Field(min_length=1)
    denial_reason: str = Field(min_length=1)
    event_name: str = Field(min_length=1)
    timestamp_ms: int = Field(ge=0)


class _ExportWatermarkRow(_IdentityRow):
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    command_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    exported_at_ms: int = Field(ge=0)
    sequence: int = Field(ge=1)


class _MetricRow(_StrictEvidenceModel):
    metric_name: str = Field(min_length=1)
    value: FiniteFloat


class SigNozMCPClient:
    """Strict, fail-closed SigNoz MCP adapter.

    Telemetry is VERIFIED only when command, blocked-action trace, blocked-action
    log and successful export-watermark rows exactly match the authoritative
    runtime context. Metrics are validated as supplementary health signals and
    never substitute for command-specific rows.
    """

    async def verify_command(
        self,
        *,
        context: TelemetryVerificationContext,
    ) -> TelemetryProof:
        unavailable = self._configuration_error(context)
        if unavailable is not None:
            return unavailable

        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
            from mcp.shared.exceptions import McpError
        except ImportError:
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.CONFIGURATION_UNAVAILABLE,
                "MCP Python SDK is not installed",
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
                instrument_httpx_client(http_client)
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
                            return _failure(
                                ProofVerdict.UNAVAILABLE,
                                TelemetryFailureKind.MCP_TOOL_ERROR,
                                f"Missing SigNoz MCP tools: {', '.join(missing)}",
                                {"available_tools": sorted(tool_names)},
                            )

                        time_arguments = {
                            "start": context.start_ms,
                            "end": context.end_ms,
                        }
                        command_result = await session.call_tool(
                            "signoz_search_traces",
                            arguments={
                                "searchContext": "TraceFence command issuance evidence",
                                "operation": context.command_operation,
                                "filter": _command_filter(context),
                                "limit": 100,
                                **time_arguments,
                            },
                        )
                        blocked_result = await session.call_tool(
                            "signoz_search_traces",
                            arguments={
                                "searchContext": "TraceFence stale action block evidence",
                                "operation": "tracefence.action.block",
                                "filter": _command_filter(context),
                                "limit": 100,
                                **time_arguments,
                            },
                        )
                        log_result = await session.call_tool(
                            "signoz_search_logs",
                            arguments={
                                "searchContext": "TraceFence correlated action-denied logs",
                                "searchText": (
                                    f"action_denied command_id={context.command_id} "
                                    f"run_id={context.run_id}"
                                ),
                                "limit": 100,
                                **time_arguments,
                            },
                        )
                        watermark_result = await session.call_tool(
                            "signoz_search_traces",
                            arguments={
                                "searchContext": "TraceFence successful export watermark",
                                "operation": "tracefence.telemetry.export_watermark",
                                "filter": _command_filter(context),
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
                                "searchContext": "TraceFence stale action attempt health",
                                "metricName": "tracefence_stale_action_attempts_total",
                                **metric_arguments,
                            },
                        )
                        committed_metric = await session.call_tool(
                            "signoz_query_metrics",
                            arguments={
                                "searchContext": "TraceFence stale action commit health",
                                "metricName": "tracefence_stale_actions_committed_total",
                                **metric_arguments,
                            },
                        )
        except (httpx.TransportError, TimeoutError, OSError) as exc:
            _record_mcp_health(
                available=False,
                status=TelemetryFailureKind.TRANSPORT_UNAVAILABLE.value.lower(),
            )
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.TRANSPORT_UNAVAILABLE,
                f"SigNoz MCP transport unavailable: {type(exc).__name__}: {exc}",
            )
        except McpError as exc:
            _record_mcp_health(
                available=True,
                status=TelemetryFailureKind.MCP_TOOL_ERROR.value.lower(),
            )
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.MCP_TOOL_ERROR,
                f"SigNoz MCP tool error: {type(exc).__name__}: {exc}",
            )

        _record_mcp_health(
            available=True,
            status="ready",
            successful_query=True,
        )
        try:
            evidence = {
                "command_traces": _normalize_tool_result(command_result),
                "blocked_traces": _normalize_tool_result(blocked_result),
                "blocked_logs": _normalize_tool_result(log_result),
                "export_watermarks": _normalize_tool_result(watermark_result),
                "attempts_metric": _normalize_tool_result(
                    attempts_metric,
                    defaults={
                        "metric_name": "tracefence_stale_action_attempts_total"
                    },
                ),
                "committed_metric": _normalize_tool_result(
                    committed_metric,
                    defaults={
                        "metric_name": "tracefence_stale_actions_committed_total"
                    },
                ),
            }
        except MCPToolResultError as exc:
            _record_mcp_health(
                available=True,
                status=TelemetryFailureKind.MCP_TOOL_ERROR.value.lower(),
            )
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.MCP_TOOL_ERROR,
                str(exc),
            )
        except ResponseSchemaError as exc:
            _record_mcp_health(
                available=True,
                status=TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH.value.lower(),
            )
            return _failure(
                ProofVerdict.PARTIAL,
                TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH,
                str(exc),
            )

        try:
            proof = _reconcile_evidence(context, evidence)
            if proof.failure_kind is not None:
                _record_mcp_health(
                    available=True,
                    status=proof.failure_kind.value.lower(),
                )
            return proof
        except Exception as exc:
            _record_mcp_health(
                available=True,
                status=TelemetryFailureKind.INTERNAL_PARSER_DEFECT.value.lower(),
            )
            return _failure(
                ProofVerdict.INCONSISTENT,
                TelemetryFailureKind.INTERNAL_PARSER_DEFECT,
                f"Internal telemetry parser defect: {type(exc).__name__}: {exc}",
                evidence,
            )

    @staticmethod
    def _configuration_error(
        context: TelemetryVerificationContext,
    ) -> TelemetryProof | None:
        if not settings.signoz_api_key:
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.CONFIGURATION_UNAVAILABLE,
                "SIGNOZ_API_KEY is not configured",
            )
        if not context.build_commit or context.build_commit == "UNSET":
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.CONFIGURATION_UNAVAILABLE,
                "TRACEFENCE_BUILD_COMMIT is required for telemetry verification",
            )
        if context.export_watermark is None:
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.EXPORTER_UNAVAILABLE,
                "No successful TraceFence export watermark exists for this command",
            )
        return None


def _failure(
    verdict: ProofVerdict,
    kind: TelemetryFailureKind,
    discrepancy: str,
    evidence: dict[str, Any] | None = None,
) -> TelemetryProof:
    return TelemetryProof(
        verdict=verdict,
        trace_ids=[],
        discrepancies=[discrepancy],
        evidence=evidence or {},
        failure_kind=kind,
    )


def _command_filter(context: TelemetryVerificationContext) -> str:
    return (
        f"attribute.tracefence.command.id = '{context.command_id}' AND "
        f"attribute.tracefence.run.id = '{context.run_id}'"
    )


_PAGINATION_NOTE = re.compile(
    r"^note: returned \d+ rows \(limit \d+\) .+"
    r"all matching results returned \(hasMore=false\)\.$"
)
_INCOMPLETE_PAGINATION_NOTE = re.compile(
    r"^note: returned \d+ rows \(limit \d+\) .+"
    r"(?:\(hasMore=true\)|more results exist|result limited|results limited|results truncated)\.$"
)

_FIELD_ALIASES = {
    "trace_id": "trace_id",
    "traceID": "trace_id",
    "traceId": "trace_id",
    "command_id": "command_id",
    "tracefence.command.id": "command_id",
    "attribute.tracefence.command.id": "command_id",
    "run_id": "run_id",
    "tracefence.run.id": "run_id",
    "attribute.tracefence.run.id": "run_id",
    "action_id": "action_id",
    "tracefence.action.id": "action_id",
    "attribute.tracefence.action.id": "action_id",
    "node_id": "node_id",
    "tracefence.node.id": "node_id",
    "attribute.tracefence.node.id": "node_id",
    "target_scope_id": "target_scope_id",
    "tracefence.target_scope.id": "target_scope_id",
    "attribute.tracefence.target_scope.id": "target_scope_id",
    "snapshot_version": "snapshot_version",
    "tracefence.snapshot.version": "snapshot_version",
    "attribute.tracefence.snapshot.version": "snapshot_version",
    "live_version": "live_version",
    "tracefence.live.version": "live_version",
    "attribute.tracefence.live.version": "live_version",
    "live_status": "live_status",
    "tracefence.live.status": "live_status",
    "attribute.tracefence.live.status": "live_status",
    "denial_reason": "denial_reason",
    "tracefence.denial.reason": "denial_reason",
    "attribute.tracefence.denial.reason": "denial_reason",
    "operation": "operation",
    "name": "operation",
    "event_name": "event_name",
    "event.name": "event_name",
    "timestamp_ms": "timestamp_ms",
    "service_name": "service_name",
    "service.name": "service_name",
    "resource.service.name": "service_name",
    "service_instance_id": "service_instance_id",
    "service.instance.id": "service_instance_id",
    "resource.service.instance.id": "service_instance_id",
    "process_instance_id": "process_instance_id",
    "tracefence.process.instance.id": "process_instance_id",
    "attribute.tracefence.process.instance.id": "process_instance_id",
    "build_commit": "build_commit",
    "tracefence.build.commit": "build_commit",
    "attribute.tracefence.build.commit": "build_commit",
    "schema_version": "schema_version",
    "tracefence.schema.version": "schema_version",
    "attribute.tracefence.schema.version": "schema_version",
    "exported_at_ms": "exported_at_ms",
    "tracefence.exported_at_ms": "exported_at_ms",
    "attribute.tracefence.exported_at_ms": "exported_at_ms",
    "sequence": "sequence",
    "tracefence.export.sequence": "sequence",
    "attribute.tracefence.export.sequence": "sequence",
    "metric_name": "metric_name",
    "metric.name": "metric_name",
    "value": "value",
    "__result": "value",
}


def _normalize_tool_result(
    result: Any,
    *,
    defaults: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize SDK structured results or the official SigNoz JSON-first contract.

    SigNoz search/query tools return raw backend JSON in content block zero and
    append human-readable advisory blocks. Only a complete pagination note or a
    warning-free metrics decision note is admissible. Backend warnings,
    truncation, multiple JSON blocks, and unknown advisory text fail closed.
    """

    if bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
        raise MCPToolResultError("MCP tool returned isError=true")

    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    content = getattr(result, "content", None)
    if structured is not None:
        if content not in (None, [], ""):
            raise ResponseSchemaError(
                "MCP result contained additional content beside structured evidence"
            )
        if not isinstance(structured, dict):
            raise ResponseSchemaError("MCP structured evidence must be an object")
        return structured

    if not isinstance(content, list) or not content:
        raise ResponseSchemaError(
            "MCP result has no unambiguous structured result container"
        )
    texts: list[str] = []
    for block in content:
        block_type = getattr(block, "type", "text")
        text = getattr(block, "text", None)
        if block_type != "text" or not isinstance(text, str):
            raise ResponseSchemaError("MCP result contained unexpected executable content")
        texts.append(text)
    try:
        parsed = json.loads(texts[0])
    except json.JSONDecodeError as exc:
        raise ResponseSchemaError("MCP first text block was not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ResponseSchemaError("MCP first JSON content block must be an object")
    advisory_state = _validate_advisories(texts[1:])
    if set(parsed) == {"results"}:
        return parsed
    return _adapt_query_builder_payload(
        parsed,
        defaults=defaults or {},
        advisory_state=advisory_state,
    )


def _validate_advisories(advisories: list[str]) -> _AdvisoryState:
    pagination_state = _AdvisoryState(_AdvisoryKind.NO_PAGINATION)
    for advisory in advisories:
        try:
            json.loads(advisory)
        except json.JSONDecodeError:
            advisory_state = _validate_advisory(advisory)
        else:
            raise ResponseSchemaError(
                "MCP result contained ambiguous multiple JSON content blocks"
            )
        if advisory_state.kind is _AdvisoryKind.BACKEND_WARNING:
            raise ResponseSchemaError("SigNoz backend warning makes evidence ambiguous")
        if advisory_state.kind is _AdvisoryKind.DECISION_WARNING:
            raise ResponseSchemaError(
                "SigNoz decision advisory contains a warning or assumption"
            )
        if advisory_state.kind is _AdvisoryKind.MALFORMED_METRICS_DECISION:
            raise ResponseSchemaError("SigNoz metrics decision advisory is malformed")
        if advisory_state.kind is _AdvisoryKind.PAGE_INCOMPLETE:
            raise ResponseSchemaError("SigNoz evidence page is incomplete")
        if advisory_state.kind is _AdvisoryKind.UNKNOWN:
            raise ResponseSchemaError("MCP result contained an unknown advisory content block")
        if advisory_state.kind is _AdvisoryKind.PAGE_COMPLETE:
            pagination_state = advisory_state
    return pagination_state


def _validate_advisory(advisory: str) -> _AdvisoryState:
    text = advisory.strip()
    lower = text.lower()
    if _PAGINATION_NOTE.fullmatch(text):
        return _AdvisoryState(_AdvisoryKind.PAGE_COMPLETE)
    if _INCOMPLETE_PAGINATION_NOTE.fullmatch(text):
        return _AdvisoryState(_AdvisoryKind.PAGE_INCOMPLETE)
    if text.startswith("[Decisions applied]\n"):
        if any(marker in lower for marker in ("warning:", "unknown", "assumed")):
            return _AdvisoryState(_AdvisoryKind.DECISION_WARNING)
        lines = text.splitlines()[1:]
        if lines and all(line.startswith("  ") and ":" in line for line in lines):
            return _AdvisoryState(_AdvisoryKind.METRICS_DECISION)
        return _AdvisoryState(_AdvisoryKind.MALFORMED_METRICS_DECISION)
    if lower.startswith("note: signoz backend returned non-fatal warnings:"):
        return _AdvisoryState(_AdvisoryKind.BACKEND_WARNING)
    return _AdvisoryState(_AdvisoryKind.UNKNOWN)


def _adapt_query_builder_payload(
    payload: dict[str, Any],
    *,
    defaults: dict[str, Any],
    advisory_state: _AdvisoryState,
) -> dict[str, Any]:
    if set(payload) != {"status", "data"}:
        raise ResponseSchemaError(
            "SigNoz response contains an ambiguous result container"
        )
    if payload.get("status") != "success":
        raise ResponseSchemaError("SigNoz Query Builder response was not successful")
    outer = payload.get("data")
    if not isinstance(outer, dict):
        raise ResponseSchemaError("SigNoz Query Builder data envelope must be an object")
    allowed_outer_keys = {"type", "data", "meta", "warning"}
    if not set(outer).issubset(allowed_outer_keys):
        raise ResponseSchemaError(
            "SigNoz data envelope contains an ambiguous result container"
        )
    if not isinstance(outer.get("type"), str):
        raise ResponseSchemaError("SigNoz Query Builder response lacks a result type")
    if "meta" in outer and not isinstance(outer["meta"], dict):
        raise ResponseSchemaError("SigNoz Query Builder metadata is malformed")
    warning = outer.get("warning")
    if warning is not None:
        if not isinstance(warning, dict) or set(warning) != {"warnings"}:
            raise ResponseSchemaError("SigNoz warning envelope is malformed")
        warnings = warning["warnings"]
        if not isinstance(warnings, list):
            raise ResponseSchemaError("SigNoz warning list is malformed")
        if warnings:
            raise ResponseSchemaError("SigNoz backend warning makes evidence ambiguous")
    query_data = outer.get("data")
    if not isinstance(query_data, dict) or set(query_data) != {"results"}:
        raise ResponseSchemaError(
            "SigNoz Query Builder response must contain data.data.results"
        )
    result_sets = query_data["results"]
    if result_sets is None:
        result_sets = []
    if not isinstance(result_sets, list):
        raise ResponseSchemaError("SigNoz Query Builder results must be an array")

    normalized: list[dict[str, Any]] = []
    query_names: set[str] = set()
    has_nonempty_cursor = False
    for result_set in result_sets:
        page = _parse_query_builder_page(result_set)
        if page.query_name in query_names:
            raise ResponseSchemaError("SigNoz Query Builder queryName is duplicated")
        query_names.add(page.query_name)
        has_nonempty_cursor = has_nonempty_cursor or bool(page.next_cursor)
        for row in page.rows:
            normalized.append(
                _adapt_query_builder_row(row, columns=page.columns, defaults=defaults)
            )
    if has_nonempty_cursor and advisory_state.kind is not _AdvisoryKind.PAGE_COMPLETE:
        raise ResponseSchemaError("SigNoz evidence page is incomplete")
    return {"results": normalized}


def _parse_query_builder_page(result_set: Any) -> _QueryBuilderPage:
    if not isinstance(result_set, dict):
        raise ResponseSchemaError("SigNoz Query Builder result set must be an object")
    if not set(result_set).issubset({"queryName", "rows", "columns", "nextCursor"}):
        raise ResponseSchemaError("SigNoz result set contains an ambiguous row container")
    query_name = result_set.get("queryName")
    if not isinstance(query_name, str) or not query_name:
        raise ResponseSchemaError("SigNoz Query Builder result set lacks queryName")
    rows = result_set.get("rows")
    if rows is None:
        rows = []
    if not isinstance(rows, list):
        raise ResponseSchemaError("SigNoz Query Builder rows must be an array")
    next_cursor = result_set.get("nextCursor")
    if next_cursor is not None and not isinstance(next_cursor, str):
        raise ResponseSchemaError("SigNoz Query Builder nextCursor must be a string")
    if "nextCursor" in result_set and next_cursor is None:
        raise ResponseSchemaError("SigNoz Query Builder nextCursor must be a string")
    return _QueryBuilderPage(
        query_name=query_name,
        rows=rows,
        columns=_parse_column_aliases(result_set.get("columns")),
        next_cursor=next_cursor,
    )


def _parse_column_aliases(raw_columns: Any) -> list[str] | None:
    if raw_columns is None:
        return None
    if not isinstance(raw_columns, list) or not raw_columns:
        raise ResponseSchemaError("SigNoz Query Builder columns must be a non-empty array")
    aliases: list[str] = []
    for column in raw_columns:
        if isinstance(column, str) and column:
            alias = column
        elif isinstance(column, dict):
            alias_value = column.get("alias") or column.get("name")
            if not isinstance(alias_value, str) or not alias_value:
                raise ResponseSchemaError("SigNoz Query Builder column lacks an alias")
            alias = alias_value
        else:
            raise ResponseSchemaError("SigNoz Query Builder column metadata is malformed")
        aliases.append(alias)
    if len(set(aliases)) != len(aliases):
        raise ResponseSchemaError("SigNoz Query Builder column aliases are duplicated")
    return aliases


def _adapt_query_builder_row(
    row: Any,
    *,
    columns: list[str] | None,
    defaults: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ResponseSchemaError("SigNoz Query Builder row must be an object")
    if not set(row).issubset({"timestamp", "data"}):
        raise ResponseSchemaError("SigNoz row contains an ambiguous data container")
    raw_data = row.get("data")
    if isinstance(raw_data, dict):
        items = list(raw_data.items())
    elif isinstance(raw_data, list):
        if columns is None or len(columns) != len(raw_data):
            raise ResponseSchemaError(
                "Positional SigNoz row requires matching column aliases"
            )
        items = list(zip(columns, raw_data, strict=True))
    else:
        raise ResponseSchemaError("SigNoz Query Builder row data is malformed")

    normalized = dict(defaults)
    for source_name, value in items:
        canonical = _FIELD_ALIASES.get(source_name)
        if canonical is None:
            continue
        _put_unambiguous(normalized, canonical, value)
    if "timestamp" in row:
        _put_unambiguous(
            normalized,
            "timestamp_ms",
            _timestamp_to_milliseconds(row["timestamp"]),
        )
    return normalized


def _put_unambiguous(target: dict[str, Any], key: str, value: Any) -> None:
    if key in target and target[key] != value:
        raise ResponseSchemaError(f"Conflicting SigNoz aliases for {key}")
    target[key] = value


def _timestamp_to_milliseconds(value: Any) -> int:
    if isinstance(value, bool):
        raise ResponseSchemaError("SigNoz timestamp is malformed")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise ResponseSchemaError("SigNoz timestamp is malformed")
        return int(value)
    if not isinstance(value, str):
        raise ResponseSchemaError("SigNoz timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResponseSchemaError("SigNoz timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise ResponseSchemaError("SigNoz timestamp lacks a timezone")
    return int(parsed.timestamp() * 1000)


def _parse_rows[EvidenceModel: _StrictEvidenceModel](
    payload: Any,
    model: type[EvidenceModel],
    label: str,
) -> list[EvidenceModel]:
    if not isinstance(payload, dict) or set(payload) != {"results"}:
        raise ResponseSchemaError(
            f"{label} must contain exactly one top-level results array"
        )
    rows = payload["results"]
    if not isinstance(rows, list):
        raise ResponseSchemaError(f"{label}.results must be an array")
    try:
        return [model.model_validate(row) for row in rows]
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"])
        raise ResponseSchemaError(
            f"{label} row schema mismatch at {location}: {first['msg']}"
        ) from exc


def _reconcile_evidence(
    context: TelemetryVerificationContext,
    evidence: dict[str, Any],
) -> TelemetryProof:
    if context.export_watermark is None:
        return _failure(
            ProofVerdict.UNAVAILABLE,
            TelemetryFailureKind.EXPORTER_UNAVAILABLE,
            "OpenTelemetry exporter is disabled or has no successful command export",
            evidence,
        )
    if context.export_watermark.exported_at_ms <= context.command_created_ms:
        return _failure(
            ProofVerdict.INCONSISTENT,
            TelemetryFailureKind.EVIDENCE_INCONSISTENT,
            "Successful export watermark predates the command",
            evidence,
        )

    try:
        command_rows = _parse_rows(
            evidence.get("command_traces"), _CommandTraceRow, "command_traces"
        )
        blocked_traces = _parse_rows(
            evidence.get("blocked_traces"), _BlockedTraceRow, "blocked_traces"
        )
        blocked_logs = _parse_rows(
            evidence.get("blocked_logs"), _BlockedLogRow, "blocked_logs"
        )
        watermark_rows = _parse_rows(
            evidence.get("export_watermarks"),
            _ExportWatermarkRow,
            "export_watermarks",
        )
        _parse_rows(evidence.get("attempts_metric"), _MetricRow, "attempts_metric")
        _parse_rows(evidence.get("committed_metric"), _MetricRow, "committed_metric")
    except ResponseSchemaError as exc:
        return _failure(
            ProofVerdict.PARTIAL,
            TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH,
            str(exc),
            evidence,
        )

    discrepancies: list[str] = []
    if len(command_rows) != 1:
        discrepancies.append(
            f"Expected exactly one command trace, received {len(command_rows)}"
        )
    if len(watermark_rows) != 1:
        discrepancies.append(
            f"Expected exactly one export watermark, received {len(watermark_rows)}"
        )

    trace_ids = [
        *(row.trace_id for row in command_rows),
        *(row.trace_id for row in blocked_traces),
        *(row.trace_id for row in watermark_rows),
    ]
    duplicate_trace_ids = _duplicates(trace_ids)
    if duplicate_trace_ids:
        discrepancies.append(
            "Duplicate trace IDs: " + ", ".join(sorted(duplicate_trace_ids))
        )

    trace_action_ids = [row.action_id for row in blocked_traces]
    log_action_ids = [row.action_id for row in blocked_logs]
    duplicate_action_ids = _duplicates(trace_action_ids) | _duplicates(log_action_ids)
    if duplicate_action_ids:
        discrepancies.append(
            "Duplicate blocked action IDs: "
            + ", ".join(sorted(duplicate_action_ids))
        )

    runtime_by_id = {row.action_id: row for row in context.blocked_actions}
    if len(runtime_by_id) != len(context.blocked_actions):
        discrepancies.append("Authoritative runtime action IDs are duplicated")
    runtime_ids = set(runtime_by_id)
    trace_ids_set = set(trace_action_ids)
    log_ids_set = set(log_action_ids)
    if runtime_ids != trace_ids_set or runtime_ids != log_ids_set:
        discrepancies.append(
            "Runtime, trace and log blocked action-ID sets do not match exactly"
        )

    for row in command_rows:
        discrepancies.extend(_command_row_discrepancies(context, row))
    for blocked_trace in blocked_traces:
        discrepancies.extend(
            _blocked_row_discrepancies(
                context,
                runtime_by_id.get(blocked_trace.action_id),
                blocked_trace,
                operation=blocked_trace.operation,
                expected_operation="tracefence.action.block",
            )
        )
    for blocked_log in blocked_logs:
        discrepancies.extend(
            _blocked_row_discrepancies(
                context,
                runtime_by_id.get(blocked_log.action_id),
                blocked_log,
                operation=blocked_log.event_name,
                expected_operation="action_denied",
            )
        )
    for watermark_row in watermark_rows:
        discrepancies.extend(_watermark_discrepancies(context, watermark_row))

    if discrepancies:
        return TelemetryProof(
            verdict=ProofVerdict.INCONSISTENT,
            trace_ids=sorted(set(trace_ids)),
            discrepancies=discrepancies,
            evidence=evidence,
            failure_kind=TelemetryFailureKind.EVIDENCE_INCONSISTENT,
        )
    return TelemetryProof(
        verdict=ProofVerdict.VERIFIED,
        trace_ids=sorted(trace_ids),
        discrepancies=[],
        evidence=evidence,
    )


def _duplicates(values: list[str]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def _identity_discrepancies(
    context: TelemetryVerificationContext,
    row: _IdentityRow,
) -> list[str]:
    differences: list[str] = []
    for field in (
        "service_name",
        "service_instance_id",
        "process_instance_id",
        "build_commit",
        "schema_version",
    ):
        if getattr(row, field) != getattr(context, field):
            differences.append(f"{field} does not match the active TraceFence process")
    return differences


def _command_row_discrepancies(
    context: TelemetryVerificationContext,
    row: _CommandTraceRow,
) -> list[str]:
    differences = _identity_discrepancies(context, row)
    if row.command_id != context.command_id:
        differences.append("Command trace belongs to another command")
    if row.run_id != context.run_id:
        differences.append("Command trace belongs to another run")
    if row.operation != context.command_operation:
        differences.append("Command trace operation does not match")
    if not context.start_ms <= row.timestamp_ms <= context.end_ms:
        differences.append("Command trace is outside the proof time window")
    return differences


def _blocked_row_discrepancies(
    context: TelemetryVerificationContext,
    expected: RuntimeBlockedAction | None,
    row: _BlockedTraceRow | _BlockedLogRow,
    *,
    operation: str,
    expected_operation: str,
) -> list[str]:
    differences = _identity_discrepancies(context, row)
    if row.command_id != context.command_id:
        differences.append("Blocked evidence belongs to another command")
    if row.run_id != context.run_id:
        differences.append("Blocked evidence belongs to another run")
    if operation != expected_operation:
        differences.append("Blocked evidence operation/event does not match")
    if not context.start_ms <= row.timestamp_ms <= context.end_ms:
        differences.append("Blocked evidence is outside the proof time window")
    if expected is None:
        differences.append(f"Blocked action {row.action_id} is absent from runtime")
        return differences
    for field in (
        "node_id",
        "target_scope_id",
        "snapshot_version",
        "live_version",
        "live_status",
        "denial_reason",
    ):
        if getattr(row, field) != getattr(expected, field):
            differences.append(
                f"Blocked action {row.action_id} {field} does not match runtime"
            )
    return differences


def _watermark_discrepancies(
    context: TelemetryVerificationContext,
    row: _ExportWatermarkRow,
) -> list[str]:
    differences = _identity_discrepancies(context, row)
    expected = context.export_watermark
    if expected is None:
        return [*differences, "No local successful export watermark exists"]
    for field in (
        "command_id",
        "run_id",
        "service_name",
        "service_instance_id",
        "process_instance_id",
        "build_commit",
        "schema_version",
        "exported_at_ms",
        "sequence",
    ):
        if getattr(row, field) != getattr(expected, field):
            differences.append(f"Export watermark {field} does not match")
    if row.operation != "tracefence.telemetry.export_watermark":
        differences.append("Export watermark operation does not match")
    if row.exported_at_ms <= context.command_created_ms:
        differences.append("Export watermark predates the command")
    if not context.start_ms <= row.exported_at_ms <= context.end_ms:
        differences.append("Export watermark is outside the proof time window")
    return differences
