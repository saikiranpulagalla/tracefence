from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, FiniteFloat, ValidationError

from tracefence.config import settings
from tracefence.domain.enums import ProofVerdict


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
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.TRANSPORT_UNAVAILABLE,
                f"SigNoz MCP transport unavailable: {type(exc).__name__}: {exc}",
            )
        except McpError as exc:
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.MCP_TOOL_ERROR,
                f"SigNoz MCP tool error: {type(exc).__name__}: {exc}",
            )

        try:
            evidence = {
                "command_traces": _normalize_tool_result(command_result),
                "blocked_traces": _normalize_tool_result(blocked_result),
                "blocked_logs": _normalize_tool_result(log_result),
                "export_watermarks": _normalize_tool_result(watermark_result),
                "attempts_metric": _normalize_tool_result(attempts_metric),
                "committed_metric": _normalize_tool_result(committed_metric),
            }
        except MCPToolResultError as exc:
            return _failure(
                ProofVerdict.UNAVAILABLE,
                TelemetryFailureKind.MCP_TOOL_ERROR,
                str(exc),
            )
        except ResponseSchemaError as exc:
            return _failure(
                ProofVerdict.PARTIAL,
                TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH,
                str(exc),
            )

        try:
            return _reconcile_evidence(context, evidence)
        except Exception as exc:
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


def _normalize_tool_result(result: Any) -> dict[str, Any]:
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

    if isinstance(content, list) and len(content) == 1:
        text = getattr(content[0], "text", None)
        if isinstance(text, str):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ResponseSchemaError("MCP textual result was not valid JSON") from exc
            if isinstance(parsed, dict):
                return parsed
    raise ResponseSchemaError("MCP result has no unambiguous structured result container")


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
