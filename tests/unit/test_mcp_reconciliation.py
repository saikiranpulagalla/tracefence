from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from tracefence.domain.enums import ProofVerdict
from tracefence.signoz.mcp_client import (
    ExportWatermark,
    RuntimeBlockedAction,
    TelemetryFailureKind,
    TelemetryVerificationContext,
    _normalize_tool_result,
    _reconcile_evidence,
)

COMMAND_ID = "command-123"
RUN_ID = "run-123"
ACTION_ID = "action-123"
COMMAND_TIME_MS = 1_000_000
WINDOW_START_MS = 995_000
WINDOW_END_MS = 1_010_000
IDENTITY = {
    "service_name": "tracefence-control-plane",
    "service_instance_id": "service-instance-a",
    "process_instance_id": "process-a",
    "build_commit": "0123456789abcdef",
    "schema_version": 1,
}


def context(*, with_exporter: bool = True) -> TelemetryVerificationContext:
    watermark = (
        ExportWatermark(
            run_id=RUN_ID,
            command_id=COMMAND_ID,
            exported_at_ms=1_005_000,
            sequence=7,
            **IDENTITY,
        )
        if with_exporter
        else None
    )
    return TelemetryVerificationContext(
        command_id=COMMAND_ID,
        run_id=RUN_ID,
        command_created_ms=COMMAND_TIME_MS,
        start_ms=WINDOW_START_MS,
        end_ms=WINDOW_END_MS,
        command_operation="tracefence.control.command_issue",
        service_name=IDENTITY["service_name"],
        service_instance_id=IDENTITY["service_instance_id"],
        process_instance_id=IDENTITY["process_instance_id"],
        build_commit=IDENTITY["build_commit"],
        schema_version=IDENTITY["schema_version"],
        blocked_actions=(
            RuntimeBlockedAction(
                action_id=ACTION_ID,
                node_id="node-123",
                target_scope_id="scope-123",
                snapshot_version=1,
                live_version=2,
                live_status="CANCELLED",
                denial_reason="SCOPE_CANCELLED",
            ),
        ),
        export_watermark=watermark,
    )


def evidence() -> dict:
    blocked = {
        "command_id": COMMAND_ID,
        "run_id": RUN_ID,
        "action_id": ACTION_ID,
        "node_id": "node-123",
        "target_scope_id": "scope-123",
        "snapshot_version": 1,
        "live_version": 2,
        "live_status": "CANCELLED",
        "denial_reason": "SCOPE_CANCELLED",
        "timestamp_ms": 1_003_000,
        **IDENTITY,
    }
    return {
        "command_traces": {
            "results": [
                {
                    "trace_id": "a" * 32,
                    "command_id": COMMAND_ID,
                    "run_id": RUN_ID,
                    "operation": "tracefence.control.command_issue",
                    "timestamp_ms": 1_001_000,
                    **IDENTITY,
                }
            ]
        },
        "blocked_traces": {
            "results": [
                {
                    **blocked,
                    "trace_id": "b" * 32,
                    "operation": "tracefence.action.block",
                }
            ]
        },
        "blocked_logs": {
            "results": [
                {
                    **blocked,
                    "event_name": "action_denied",
                }
            ]
        },
        "export_watermarks": {
            "results": [
                {
                    "trace_id": "c" * 32,
                    "command_id": COMMAND_ID,
                    "run_id": RUN_ID,
                    "operation": "tracefence.telemetry.export_watermark",
                    "exported_at_ms": 1_005_000,
                    "sequence": 7,
                    **IDENTITY,
                }
            ]
        },
        "attempts_metric": {
            "results": [
                {
                    "metric_name": "tracefence_stale_action_attempts_total",
                    "value": 1.0,
                }
            ]
        },
        "committed_metric": {
            "results": [
                {
                    "metric_name": "tracefence_stale_actions_committed_total",
                    "value": 0.0,
                }
            ]
        },
    }


def reconcile(payload: dict | None = None, *, ctx=None):
    return _reconcile_evidence(ctx or context(), payload or evidence())


def test_complete_exact_command_evidence_verifies():
    result = reconcile()

    assert result.verdict == ProofVerdict.VERIFIED
    assert result.failure_kind is None
    assert result.trace_ids == ["a" * 32, "b" * 32, "c" * 32]


def test_empty_supplementary_metrics_do_not_hide_exact_correlated_evidence():
    payload = evidence()
    payload["attempts_metric"]["results"] = []
    payload["committed_metric"]["results"] = []

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.VERIFIED
    assert result.failure_kind is None


def test_cross_command_blocked_rows_are_inconsistent():
    payload = evidence()
    payload["blocked_traces"]["results"][0]["command_id"] = "another-command"

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.INCONSISTENT
    assert result.failure_kind == TelemetryFailureKind.EVIDENCE_INCONSISTENT


def test_missing_action_id_is_schema_mismatch():
    payload = evidence()
    del payload["blocked_logs"]["results"][0]["action_id"]

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.PARTIAL
    assert result.failure_kind == TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH


def test_duplicate_action_and_trace_ids_are_rejected():
    payload = evidence()
    payload["blocked_traces"]["results"].append(
        deepcopy(payload["blocked_traces"]["results"][0])
    )

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.INCONSISTENT
    assert "duplicate" in " ".join(result.discrepancies).lower()


def test_trace_and_log_action_sets_must_match_exactly():
    payload = evidence()
    payload["blocked_logs"]["results"] = []

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.INCONSISTENT
    assert "action-id set" in " ".join(result.discrepancies).lower()


@pytest.mark.parametrize("invalid_value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_metric_values_are_schema_mismatch(invalid_value):
    payload = evidence()
    payload["attempts_metric"]["results"][0]["value"] = invalid_value

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.PARTIAL
    assert result.failure_kind == TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH


def test_historical_evidence_from_another_process_or_build_is_inconsistent():
    payload = evidence()
    payload["command_traces"]["results"][0]["process_instance_id"] = "old-process"
    payload["blocked_logs"]["results"][0]["build_commit"] = "old-build"

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.INCONSISTENT
    assert result.failure_kind == TelemetryFailureKind.EVIDENCE_INCONSISTENT


def test_exporter_disabled_cannot_verify():
    result = reconcile(ctx=context(with_exporter=False))

    assert result.verdict == ProofVerdict.UNAVAILABLE
    assert result.failure_kind == TelemetryFailureKind.EXPORTER_UNAVAILABLE


def test_export_watermark_predating_command_is_inconsistent():
    ctx = context()
    assert ctx.export_watermark is not None
    ctx = replace(
        ctx,
        export_watermark=replace(
            ctx.export_watermark,
            exported_at_ms=COMMAND_TIME_MS - 1,
        ),
    )

    result = reconcile(ctx=ctx)

    assert result.verdict == ProofVerdict.INCONSISTENT
    assert "predates" in " ".join(result.discrepancies).lower()


def test_ambiguous_nested_result_containers_are_schema_mismatch():
    payload = evidence()
    payload["command_traces"]["data"] = deepcopy(
        payload["command_traces"]["results"]
    )

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.PARTIAL
    assert result.failure_kind == TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH


def test_malformed_timestamp_is_schema_mismatch():
    payload = evidence()
    payload["blocked_logs"]["results"][0]["timestamp_ms"] = "yesterday"

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.PARTIAL
    assert result.failure_kind == TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH


def test_out_of_window_rows_are_inconsistent():
    payload = evidence()
    payload["blocked_traces"]["results"][0]["timestamp_ms"] = WINDOW_END_MS + 1

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.INCONSISTENT
    assert "outside" in " ".join(result.discrepancies).lower()


def test_response_shape_drift_is_schema_mismatch():
    payload = evidence()
    payload["command_traces"]["results"][0]["unexpected_new_field"] = "drift"

    result = reconcile(payload)

    assert result.verdict == ProofVerdict.PARTIAL
    assert result.failure_kind == TelemetryFailureKind.RESPONSE_SCHEMA_MISMATCH


class _ErrorToolResult:
    structuredContent = {"results": []}
    content = []
    isError = True


def test_is_error_true_is_rejected_unconditionally():
    with pytest.raises(ValueError, match="MCP tool returned isError"):
        _normalize_tool_result(_ErrorToolResult())


class _StructuredWithWarning:
    structuredContent = {"results": []}
    content = [type("Text", (), {"text": "Input validation notice"})()]
    isError = False


def test_validation_warning_content_is_not_silently_discarded():
    with pytest.raises(ValueError, match="additional content"):
        _normalize_tool_result(_StructuredWithWarning())
