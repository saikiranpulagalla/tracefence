from __future__ import annotations

from tracefence.domain.enums import ProofVerdict
from tracefence.signoz.mcp_client import _reconcile_evidence


def evidence(command_id: str, *, blocked: int = 1, committed: int = 0):
    trace_id = "a" * 32
    return {
        "command_traces": {
            "results": [
                {
                    "name": "tracefence.control.command_issue",
                    "traceId": trace_id,
                    "command_id": command_id,
                }
            ]
        },
        "blocked_traces": {
            "results": [
                {
                    "name": "tracefence.action.block",
                    "traceId": trace_id,
                    "command_id": command_id,
                }
                for _ in range(blocked)
            ]
        },
        "blocked_logs": {
            "results": [
                {"body": f"action_denied command_id={command_id}"}
                for _ in range(blocked)
            ]
        },
        "attempts_metric": {
            "metric": "tracefence_stale_action_attempts_total",
            "value": blocked,
        },
        "committed_metric": {
            "metric": "tracefence_stale_actions_committed_total",
            "value": committed,
        },
        "expected_stale_attempts": 1,
        "expected_stale_committed": 0,
    }


def test_structured_mcp_evidence_reconciles_to_verified():
    result = _reconcile_evidence("command-123", evidence("command-123"))
    assert result.verdict == ProofVerdict.VERIFIED
    assert result.trace_ids == ["a" * 32]


def test_mcp_count_disagreement_is_inconsistent():
    result = _reconcile_evidence("command-123", evidence("command-123", blocked=2))
    assert result.verdict == ProofVerdict.INCONSISTENT
    assert any("Blocked trace count" in item for item in result.discrepancies)


def test_nonzero_stale_committed_metric_is_inconsistent():
    result = _reconcile_evidence("command-123", evidence("command-123", committed=1))
    assert result.verdict == ProofVerdict.INCONSISTENT
    assert any("Stale-committed metric delta" in item for item in result.discrepancies)


def test_global_attempt_metric_may_include_concurrent_commands():
    payload = evidence("command-123")
    payload["attempts_metric"]["value"] = 3
    result = _reconcile_evidence("command-123", payload)
    assert result.verdict == ProofVerdict.VERIFIED


def test_global_attempt_metric_cannot_undercount_command_evidence():
    payload = evidence("command-123")
    payload["attempts_metric"]["value"] = 0
    result = _reconcile_evidence("command-123", payload)
    assert result.verdict == ProofVerdict.INCONSISTENT
    assert any("below runtime count" in item for item in result.discrepancies)


def test_mcp_input_validation_notice_prevents_verified_proof():
    payload = evidence("command-123")
    payload["blocked_logs"]["notice"] = "Input validation notice: ignored unknown field"
    result = _reconcile_evidence("command-123", payload)
    assert result.verdict == ProofVerdict.PARTIAL
    assert any("validation notice" in item.lower() for item in result.discrepancies)


def test_concrete_result_rows_take_precedence_over_unrelated_metadata_count():
    payload = evidence("command-123")
    payload["blocked_traces"]["metadata"] = {"count": 999}
    result = _reconcile_evidence("command-123", payload)
    assert result.verdict == ProofVerdict.VERIFIED


class _TextItem:
    def __init__(self, text: str):
        self.text = text


class _StructuredWithNotice:
    def __init__(self):
        self.structuredContent = {"results": [{"name": "tracefence.action.block"}]}
        self.content = [_TextItem("Input validation notice: unknown argument")]
        self.isError = False


def test_normalization_preserves_notice_beside_structured_content():
    from tracefence.signoz.mcp_client import _normalize_tool_result

    normalized = _normalize_tool_result(_StructuredWithNotice())
    assert normalized["structured"]["results"]
    assert "Input validation notice" in str(normalized["content"])
