from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tracefence.signoz.mcp_client import ResponseSchemaError, _normalize_tool_result

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "signoz_mcp"


def load_tool_result(name: str) -> SimpleNamespace:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    content = [SimpleNamespace(**block) for block in payload["content"]]
    return SimpleNamespace(
        isError=payload["isError"],
        content=content,
        structuredContent=None,
    )


def test_official_trace_search_json_and_pagination_contract_is_accepted():
    result = _normalize_tool_result(load_tool_result("trace_search_page.json"))

    assert result["results"][0]["command_id"] == "command-123"
    assert result["results"][0]["timestamp_ms"] == 1_001_000


def test_official_log_search_json_and_pagination_contract_is_accepted():
    result = _normalize_tool_result(load_tool_result("log_search_page.json"))

    assert result["results"][0]["action_id"] == "action-123"
    assert result["results"][0]["event_name"] == "action_denied"


def test_official_empty_and_multiple_result_sets_are_unambiguous():
    assert _normalize_tool_result(load_tool_result("empty_results.json")) == {
        "results": []
    }
    assert _normalize_tool_result(load_tool_result("multiple_result_sets.json")) == {
        "results": []
    }


def test_official_warning_note_fails_closed():
    with pytest.raises(ResponseSchemaError, match="warning"):
        _normalize_tool_result(load_tool_result("warning_note.json"))


def test_multiple_json_content_blocks_are_rejected_as_ambiguous():
    with pytest.raises(ResponseSchemaError, match="ambiguous"):
        _normalize_tool_result(load_tool_result("malformed_ambiguous.json"))


def test_metric_raw_payload_uses_column_aliases_and_valid_decision_note():
    result = _normalize_tool_result(
        load_tool_result("metric_query.json"),
        defaults={"metric_name": "tracefence_stale_action_attempts_total"},
    )

    assert result == {
        "results": [
            {
                "metric_name": "tracefence_stale_action_attempts_total",
                "value": 1.0,
            }
        ]
    }
