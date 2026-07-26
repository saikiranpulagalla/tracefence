from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tracefence.signoz.mcp_client import (
    ResponseSchemaError,
    _AdvisoryKind,
    _normalize_tool_result,
    _validate_advisories,
    _validate_advisory,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "signoz_mcp"


def load_tool_result(name: str) -> SimpleNamespace:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    content = [SimpleNamespace(**block) for block in payload["content"]]
    return SimpleNamespace(
        isError=payload["isError"],
        content=content,
        structuredContent=None,
    )


def query_builder_tool_result(
    result_sets: object,
    *advisories: str,
    query_data_extra: dict[str, object] | None = None,
    extra_result_set_fields: dict[str, object] | None = None,
) -> SimpleNamespace:
    if isinstance(result_sets, list) and extra_result_set_fields:
        result_sets = [
            {**result_set, **extra_result_set_fields}
            if isinstance(result_set, dict)
            else result_set
            for result_set in result_sets
        ]
    query_data: dict[str, object] = {"results": result_sets}
    if query_data_extra:
        query_data.update(query_data_extra)
    payload = {
        "status": "success",
        "data": {"type": "raw", "data": query_data, "meta": {}},
    }
    content = [SimpleNamespace(type="text", text=json.dumps(payload))]
    content.extend(SimpleNamespace(type="text", text=advisory) for advisory in advisories)
    return SimpleNamespace(isError=False, content=content, structuredContent=None)


def complete_note(rows: int = 0, limit: int = 1) -> str:
    return (
        f"note: returned {rows} rows (limit {limit}) — "
        "all matching results returned (hasMore=false)."
    )


def observed_result_set(*, cursor: object = "", rows: object = None) -> dict[str, object]:
    return {"queryName": "A", "rows": rows, "nextCursor": cursor}


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


@pytest.mark.parametrize(
    "fixture_name",
    ["live_trace_empty_next_cursor.json", "live_log_empty_next_cursor.json"],
)
def test_live_observed_empty_next_cursor_contract_is_accepted(fixture_name: str):
    """Sanitized fixtures capture the deployed SigNoz MCP contract seen at the RC2 gate."""

    assert _normalize_tool_result(load_tool_result(fixture_name)) == {"results": []}


def test_non_empty_rows_with_complete_next_cursor_metadata_are_accepted():
    result = _normalize_tool_result(
        query_builder_tool_result(
            [
                observed_result_set(
                    cursor="official-complete-page-cursor",
                    rows=[{"data": {"name": "tracefence.action.block"}}],
                )
            ],
            complete_note(rows=1),
        )
    )

    assert result == {"results": [{"operation": "tracefence.action.block"}]}


def test_official_warning_note_fails_closed():
    with pytest.raises(ResponseSchemaError, match="warning"):
        _normalize_tool_result(load_tool_result("warning_note.json"))


def test_multiple_json_content_blocks_are_rejected_as_ambiguous():
    with pytest.raises(ResponseSchemaError, match="ambiguous"):
        _normalize_tool_result(load_tool_result("malformed_ambiguous.json"))


def test_competing_query_builder_result_containers_are_rejected():
    with pytest.raises(ResponseSchemaError, match="container"):
        _normalize_tool_result(load_tool_result("ambiguous_containers.json"))


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


def test_legacy_exact_results_container_remains_accepted():
    result = SimpleNamespace(
        isError=False,
        structuredContent=None,
        content=[SimpleNamespace(type="text", text='{"results":[]}')],
    )

    assert _normalize_tool_result(result) == {"results": []}


def test_unknown_sibling_beside_results_is_rejected():
    with pytest.raises(ResponseSchemaError, match="data.data.results"):
        _normalize_tool_result(
            query_builder_tool_result([], query_data_extra={"unexpected": []})
        )


def test_unknown_sibling_beside_next_cursor_is_rejected():
    with pytest.raises(ResponseSchemaError, match="ambiguous row container"):
        _normalize_tool_result(
            query_builder_tool_result(
                [observed_result_set()],
                complete_note(),
                extra_result_set_fields={"cursorMetadata": {}},
            )
        )


@pytest.mark.parametrize("cursor", [None, 1, {}, []])
def test_incorrect_next_cursor_type_is_rejected(cursor: object):
    with pytest.raises(ResponseSchemaError, match="nextCursor"):
        _normalize_tool_result(
            query_builder_tool_result([observed_result_set(cursor=cursor)], complete_note())
        )


def test_non_empty_cursor_without_completeness_advisory_fails_closed():
    with pytest.raises(ResponseSchemaError, match="SigNoz evidence page is incomplete"):
        _normalize_tool_result(
            query_builder_tool_result(
                [observed_result_set(cursor="more-pages")],
            )
        )


@pytest.mark.parametrize(
    "advisory",
    [
        "note: returned 1 rows (limit 1) — more results exist (hasMore=true).",
        "note: returned 1 rows (limit 1) — result limited (hasMore=true).",
    ],
)
def test_incomplete_pagination_advisories_fail_closed(advisory: str):
    with pytest.raises(ResponseSchemaError, match="SigNoz evidence page is incomplete"):
        _normalize_tool_result(
            query_builder_tool_result([observed_result_set(cursor="more-pages")], advisory)
        )


def test_malformed_pagination_advisory_is_rejected():
    with pytest.raises(ResponseSchemaError, match="unknown advisory"):
        _normalize_tool_result(
            query_builder_tool_result(
                [observed_result_set()],
                "note: returned 0 rows (limit 1) all matching results returned hasMore=false",
            )
        )


def test_non_text_mcp_content_is_rejected():
    result = SimpleNamespace(
        isError=False,
        structuredContent=None,
        content=[SimpleNamespace(type="image", text=None)],
    )

    with pytest.raises(ResponseSchemaError, match="unexpected executable"):
        _normalize_tool_result(result)


def test_cursor_at_unobserved_query_data_nesting_is_rejected():
    with pytest.raises(ResponseSchemaError, match="data.data.results"):
        _normalize_tool_result(
            query_builder_tool_result([], query_data_extra={"nextCursor": ""})
        )


def test_missing_results_is_rejected():
    result = SimpleNamespace(
        isError=False,
        structuredContent=None,
        content=[
            SimpleNamespace(
                type="text",
                text=json.dumps({"status": "success", "data": {"type": "raw", "data": {}}}),
            )
        ],
    )

    with pytest.raises(ResponseSchemaError, match="data.data.results"):
        _normalize_tool_result(result)


def test_non_array_results_is_rejected():
    with pytest.raises(ResponseSchemaError, match="results must be an array"):
        _normalize_tool_result(query_builder_tool_result({"not": "an array"}))


def test_advisory_validation_returns_structured_pagination_state():
    assert _validate_advisories([]).kind is _AdvisoryKind.NO_PAGINATION
    assert _validate_advisory(complete_note()).kind is _AdvisoryKind.PAGE_COMPLETE
    assert _validate_advisory(
        "note: returned 1 rows (limit 1) — more results exist (hasMore=true)."
    ).kind is _AdvisoryKind.PAGE_INCOMPLETE
    assert _validate_advisory(
        "note: SigNoz backend returned non-fatal warnings:\n- safe summary"
    ).kind is _AdvisoryKind.BACKEND_WARNING
    assert _validate_advisory("unrecognized advisory").kind is _AdvisoryKind.UNKNOWN
