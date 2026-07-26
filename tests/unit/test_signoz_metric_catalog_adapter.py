from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tracefence.signoz.mcp_client import (
    MCPToolResultError,
    ResponseSchemaError,
    normalize_metric_catalog_names,
    normalize_metric_query_values,
)


class _TextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


def _complete_note(rows: int = 0, limit: int = 1) -> str:
    return (
        f"note: returned {rows} rows (limit {limit}) — "
        "all matching results returned (hasMore=false)."
    )


def _metric_decision_note() -> str:
    return "[Decisions applied]\n  metricType: gauge"


def test_metric_catalog_adapter_accepts_observed_official_envelope() -> None:
    payload = {
        "status": "success",
        "data": {
            "metrics": [
                {
                    "description": "Sanitized observable gauge description",
                    "metricName": "tracefence_active_nodes",
                    "type": "gauge",
                    "temporality": "unspecified",
                    "isMonotonic": False,
                    "unit": "1",
                }
            ]
        },
    }
    result = SimpleNamespace(
        content=[_TextBlock(json.dumps(payload)), _TextBlock(_complete_note())],
        isError=False,
    )

    assert normalize_metric_catalog_names(result) == {"tracefence_active_nodes"}


def test_metric_catalog_adapter_requires_the_official_complete_pagination_note() -> None:
    payload = {
        "status": "success",
        "data": {"metrics": [{"metricName": "tracefence_active_nodes"}]},
    }
    missing_note = SimpleNamespace(content=[_TextBlock(json.dumps(payload))], isError=False)
    incomplete_note = SimpleNamespace(
        content=[
            _TextBlock(json.dumps(payload)),
            _TextBlock("note: returned 100 rows (limit 100) -- more results exist."),
        ],
        isError=False,
    )

    with pytest.raises(ResponseSchemaError, match="complete pagination advisory"):
        normalize_metric_catalog_names(missing_note)
    with pytest.raises(ResponseSchemaError, match="evidence page is incomplete"):
        normalize_metric_catalog_names(incomplete_note)


@pytest.mark.parametrize(
    "payload",
    (
        {"status": "success", "data": {"metrics": [{"metricName": "tracefence_active_nodes", "x": 1}]}},
        {"status": "success", "data": {"metrics": [{"metricName": "tracefence_active_nodes"}, {"metricName": "tracefence_active_nodes"}]}},
        {"status": "success", "data": {"metrics": "not-an-array"}},
    ),
)
def test_metric_catalog_adapter_rejects_ambiguous_or_malformed_rows(payload: dict[str, object]) -> None:
    result = SimpleNamespace(content=[], structuredContent=payload, isError=False)

    with pytest.raises(ResponseSchemaError):
        normalize_metric_catalog_names(result)


def test_metric_catalog_adapter_rejects_mcp_tool_error() -> None:
    with pytest.raises(MCPToolResultError):
        normalize_metric_catalog_names(SimpleNamespace(content=[], isError=True))


def test_current_metric_query_requires_expected_finite_metric_values() -> None:
    result = SimpleNamespace(
        content=[],
        structuredContent={
            "results": [{"metric_name": "tracefence_active_nodes", "value": 0.0}]
        },
        isError=False,
    )

    assert normalize_metric_query_values(
        result,
        expected_metric_name="tracefence_active_nodes",
    ) == [0.0]

    invalid = SimpleNamespace(
        content=[],
        structuredContent={
            "results": [{"metric_name": "other", "value": float("nan")}]
        },
        isError=False,
    )
    with pytest.raises(ResponseSchemaError):
        normalize_metric_query_values(
            invalid,
            expected_metric_name="tracefence_active_nodes",
        )


def test_current_metric_query_adapts_an_official_scalar_query_builder_response() -> None:
    payload = {
        "status": "success",
        "data": {
            "type": "scalar",
            "data": {
                "results": [
                    {
                        "queryName": "A",
                        "columns": [
                            {
                                "aggregationIndex": 0,
                                "columnType": "number",
                                "fieldContext": "metric",
                                "fieldDataType": "float64",
                                "meta": {},
                                "name": "__result_0",
                                "queryName": "A",
                                "signal": "metrics",
                            }
                        ],
                        "data": [[0.0]],
                    }
                ]
            },
        },
    }
    result = SimpleNamespace(
        content=[_TextBlock(json.dumps(payload)), _TextBlock(_metric_decision_note())],
        isError=False,
    )

    assert normalize_metric_query_values(
        result,
        expected_metric_name="tracefence_active_nodes",
    ) == [0.0]


def test_current_metric_query_rejects_mixed_or_unknown_metric_data_containers() -> None:
    payload = {
        "status": "success",
        "data": {
            "type": "scalar",
            "data": {
                "results": [
                    {
                        "queryName": "A",
                        "columns": [{"name": "__result_0"}],
                        "data": [[0.0]],
                        "nextCursor": "",
                    }
                ]
            },
        },
    }
    result = SimpleNamespace(
        content=[_TextBlock(json.dumps(payload)), _TextBlock(_metric_decision_note())],
        isError=False,
    )

    with pytest.raises(ResponseSchemaError, match="ambiguous row container"):
        normalize_metric_query_values(
            result,
            expected_metric_name="tracefence_active_nodes",
        )


@pytest.mark.parametrize(
    "advisory",
    (
        "note: SigNoz backend returned non-fatal warnings: query warning",
        "[Decisions applied]\\nmalformed decision advisory",
    ),
)
def test_current_metric_query_rejects_unsafe_raw_query_builder_advisories(advisory: str) -> None:
    payload = {
        "status": "success",
        "data": {
            "type": "scalar",
            "data": {
                "results": [
                    {
                        "queryName": "A",
                        "rows": [{"data": {"__result": 0.0}}],
                        "nextCursor": "",
                    }
                ]
            },
        },
    }
    result = SimpleNamespace(
        content=[_TextBlock(json.dumps(payload)), _TextBlock(advisory)],
        isError=False,
    )

    with pytest.raises(ResponseSchemaError):
        normalize_metric_query_values(
            result,
            expected_metric_name="tracefence_active_nodes",
        )
