from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tracefence.signoz.mcp_client import ResponseSchemaError, normalize_metric_query_values


def _result(payload: dict[str, object]) -> SimpleNamespace:
    return SimpleNamespace(
        content=[
            SimpleNamespace(type="text", text=json.dumps(payload)),
            SimpleNamespace(type="text", text="[Decisions applied]\n  metricType: sum"),
        ],
        isError=False,
    )


def _payload(data: list[object]) -> dict[str, object]:
    return {
        "status": "success",
        "data": {
            "type": "scalar",
            "data": {
                "results": [
                    {"queryName": "A", "columns": None, "data": data},
                ]
            },
            "warning": {"warnings": []},
        },
    }


def test_empty_official_scalar_result_without_columns_is_normalized() -> None:
    """Captured live failure-only metric form: columns=null, data=[]."""

    assert normalize_metric_query_values(
        _result(_payload([])),
        expected_metric_name="tracefence_stale_actions_committed_total",
    ) == []


def test_nonempty_scalar_result_without_columns_remains_rejected() -> None:
    with pytest.raises(ResponseSchemaError, match="requires columns"):
        normalize_metric_query_values(
            _result(_payload([[0.0]])),
            expected_metric_name="tracefence_stale_actions_committed_total",
        )
