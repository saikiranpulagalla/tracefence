from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import AsyncExitStack
from typing import Any

import httpx
import pytest

from tracefence.signoz.mcp_client import _normalize_tool_result


def _redacted_result_structure(result: Any) -> dict[str, object]:
    """Return only content-block shapes; never include payload text or headers."""

    blocks: list[dict[str, object]] = []
    content = getattr(result, "content", None)
    if not isinstance(content, list):
        return {"content_type": type(content).__name__}
    for index, block in enumerate(content):
        block_type = getattr(block, "type", None)
        summary: dict[str, object] = {"index": index, "type": block_type}
        text = getattr(block, "text", None)
        if block_type != "text" or not isinstance(text, str):
            summary["classification"] = "non-text"
            blocks.append(summary)
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            summary["classification"] = "advisory"
            blocks.append(summary)
            continue
        summary["classification"] = "json"
        if isinstance(payload, dict):
            summary["root_keys"] = sorted(payload)
            outer = payload.get("data")
            if isinstance(outer, dict):
                summary["data_keys"] = sorted(outer)
                inner = outer.get("data")
                if isinstance(inner, dict):
                    result_sets = inner.get("results")
                    summary["results_type"] = type(result_sets).__name__
                    if isinstance(result_sets, list):
                        summary["result_set_keys"] = [
                            sorted(item) if isinstance(item, dict) else type(item).__name__
                            for item in result_sets
                        ]
        blocks.append(summary)
    return {"content_block_count": len(content), "blocks": blocks}


def _assert_empty_normalized_result(result: Any, tool_name: str) -> None:
    try:
        normalized = _normalize_tool_result(result)
    except ValueError as exc:
        pytest.fail(
            f"{tool_name} strict normalization failed: {exc}; "
            f"redacted structure={_redacted_result_structure(result)}"
        )
    assert normalized == {"results": []}, (
        f"{tool_name} returned unexpected evidence; "
        f"redacted structure={_redacted_result_structure(result)}"
    )


@pytest.mark.skipif(
    not (
        os.getenv("TRACEFENCE_RUN_LIVE_SIGNOZ_MCP") == "1"
        and os.getenv("SIGNOZ_MCP_URL")
        and os.getenv("SIGNOZ_API_KEY")
    ),
    reason="live SigNoz MCP contract test requires explicit opt-in and credentials",
)
async def test_live_signoz_search_responses_match_strict_adapter() -> None:
    """Exercise trace and log JSON-first contracts without embedding credentials."""

    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    end_ms = int(time.time() * 1000)
    no_match = f"tracefence-contract-test-no-match-{uuid.uuid4().hex}"
    async with AsyncExitStack() as stack:
        http_client = await stack.enter_async_context(
            httpx.AsyncClient(
                headers={"SIGNOZ-API-KEY": os.environ["SIGNOZ_API_KEY"]},
                timeout=httpx.Timeout(connect=3, read=10, write=10, pool=3),
                limits=httpx.Limits(
                    max_connections=2,
                    max_keepalive_connections=1,
                ),
                follow_redirects=False,
            )
        )
        streams = await stack.enter_async_context(
            streamable_http_client(
                os.environ["SIGNOZ_MCP_URL"],
                http_client=http_client,
            )
        )
        read_stream, write_stream, _ = streams
        session = await stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await session.initialize()
        trace_result = await session.call_tool(
            "signoz_search_traces",
            arguments={
                "searchContext": "TraceFence live MCP response contract test",
                "filter": f"attribute.tracefence.command.id = '{no_match}'",
                "start": end_ms - 60_000,
                "end": end_ms,
                "limit": 1,
                "offset": 0,
            },
        )
        log_result = await session.call_tool(
            "signoz_search_logs",
            arguments={
                "searchContext": "TraceFence live MCP response contract test",
                "searchText": no_match,
                "start": end_ms - 60_000,
                "end": end_ms,
                "limit": 1,
                "offset": 0,
            },
        )

    _assert_empty_normalized_result(trace_result, "signoz_search_traces")
    _assert_empty_normalized_result(log_result, "signoz_search_logs")
