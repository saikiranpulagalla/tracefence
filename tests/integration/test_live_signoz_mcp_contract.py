from __future__ import annotations

import os
import time
from contextlib import AsyncExitStack

import httpx
import pytest

from tracefence.signoz.mcp_client import _normalize_tool_result


@pytest.mark.skipif(
    not (
        os.getenv("TRACEFENCE_RUN_LIVE_SIGNOZ_MCP") == "1"
        and os.getenv("SIGNOZ_MCP_URL")
        and os.getenv("SIGNOZ_API_KEY")
    ),
    reason="live SigNoz MCP contract test requires explicit opt-in and credentials",
)
async def test_live_signoz_search_response_matches_strict_adapter() -> None:
    """Exercise the official JSON-first wire contract without embedding credentials."""

    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    end_ms = int(time.time() * 1000)
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
        result = await session.call_tool(
            "signoz_search_traces",
            arguments={
                "searchContext": "TraceFence live MCP response contract test",
                "filter": (
                    "attribute.tracefence.command.id = "
                    "'tracefence-contract-test-no-match'"
                ),
                "start": end_ms - 60_000,
                "end": end_ms,
                "limit": 1,
                "offset": 0,
            },
        )

    assert _normalize_tool_result(result) == {"results": []}
