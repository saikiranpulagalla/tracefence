"""Shared bounded HTTP transport for SigNoz MCP operational tools."""

from __future__ import annotations

import httpx


def create_mcp_http_client(api_key: str) -> httpx.AsyncClient:
    """Create an owned, bounded client for one SigNoz MCP operation."""

    return httpx.AsyncClient(
        headers={"SIGNOZ-API-KEY": api_key},
        timeout=httpx.Timeout(connect=3, read=10, write=10, pool=3),
        limits=httpx.Limits(
            max_connections=4,
            max_keepalive_connections=2,
        ),
        follow_redirects=False,
    )
