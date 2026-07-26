from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tracefence.signoz.mcp_transport import create_mcp_http_client

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "script",
    ("provision_signoz.py", "verify_signoz.py"),
)
def test_operational_scripts_use_supported_mcp_http_client_contract(script: str) -> None:
    tree = ast.parse((ROOT / "scripts" / script).read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "streamable_http_client"
    ]
    assert len(calls) == 1
    assert {keyword.arg for keyword in calls[0].keywords} == {"http_client"}
    assert isinstance(calls[0].keywords[0].value, ast.Name)
    assert calls[0].keywords[0].value.id == "http_client"
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "create_mcp_http_client"
        for node in ast.walk(tree)
    )


async def test_operational_mcp_http_client_is_bounded_and_closes() -> None:
    client = create_mcp_http_client("test-signoz-api-key")
    try:
        pool = client._transport._pool
        assert client.headers["SIGNOZ-API-KEY"] == "test-signoz-api-key"
        assert client.follow_redirects is False
        assert client.timeout.connect == 3
        assert client.timeout.read == 10
        assert client.timeout.write == 10
        assert client.timeout.pool == 3
        assert pool._max_connections == 4
        assert pool._max_keepalive_connections == 2
        assert client.is_closed is False
    finally:
        await client.aclose()
    assert client.is_closed is True
