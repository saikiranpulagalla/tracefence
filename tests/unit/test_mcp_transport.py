from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace

import httpx

import tracefence.signoz.mcp_client as mcp_module
from tracefence.config import settings
from tracefence.domain.enums import ProofVerdict
from tracefence.signoz.mcp_client import SigNozMCPClient


ROOT = Path(__file__).resolve().parents[2]


class _ToolResult:
    def __init__(self, structured_content):
        self.structuredContent = structured_content
        self.content = []
        self.isError = False


class _FakeClientSession:
    def __init__(self, _read_stream, _write_stream) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc, _traceback):
        return False

    async def initialize(self) -> None:
        return None

    async def list_tools(self):
        return SimpleNamespace(
            tools=[
                SimpleNamespace(name="signoz_search_traces"),
                SimpleNamespace(name="signoz_search_logs"),
                SimpleNamespace(name="signoz_query_metrics"),
            ]
        )

    async def call_tool(self, name: str, arguments: dict):
        if name == "signoz_search_traces":
            rows = []
            if arguments.get("operation") == "tracefence.control.command_issue":
                rows = [
                    {
                        "name": "tracefence.control.command_issue",
                        "traceId": "d" * 32,
                        "command_id": "transport-command",
                    }
                ]
            return _ToolResult({"results": rows})
        if name == "signoz_search_logs":
            return _ToolResult({"results": []})
        metric_name = arguments["metricName"]
        return _ToolResult({"metric": metric_name, "value": 0})


async def test_supported_streamable_http_client_receives_owned_bounded_httpx_client(
    monkeypatch,
):
    captured: dict[str, object] = {}

    @asynccontextmanager
    async def fake_streamable_http_client(url: str, *, http_client: httpx.AsyncClient):
        captured["url"] = url
        captured["client"] = http_client
        captured["closed_inside"] = http_client.is_closed
        pool = http_client._transport._pool
        captured["max_connections"] = pool._max_connections
        captured["max_keepalive_connections"] = pool._max_keepalive_connections
        yield object(), object(), lambda: "session-id"

    fake_mcp = ModuleType("mcp")
    fake_mcp.__path__ = []
    fake_mcp.ClientSession = _FakeClientSession
    fake_client_package = ModuleType("mcp.client")
    fake_client_package.__path__ = []
    fake_streamable = ModuleType("mcp.client.streamable_http")
    fake_streamable.streamable_http_client = fake_streamable_http_client
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.client", fake_client_package)
    monkeypatch.setitem(sys.modules, "mcp.client.streamable_http", fake_streamable)
    monkeypatch.setattr(
        mcp_module,
        "settings",
        replace(
            settings,
            signoz_api_key="test-signoz-api-key",
            signoz_mcp_url="https://signoz.example.test/mcp",
        ),
    )

    result = await SigNozMCPClient().verify_command(
        command_id="transport-command",
        expected_stale_attempts=0,
        expected_stale_committed=0,
        start_ms=1_000,
        end_ms=2_000,
    )

    client = captured["client"]
    assert isinstance(client, httpx.AsyncClient)
    assert captured["url"] == "https://signoz.example.test/mcp"
    assert captured["closed_inside"] is False
    assert client.headers["SIGNOZ-API-KEY"] == "test-signoz-api-key"
    assert client.follow_redirects is False
    assert client.timeout.connect == 3
    assert client.timeout.read == 10
    assert client.timeout.write == 10
    assert client.timeout.pool == 3
    assert captured["max_connections"] == 4
    assert captured["max_keepalive_connections"] == 2
    assert client.is_closed is True
    assert result.verdict == ProofVerdict.VERIFIED


def test_patched_mcp_and_pytest_versions_are_declared_consistently():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    full = (ROOT / "requirements-full.txt").read_text(encoding="utf-8")
    dev = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")

    assert '"mcp>=1.28.1,<2"' in pyproject
    assert "mcp==1.28.1" in full
    assert '"pytest>=9.0.3,<10"' in pyproject
    assert "pytest==9.0.3" in dev
