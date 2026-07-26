from __future__ import annotations

from scripts.run_local_tests import hermetic_test_environment


def test_hermetic_test_environment_removes_live_telemetry_credentials() -> None:
    environment = hermetic_test_environment(
        {
            "SIGNOZ_API_KEY": "private-api-key",
            "TRACEFENCE_NOTIFICATION_CHANNEL": "private-channel",
            "OTEL_EXPORTER_OTLP_HEADERS": "authorization=private",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318",
            "SIGNOZ_URL": "http://127.0.0.1:8080",
            "SIGNOZ_MCP_URL": "http://127.0.0.1:8000/mcp",
            "TRACEFENCE_RUN_LIVE_SIGNOZ_MCP": "1",
        }
    )

    assert environment["TRACEFENCE_ENV"] == "test"
    assert environment["TRACEFENCE_LEASE_TTL_SECONDS"] == "300"
    assert environment["TRACEFENCE_SPAWN_INTENT_TTL_SECONDS"] == "300"
    assert environment["TRACEFENCE_RUN_LIVE_SIGNOZ_MCP"] == "0"
    assert environment["OTEL_SDK_DISABLED"] == "true"
    assert environment["SIGNOZ_URL"] == "http://127.0.0.1:1"
    assert environment["SIGNOZ_MCP_URL"] == "http://127.0.0.1:1/mcp"
    assert environment["OTEL_EXPORTER_OTLP_ENDPOINT"] == ""
    for credential_name in (
        "SIGNOZ_API_KEY",
        "TRACEFENCE_NOTIFICATION_CHANNEL",
        "OTEL_EXPORTER_OTLP_HEADERS",
    ):
        assert credential_name not in environment
