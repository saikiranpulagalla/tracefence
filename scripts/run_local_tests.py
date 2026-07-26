from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from typing import NoReturn


def hermetic_test_environment(parent: Mapping[str, str]) -> dict[str, str]:
    """Return the isolated environment used by ordinary local pytest runs."""

    environment = dict(parent)
    environment.update(
        {
            "TRACEFENCE_ENV": "test",
            "TRACEFENCE_LEASE_TTL_SECONDS": "300",
            "TRACEFENCE_SPAWN_INTENT_TTL_SECONDS": "300",
            "TRACEFENCE_RUN_LIVE_SIGNOZ_MCP": "0",
            "SIGNOZ_URL": "http://127.0.0.1:1",
            "SIGNOZ_MCP_URL": "http://127.0.0.1:1/mcp",
            "OTEL_SDK_DISABLED": "true",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "",
        }
    )
    for name in (
        "SIGNOZ_API_KEY",
        "TRACEFENCE_NOTIFICATION_CHANNEL",
        "OTEL_EXPORTER_OTLP_HEADERS",
    ):
        environment.pop(name, None)
    return environment


def main(arguments: Sequence[str] | None = None) -> NoReturn:
    pytest_arguments = list(sys.argv[1:] if arguments is None else arguments)
    # The fixed interpreter path runs pytest without a shell; its arguments
    # are the explicit arguments supplied to this local test-runner command.
    os.execvpe(  # nosec B606
        sys.executable,
        [sys.executable, "-m", "pytest", *pytest_arguments],
        hermetic_test_environment(os.environ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
