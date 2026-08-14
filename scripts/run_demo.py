from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path


def demo_environment(
    inherited: Mapping[str, str],
    database_path: Path,
) -> dict[str, str]:
    environment = dict(inherited)
    for name in (
        "SIGNOZ_API_KEY",
        "SIGNOZ_URL",
        "SIGNOZ_MCP_URL",
        "TRACEFENCE_NOTIFICATION_CHANNEL",
        "OTEL_EXPORTER_OTLP_HEADERS",
    ):
        environment.pop(name, None)
    generated = [secrets.token_urlsafe(48) for _ in range(4)]
    environment.update(
        {
            "TRACEFENCE_ENV": "development",
            "TRACEFENCE_DEMO_MODE": "true",
            "TRACEFENCE_OPERATOR_KEY": generated[0],
            "TRACEFENCE_TOKEN_HASH_SECRET": generated[1],
            "TRACEFENCE_CREDENTIAL_RECOVERY_KEY": generated[2],
            "TRACEFENCE_EVIDENCE_SIGNING_KEY": generated[3],
            "TRACEFENCE_DATABASE_URL": f"sqlite+pysqlite:///{database_path}",
            "TRACEFENCE_DEMO_API_URL": "http://127.0.0.1:9000",
            "OTEL_SDK_DISABLED": "true",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "",
        }
    )
    return environment


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    demo_dir = (root / "data" / "demo").resolve()
    demo_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    database_path = demo_dir / f"tracefence-demo-{stamp}-{os.getpid()}.db"
    environment = demo_environment(os.environ, database_path)
    os.environ.clear()
    os.environ.update(environment)

    # Import only after the complete hermetic demo environment is installed;
    # tracefence.config intentionally creates one immutable settings snapshot.
    import uvicorn

    print("TraceFence Runtime Inspector:", flush=True)
    print("http://127.0.0.1:9000/", flush=True)
    print("External telemetry: disabled for this local demo", flush=True)
    uvicorn.run(
        "tracefence.api.main:app",
        host="127.0.0.1",
        port=9000,
        reload=False,
        access_log=False,
    )


if __name__ == "__main__":
    main()
