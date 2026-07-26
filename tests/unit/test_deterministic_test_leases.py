from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace

import pytest

from tracefence.config import settings


def test_ordinary_pytest_bootstrap_uses_generous_test_lease() -> None:
    assert settings.environment == "test"
    assert settings.lease_ttl_seconds == 300
    assert settings.spawn_intent_ttl_seconds == 300


def test_runtime_default_lease_remains_seven_seconds_in_fresh_process() -> None:
    environment = os.environ.copy()
    environment.pop("TRACEFENCE_LEASE_TTL_SECONDS", None)
    environment.pop("TRACEFENCE_SPAWN_INTENT_TTL_SECONDS", None)
    environment.pop("TRACEFENCE_ENV", None)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from tracefence.config import settings; "
            "print(settings.lease_ttl_seconds, settings.spawn_intent_ttl_seconds)",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.stdout.split() == ["7", "60"]


def test_spawn_intent_ttl_is_bounded_in_security_validation() -> None:
    secure = replace(
        settings,
        environment="development",
        operator_key="o" * 32,
        token_hash_secret="t" * 48,
        credential_recovery_key="r" * 48,
        evidence_signing_key="e" * 48,
    )

    for value in (5, 300):
        replace(secure, spawn_intent_ttl_seconds=value).validate_security()
    for value in (4, 301):
        with pytest.raises(
            RuntimeError,
            match="TRACEFENCE_SPAWN_INTENT_TTL_SECONDS must be between 5 and 300",
        ):
            replace(secure, spawn_intent_ttl_seconds=value).validate_security()
