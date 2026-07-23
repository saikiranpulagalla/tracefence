from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from tests.helpers import create_seeded_run
from tracefence.api.main import app
from tracefence.config import settings
from tracefence.services.run_service import RunService


async def test_non_ascii_operator_key_is_unauthorized_not_internal_error():
    from tests.unit.test_release_hardening import _asgi_request

    messages = await _asgi_request(
        app,
        path="/v1/runs",
        headers=[(b"x-operator-key", b"not-ascii-\xff")],
    )
    assert messages[0]["status"] == 401


async def test_run_listing_is_bounded_and_offset_paginated(session_factory):
    await create_seeded_run(session_factory, "page-one")
    await create_seeded_run(session_factory, "page-two")
    await create_seeded_run(session_factory, "page-three")

    page = await RunService(session_factory).list_runs(limit=1, offset=1)

    assert len(page) == 1


def test_test_environment_does_not_blanket_bypass_security(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    insecure = replace(
        settings,
        environment="test",
        operator_key="",
        evidence_signing_key="",
    )
    with pytest.raises(RuntimeError, match="TRACEFENCE_OPERATOR_KEY"):
        insecure.validate_security()


def test_frontend_contains_immediate_state_clearing_and_submission_guard():
    root = Path(__file__).resolve().parents[2]
    source = (root / "src/tracefence/frontend/app.js").read_text(
        encoding="utf-8"
    )
    markup = (root / "src/tracefence/frontend/index.html").read_text(
        encoding="utf-8"
    )

    assert "clearProtectedState" in source
    assert "commandSubmitting" in source
    assert "response.status === 401" in source
    assert "aria-live" in markup
