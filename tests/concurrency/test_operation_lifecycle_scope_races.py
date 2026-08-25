from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from sqlalchemy import select

from tests.concurrency.test_operation_lifecycle_races import (
    REPETITIONS,
    _accept,
    _cancel,
    _dispatched,
    _human,
    _pause_cancellation,
    _pause_result,
    _wait,
)
from tracefence.db.models import ActionAuthorityBinding, ControlScope, Run
from tracefence.services.control_service import ControlService


@pytest.mark.parametrize("iteration", REPETITIONS)
async def test_result_before_scope_change_remains_authoritative(
    session_factory, monkeypatch, iteration
):
    run, lifecycle, action, worker = await _dispatched(
        session_factory, f"operation-race-d1-{iteration}"
    )
    result_ready, release_result = Event(), Event()
    _pause_result(monkeypatch, lifecycle, ready=result_ready, release=release_result)

    def cancel_scope():
        return asyncio.run(
            ControlService(session_factory).issue_command(
                _cancel(run.root_node_id, f"d1-cancel-{iteration}"), _human(f"d1-{iteration}")
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = pool.submit(lambda: asyncio.run(_accept(lifecycle, action, worker)))
        _wait(result_ready)
        scope_change = pool.submit(cancel_scope)
        assert not scope_change.done()
        release_result.set()
        accepted = result.result(timeout=10)
        scope_change.result(timeout=10)

    assert accepted.accepted is True
    assert accepted.action.execution_state == "SUCCEEDED"


@pytest.mark.parametrize("iteration", REPETITIONS)
async def test_scope_change_before_result_is_stale(session_factory, monkeypatch, iteration):
    run, lifecycle, action, worker = await _dispatched(
        session_factory, f"operation-race-d2-{iteration}"
    )
    with session_factory() as session:
        binding = session.scalar(
            select(ActionAuthorityBinding).where(ActionAuthorityBinding.action_id == action.id)
        )
        assert binding is not None
        bound_version = binding.bound_version

    cancel_ready, release_cancel = Event(), Event()
    _pause_cancellation(monkeypatch, ready=cancel_ready, release=release_cancel)

    def cancel_scope():
        return asyncio.run(
            ControlService(session_factory).issue_command(
                _cancel(run.root_node_id, f"d2-cancel-{iteration}"), _human(f"d2-{iteration}")
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        scope_change = pool.submit(cancel_scope)
        _wait(cancel_ready)
        result = pool.submit(lambda: asyncio.run(_accept(lifecycle, action, worker)))
        assert not result.done()
        release_cancel.set()
        scope_change.result(timeout=10)
        stale = result.result(timeout=10)

    with session_factory() as session:
        scope = session.get(ControlScope, binding.scope_id)
        assert scope is not None and scope.version > bound_version
    assert stale.accepted is False
    assert stale.action.execution_state == "STALE"
    assert stale.action.stale_reason_code in {"SCOPE_CANCELLED", "AUTHORITY_VECTOR_CHANGED"}


async def test_unrelated_proof_revision_does_not_stale_dispatched_operation(session_factory):
    run, lifecycle, action, worker = await _dispatched(
        session_factory, "operation-race-proof-neutral"
    )
    with session_factory.begin() as session:
        row = session.get(Run, run.run_id)
        assert row is not None
        row.proof_revision += 1

    accepted = await _accept(lifecycle, action, worker)
    assert accepted.accepted is True
    assert accepted.action.execution_state == "SUCCEEDED"
