from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import text

import tracefence.services.action_gateway as gateway_module
import tracefence.services.control_service as control_module
import tracefence.services.operation_lifecycle as lifecycle_module
from tests.helpers import create_v2_run
from tracefence.db.models import (
    ActionAttempt,
    Node,
    WorkerInstance,
)
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal
from tracefence.security import hash_token, payload_digest
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.operation_lifecycle import OperationLifecycleService

REPETITIONS = range(25)
ORDERED_CASES = (
    "cancel-before-reserve",
    "reserve-before-cancel",
    "result-before-cancel",
    "cancel-before-result",
    "w1-result-before-w2",
    "w2-before-w1-result",
    "result-before-scope-change",
    "scope-change-before-result",
)


def _request(key: str, tool_name: str = "restart_postgres") -> ActionExecute:
    return ActionExecute(idempotency_key=key, tool_name=tool_name, arguments={})


def _cancel(node_id: str, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_RUN,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="deterministic operation lifecycle writer ordering",
    )


def _human(key: str) -> Principal:
    return Principal(issuer_type=IssuerType.HUMAN, principal_id=f"operation-race-{key}")


def _wait(event: Event) -> None:
    assert event.wait(timeout=5), "deterministic race synchronization point was not reached"


async def _worker(session_factory, node_id: str) -> WorkerInstance:
    with session_factory() as session:
        node = session.get(Node, node_id)
        assert node is not None and node.current_worker_instance_id is not None
        worker = session.get(WorkerInstance, node.current_worker_instance_id)
        assert worker is not None
        return worker


async def _dispatched(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    lifecycle = OperationLifecycleService(session_factory)
    action = await lifecycle.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request(f"{name}-action")
    )
    worker = await _worker(session_factory, run.root_node_id)
    lifecycle.mark_dispatched(
        action_id=action.id,
        worker_instance_id=worker.id,
        worker_incarnation=worker.incarnation,
    )
    return run, lifecycle, action, worker


async def _accept(
    lifecycle: OperationLifecycleService, action: ActionAttempt, worker: WorkerInstance
):
    return await lifecycle.accept_result(
        action_id=action.id,
        worker_instance_id=worker.id,
        worker_incarnation=worker.incarnation,
        tool_name=action.tool_name,
        arguments_digest=payload_digest({}),
        result={"external_effect": "dispatched"},
    )


def _pause_cancellation(monkeypatch, *, ready: Event, release: Event) -> None:
    original = control_module.record_runtime_event

    def paused(*args, **kwargs):
        result = original(*args, **kwargs)
        if kwargs.get("event_type") == "SCOPE_CANCELLED":
            ready.set()
            _wait(release)
        return result

    monkeypatch.setattr(control_module, "record_runtime_event", paused)


def _pause_result(
    monkeypatch, lifecycle: OperationLifecycleService, *, ready: Event, release: Event
) -> None:
    original = lifecycle._stale_reason

    async def paused(*args, **kwargs):
        ready.set()
        _wait(release)
        return await original(*args, **kwargs)

    monkeypatch.setattr(lifecycle, "_stale_reason", paused)


def _switch_to_w2(session_factory, *, node_id: str, ready: Event, release: Event) -> str:
    """Commit a test-owned replacement pointer with an independent SQLite session.

    Production currently has no same-node WorkerInstance reactivation command.
    This is the existing protocol-v2 fencing fixture: a durable W2 row and
    current-worker pointer transition, never a PID- or process-control path.
    """

    with session_factory() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        try:
            node = session.get(Node, node_id)
            assert node is not None and node.current_worker_instance_id is not None
            first = session.get(WorkerInstance, node.current_worker_instance_id)
            assert first is not None
            second = WorkerInstance(
                id=str(uuid4()),
                node_id=node.id,
                incarnation=first.incarnation + 1,
                observed_state="ACTIVE",
                activated_at=utcnow(),
                credential_hash=hash_token("operation-race-w2"),
            )
            session.add(second)
            session.flush()
            node.current_worker_instance_id = second.id
            session.flush()
            ready.set()
            _wait(release)
            session.commit()
            return second.id
        except Exception:
            session.rollback()
            raise


def _counting_restart_spec(counter: list[int]):
    original = gateway_module.get_tool_spec("restart_postgres")

    def counted(session, run_id: str, action_id: str, arguments: dict):
        counter[0] += 1
        return original.executor(session, run_id, action_id, arguments)

    return replace(original, executor=counted)


@pytest.mark.parametrize("iteration", REPETITIONS)
async def test_cancel_before_reservation_blocks_local_effect_dispatch(
    session_factory, monkeypatch, iteration
):
    run = await create_v2_run(session_factory, f"operation-race-a1-{iteration}")
    cancel_ready, release_cancel = Event(), Event()
    _pause_cancellation(monkeypatch, ready=cancel_ready, release=release_cancel)
    dispatch_count = [0]
    spec = _counting_restart_spec(dispatch_count)
    monkeypatch.setattr(gateway_module, "get_tool_spec", lambda _name: spec)

    def cancel():
        return asyncio.run(
            ControlService(session_factory).issue_command(
                _cancel(run.root_node_id, f"a1-cancel-{iteration}"), _human(f"a1-{iteration}")
            )
        )

    def execute():
        return asyncio.run(
            ActionGateway(session_factory).execute(
                run.root_node_id, run.root_token, _request(f"a1-action-{iteration}")
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        cancellation = pool.submit(cancel)
        _wait(cancel_ready)
        action = pool.submit(execute)
        assert not action.done()
        release_cancel.set()
        cancellation.result(timeout=10)
        denied = action.result(timeout=10)

    assert denied.committed is False
    assert dispatch_count == [0]


@pytest.mark.parametrize("iteration", REPETITIONS)
async def test_reservation_before_cancellation_preserves_authorized_history(
    session_factory, monkeypatch, iteration
):
    run = await create_v2_run(session_factory, f"operation-race-a2-{iteration}")
    lifecycle = OperationLifecycleService(session_factory)
    reserve_ready, release_reserve = Event(), Event()
    original = lifecycle_module.authenticate_execution_principal

    async def paused(*args, **kwargs):
        principal = await original(*args, **kwargs)
        reserve_ready.set()
        _wait(release_reserve)
        return principal

    monkeypatch.setattr(lifecycle_module, "authenticate_execution_principal", paused)

    def reserve():
        return asyncio.run(
            lifecycle.reserve(
                node_id=run.root_node_id,
                credential=run.root_token,
                request=_request(f"a2-action-{iteration}"),
            )
        )

    def cancel():
        return asyncio.run(
            ControlService(session_factory).issue_command(
                _cancel(run.root_node_id, f"a2-cancel-{iteration}"), _human(f"a2-{iteration}")
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        reservation = pool.submit(reserve)
        _wait(reserve_ready)
        cancellation = pool.submit(cancel)
        assert not cancellation.done()
        release_reserve.set()
        action = reservation.result(timeout=10)
        cancellation.result(timeout=10)

    with session_factory() as session:
        persisted = session.get(ActionAttempt, action.id)
        assert persisted is not None and persisted.execution_state == "AUTHORIZED"


@pytest.mark.parametrize("iteration", REPETITIONS)
async def test_result_before_cancellation_remains_authoritative(
    session_factory, monkeypatch, iteration
):
    run, lifecycle, action, worker = await _dispatched(
        session_factory, f"operation-race-b1-{iteration}"
    )
    result_ready, release_result = Event(), Event()
    _pause_result(monkeypatch, lifecycle, ready=result_ready, release=release_result)

    def accept():
        return asyncio.run(_accept(lifecycle, action, worker))

    def cancel():
        return asyncio.run(
            ControlService(session_factory).issue_command(
                _cancel(run.root_node_id, f"b1-cancel-{iteration}"), _human(f"b1-{iteration}")
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = pool.submit(accept)
        _wait(result_ready)
        cancellation = pool.submit(cancel)
        assert not cancellation.done()
        release_result.set()
        accepted = result.result(timeout=10)
        cancellation.result(timeout=10)

    assert accepted.accepted is True
    assert accepted.action.execution_state == "SUCCEEDED"


@pytest.mark.parametrize("iteration", REPETITIONS)
async def test_cancellation_before_result_records_stale_evidence(
    session_factory, monkeypatch, iteration
):
    run, lifecycle, action, worker = await _dispatched(
        session_factory, f"operation-race-b2-{iteration}"
    )
    cancel_ready, release_cancel = Event(), Event()
    _pause_cancellation(monkeypatch, ready=cancel_ready, release=release_cancel)

    def cancel():
        return asyncio.run(
            ControlService(session_factory).issue_command(
                _cancel(run.root_node_id, f"b2-cancel-{iteration}"), _human(f"b2-{iteration}")
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        cancellation = pool.submit(cancel)
        _wait(cancel_ready)
        result = pool.submit(lambda: asyncio.run(_accept(lifecycle, action, worker)))
        assert not result.done()
        release_cancel.set()
        cancellation.result(timeout=10)
        stale = result.result(timeout=10)

    assert stale.accepted is False
    assert stale.action.execution_state == "STALE"
    assert stale.action.result_json is None
    assert stale.action.stale_result_digest is not None


@pytest.mark.parametrize("iteration", REPETITIONS)
async def test_w1_result_before_w2_replacement_remains_historical(
    session_factory, monkeypatch, iteration
):
    run, lifecycle, action, worker = await _dispatched(
        session_factory, f"operation-race-c1-{iteration}"
    )
    result_ready, release_result = Event(), Event()
    _pause_result(monkeypatch, lifecycle, ready=result_ready, release=release_result)
    switch_ready, release_switch = Event(), Event()

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = pool.submit(lambda: asyncio.run(_accept(lifecycle, action, worker)))
        _wait(result_ready)
        replacement = pool.submit(
            _switch_to_w2,
            session_factory,
            node_id=run.root_node_id,
            ready=switch_ready,
            release=release_switch,
        )
        assert not switch_ready.is_set()
        release_result.set()
        accepted = result.result(timeout=10)
        _wait(switch_ready)
        release_switch.set()
        w2_id = replacement.result(timeout=10)

    assert accepted.accepted is True
    assert accepted.action.execution_state == "SUCCEEDED"
    assert w2_id != worker.id


@pytest.mark.parametrize("iteration", REPETITIONS)
async def test_w2_replacement_before_w1_result_is_stale(session_factory, iteration):
    run, lifecycle, action, worker = await _dispatched(
        session_factory, f"operation-race-c2-{iteration}"
    )
    switch_ready, release_switch = Event(), Event()

    with ThreadPoolExecutor(max_workers=2) as pool:
        replacement = pool.submit(
            _switch_to_w2,
            session_factory,
            node_id=run.root_node_id,
            ready=switch_ready,
            release=release_switch,
        )
        _wait(switch_ready)
        result = pool.submit(lambda: asyncio.run(_accept(lifecycle, action, worker)))
        assert not result.done()
        release_switch.set()
        w2_id = replacement.result(timeout=10)
        stale = result.result(timeout=10)

    assert w2_id != worker.id
    assert stale.accepted is False
    assert stale.action.execution_state == "STALE"
    assert stale.action.stale_reason_code == "WORKER_NOT_CURRENT"
