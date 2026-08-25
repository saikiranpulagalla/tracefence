from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import text

from tests.helpers import create_v2_run
from tracefence.db.models import Node, WorkerInstance
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.schemas import (
    ActionExecute,
    CommandCreate,
    NodeActivate,
    Principal,
    SpawnCreate,
)
from tracefence.security import hash_token
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.operation_lifecycle import (
    OperationAuthorityStatus,
    OperationCancellationContext,
    OperationLifecycleService,
)
from tracefence.services.spawn_service import SpawnService

REPETITIONS = range(25)


def _wait(event: Event) -> None:
    assert event.wait(timeout=5), "deterministic synchronization point was not reached"


def _principal(name: str) -> Principal:
    return Principal(issuer_type=IssuerType.HUMAN, principal_id=f"b1-race-{name}")


def _cancel(node_id: str, key: str, command_type: CommandType) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=command_type,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="deterministic cancellation context ordering",
    )


async def _context(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    service = OperationLifecycleService(session_factory)
    action = await service.reserve(
        node_id=run.root_node_id,
        credential=run.root_token,
        request=ActionExecute(idempotency_key=f"{name}-action", tool_name="restart_postgres", arguments={}),
    )
    return run, action, OperationCancellationContext.from_action(session_factory, action)


async def _child_context(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    spawns = SpawnService(session_factory)
    child = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="b1-race", capabilities=["tool:restart_postgres"]),
    )
    active = await spawns.activate(
        child.child_node_id, NodeActivate(activation_token=child.activation_token)
    )
    action = await OperationLifecycleService(session_factory).reserve(
        node_id=child.child_node_id,
        credential=active.node_token,
        request=ActionExecute(idempotency_key=f"{name}-action", tool_name="restart_postgres", arguments={}),
    )
    return child.child_node_id, action, OperationCancellationContext.from_action(session_factory, action)


def _switch_to_w2(session_factory, node_id: str) -> None:
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
                credential_hash=hash_token("b1-race-w2"),
            )
            session.add(second)
            session.flush()
            node.current_worker_instance_id = second.id
            session.commit()
        except Exception:
            session.rollback()
            raise


@pytest.mark.parametrize("iteration", REPETITIONS)
@pytest.mark.parametrize("ordering", ("check-before-cancel", "cancel-before-check"))
async def test_context_cancel_ordering(session_factory, iteration, ordering):
    run, _action, context = await _context(session_factory, f"cancel-{iteration}-{ordering}")
    checked = Event()

    def check():
        decision = asyncio.run(context.check())
        checked.set()
        return decision

    def cancel():
        return asyncio.run(
            ControlService(session_factory).issue_command(
                _cancel(run.root_node_id, f"cancel-{iteration}-{ordering}", CommandType.CANCEL_RUN),
                _principal(f"cancel-{iteration}-{ordering}"),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        if ordering == "check-before-cancel":
            checked_result = pool.submit(check)
            _wait(checked)
            pool.submit(cancel).result(timeout=10)
            decision = checked_result.result(timeout=10)
            assert decision.status == OperationAuthorityStatus.ALLOWED
            assert (await context.check()).status == OperationAuthorityStatus.REVOKED
        else:
            pool.submit(cancel).result(timeout=10)
            decision = pool.submit(check).result(timeout=10)
            assert decision.status == OperationAuthorityStatus.REVOKED


@pytest.mark.parametrize("iteration", REPETITIONS)
@pytest.mark.parametrize("ordering", ("w1-check-before-w2", "w2-before-w1-check"))
async def test_context_worker_ordering(session_factory, iteration, ordering):
    run, _action, context = await _context(session_factory, f"worker-{iteration}-{ordering}")
    checked = Event()

    def check():
        decision = asyncio.run(context.check())
        checked.set()
        return decision

    with ThreadPoolExecutor(max_workers=2) as pool:
        if ordering == "w1-check-before-w2":
            result = pool.submit(check)
            _wait(checked)
            pool.submit(_switch_to_w2, session_factory, run.root_node_id).result(timeout=10)
            assert result.result(timeout=10).status == OperationAuthorityStatus.ALLOWED
            assert (await context.check()).status == OperationAuthorityStatus.REVOKED
        else:
            pool.submit(_switch_to_w2, session_factory, run.root_node_id).result(timeout=10)
            assert pool.submit(check).result(timeout=10).status == OperationAuthorityStatus.REVOKED


@pytest.mark.parametrize("iteration", REPETITIONS)
@pytest.mark.parametrize("ordering", ("check-before-scope-change", "scope-change-before-check"))
async def test_context_scope_ordering(session_factory, iteration, ordering):
    node_id, _action, context = await _child_context(session_factory, f"scope-{iteration}-{ordering}")
    checked = Event()

    def check():
        decision = asyncio.run(context.check())
        checked.set()
        return decision

    def cancel():
        return asyncio.run(
            ControlService(session_factory).issue_command(
                _cancel(node_id, f"scope-{iteration}-{ordering}", CommandType.CANCEL_SUBTREE),
                _principal(f"scope-{iteration}-{ordering}"),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        if ordering == "check-before-scope-change":
            result = pool.submit(check)
            _wait(checked)
            pool.submit(cancel).result(timeout=10)
            assert result.result(timeout=10).status == OperationAuthorityStatus.ALLOWED
            assert (await context.check()).status == OperationAuthorityStatus.REVOKED
        else:
            pool.submit(cancel).result(timeout=10)
            assert pool.submit(check).result(timeout=10).status == OperationAuthorityStatus.REVOKED

