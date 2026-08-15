from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text

import tracefence.services.action_gateway as action_gateway_module
import tracefence.services.spawn_service as spawn_service_module
from tests.helpers import create_seeded_run
from tests.unit.test_execution_principal_auth import _install_synthetic_v2
from tracefence.db.models import ActionAttempt, Node, WorkerInstance
from tracefence.domain.enums import NodeStatus
from tracefence.domain.errors import AuthenticationError
from tracefence.domain.schemas import ActionExecute
from tracefence.security import hash_token
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
from tracefence.services.spawn_service import SpawnService


async def _wait(event: Event) -> None:
    assert await asyncio.to_thread(event.wait, 5)


def _prepare_second_worker(session_factory, node_id: str, credential: str) -> str:
    with session_factory.begin() as session:
        worker = WorkerInstance(
            id=str(uuid4()),
            node_id=node_id,
            incarnation=2,
            observed_state="ACTIVE",
            activated_at=utcnow(),
            credential_hash=hash_token(credential),
        )
        session.add(worker)
        session.flush()
        return worker.id


def _switch_pointer(
    session_factory,
    *,
    node_id: str,
    worker_id: str,
    attempted: Event,
    acquired: Event,
    allow_commit: Event,
    committed: Event,
) -> None:
    with session_factory() as session:
        attempted.set()
        session.execute(text("BEGIN IMMEDIATE"))
        node = session.get(Node, node_id)
        assert node is not None
        node.current_worker_instance_id = worker_id
        session.flush()
        acquired.set()
        assert allow_commit.wait(5)
        session.commit()
        committed.set()


async def test_action_gateway_pointer_switch_serializes_action_before_switch(
    session_factory, monkeypatch
):
    run = await create_seeded_run(session_factory, "v2-action-race-action-first")
    first, second, _ = await _install_synthetic_v2(session_factory, run)
    second_id = _prepare_second_worker(session_factory, run.root_node_id, second)
    gateway = ActionGateway(session_factory)
    authenticated = asyncio.Event()
    release_action = asyncio.Event()
    original = action_gateway_module.authenticate_execution_principal

    async def paused_auth(*args, **kwargs):
        principal = await original(*args, **kwargs)
        authenticated.set()
        await release_action.wait()
        return principal

    monkeypatch.setattr(action_gateway_module, "authenticate_execution_principal", paused_auth)
    action_task = asyncio.create_task(
        gateway.execute(
            run.root_node_id,
            first,
            ActionExecute(
                idempotency_key="v2-action-first",
                tool_name="read_metrics",
                arguments={},
            ),
        )
    )
    await authenticated.wait()

    attempted, acquired, allow_commit, committed = Event(), Event(), Event(), Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        switch = pool.submit(
            _switch_pointer,
            session_factory,
            node_id=run.root_node_id,
            worker_id=second_id,
            attempted=attempted,
            acquired=acquired,
            allow_commit=allow_commit,
            committed=committed,
        )
        await _wait(attempted)
        assert not acquired.is_set()
        assert not committed.is_set()
        release_action.set()
        action = await action_task
        assert action.committed is True
        await _wait(acquired)
        allow_commit.set()
        switch.result(timeout=5)

    assert committed.is_set()
    with session_factory() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None and node.current_worker_instance_id == second_id
        assert (
            session.scalar(
                select(func.count(ActionAttempt.id)).where(
                    ActionAttempt.run_id == run.run_id
                )
            )
            == 1
        )


async def test_action_gateway_pointer_switch_serializes_switch_before_stale_action(
    session_factory,
):
    run = await create_seeded_run(session_factory, "v2-action-race-switch-first")
    first, second, _ = await _install_synthetic_v2(session_factory, run)
    second_id = _prepare_second_worker(session_factory, run.root_node_id, second)
    gateway = ActionGateway(session_factory)
    attempted, acquired, allow_commit, committed = Event(), Event(), Event(), Event()

    def action_request():
        return asyncio.run(
            gateway.execute(
                run.root_node_id,
                first,
                ActionExecute(
                    idempotency_key="v2-action-switch-first",
                    tool_name="read_metrics",
                    arguments={},
                ),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        switch = pool.submit(
            _switch_pointer,
            session_factory,
            node_id=run.root_node_id,
            worker_id=second_id,
            attempted=attempted,
            acquired=acquired,
            allow_commit=allow_commit,
            committed=committed,
        )
        await _wait(acquired)
        action = pool.submit(action_request)
        allow_commit.set()
        switch.result(timeout=5)
        with pytest.raises(AuthenticationError):
            action.result(timeout=5)

    assert committed.is_set()
    with session_factory() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None and node.current_worker_instance_id == second_id
        assert (
            session.scalar(
                select(func.count(ActionAttempt.id)).where(
                    ActionAttempt.run_id == run.run_id
                )
            )
            == 0
        )


async def test_checkpoint_pointer_switch_serializes_checkpoint_before_switch(
    session_factory, monkeypatch
):
    run = await create_seeded_run(
        session_factory, "v2-checkpoint-race-checkpoint-first"
    )
    first, second, _ = await _install_synthetic_v2(session_factory, run)
    second_id = _prepare_second_worker(session_factory, run.root_node_id, second)
    spawns = SpawnService(session_factory)
    authenticated = asyncio.Event()
    release_checkpoint = asyncio.Event()
    original = spawn_service_module.authenticate_execution_principal

    async def paused_auth(*args, **kwargs):
        principal = await original(*args, **kwargs)
        authenticated.set()
        await release_checkpoint.wait()
        return principal

    monkeypatch.setattr(spawn_service_module, "authenticate_execution_principal", paused_auth)
    checkpoint_task = asyncio.create_task(
        spawns.checkpoint(run.root_node_id, first, "checkpoint-before-switch")
    )
    await authenticated.wait()

    attempted, acquired, allow_commit, committed = Event(), Event(), Event(), Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        switch = pool.submit(
            _switch_pointer,
            session_factory,
            node_id=run.root_node_id,
            worker_id=second_id,
            attempted=attempted,
            acquired=acquired,
            allow_commit=allow_commit,
            committed=committed,
        )
        await _wait(attempted)
        assert not acquired.is_set()
        assert not committed.is_set()
        release_checkpoint.set()
        checkpoint = await checkpoint_task
        assert checkpoint.allowed is True
        await _wait(acquired)
        allow_commit.set()
        switch.result(timeout=5)

    with session_factory() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        assert node.status == NodeStatus.WAITING
        assert node.current_worker_instance_id == second_id


async def test_checkpoint_pointer_switch_serializes_switch_before_stale_checkpoint(
    session_factory,
):
    run = await create_seeded_run(
        session_factory, "v2-checkpoint-race-switch-first"
    )
    first, second, _ = await _install_synthetic_v2(session_factory, run)
    second_id = _prepare_second_worker(session_factory, run.root_node_id, second)
    spawns = SpawnService(session_factory)
    attempted, acquired, allow_commit, committed = Event(), Event(), Event(), Event()

    def checkpoint_request():
        return asyncio.run(
            spawns.checkpoint(run.root_node_id, first, "checkpoint-after-switch")
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        switch = pool.submit(
            _switch_pointer,
            session_factory,
            node_id=run.root_node_id,
            worker_id=second_id,
            attempted=attempted,
            acquired=acquired,
            allow_commit=allow_commit,
            committed=committed,
        )
        await _wait(acquired)
        checkpoint = pool.submit(checkpoint_request)
        allow_commit.set()
        switch.result(timeout=5)
        with pytest.raises(AuthenticationError):
            checkpoint.result(timeout=5)

    assert committed.is_set()
    with session_factory() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        assert node.status == NodeStatus.ACTIVE
        assert node.current_worker_instance_id == second_id
