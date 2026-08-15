from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from sqlalchemy import select

from tests.helpers import create_v2_run
from tracefence.db.models import RuntimeStopIntent, RuntimeStopTarget, WorkerInstance
from tracefence.domain.enums import CommandType, IssuerType, ScopeStatus
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import CommandCreate, NodeActivate, Principal, SpawnCreate
from tracefence.services import control_service as control_module
from tracefence.services.control_service import ControlService
from tracefence.services.runtime_stop_service import RuntimeStopService
from tracefence.services.spawn_service import SpawnService


def _cancel(node_id: str, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_SUBTREE,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="deterministic runtime stop source ordering",
    )


async def _child(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    service = SpawnService(session_factory)
    spawned = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="runtime-stop-race-child", capabilities=[]),
    )
    return service, spawned


@pytest.mark.parametrize("iteration", range(25))
async def test_activation_writer_first_is_historically_targetable(
    session_factory, monkeypatch, iteration
):
    service, spawned = await _child(session_factory, f"runtime-stop-activation-first-{iteration}")
    controls = ControlService(session_factory)
    activated_ready = Event()
    release_activation = Event()
    cancel_attempted = Event()
    original = service._activate_v2_locked

    async def paused_activation(*args, **kwargs):
        result = await original(*args, **kwargs)
        activated_ready.set()
        assert release_activation.wait(timeout=5)
        return result

    monkeypatch.setattr(service, "_activate_v2_locked", paused_activation)

    def activate():
        return asyncio.run(
            service.activate(
                spawned.child_node_id,
                NodeActivate(activation_token=spawned.activation_token),
            )
        )

    def cancel():
        cancel_attempted.set()
        return asyncio.run(
            controls.issue_command(
                _cancel(spawned.child_node_id, f"runtime-stop-activation-first-cancel-{iteration}"),
                Principal(issuer_type=IssuerType.HUMAN),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        activation = pool.submit(activate)
        assert activated_ready.wait(timeout=5)
        cancellation = pool.submit(cancel)
        assert cancel_attempted.wait(timeout=5)
        assert not cancellation.done()
        release_activation.set()
        activated = activation.result(timeout=10)
        command = cancellation.result(timeout=10)

    assert command.status == ScopeStatus.CANCELLED
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(RuntimeStopIntent.source_command_id == command.command_id)
        ).scalar_one()
        worker_id = session.scalar(
            select(WorkerInstance.id).where(WorkerInstance.node_id == activated.node_id)
        )
        assert worker_id is not None
        assert session.scalar(
            select(WorkerInstance.activated_revision).where(WorkerInstance.id == worker_id)
        ) <= intent.source_revision
    await RuntimeStopService(session_factory).materialize_targets(intent_id=intent.id, batch_size=10)
    with session_factory() as session:
        assert worker_id in set(
            session.execute(
                select(RuntimeStopTarget.worker_instance_id).where(
                    RuntimeStopTarget.stop_intent_id == intent.id
                )
            ).scalars()
        )


@pytest.mark.parametrize("iteration", range(25))
async def test_stop_writer_first_excludes_later_activation(
    session_factory, monkeypatch, iteration
):
    service, spawned = await _child(session_factory, f"runtime-stop-stop-first-{iteration}")
    controls = ControlService(session_factory)
    cancellation_written = Event()
    release_cancellation = Event()
    activation_attempted = Event()
    original_event = control_module.record_runtime_event

    def paused_event(*args, **kwargs):
        result = original_event(*args, **kwargs)
        if kwargs.get("event_type") == "SCOPE_CANCELLED":
            cancellation_written.set()
            assert release_cancellation.wait(timeout=5)
        return result

    monkeypatch.setattr(control_module, "record_runtime_event", paused_event)

    def cancel():
        return asyncio.run(
            controls.issue_command(
                _cancel(spawned.child_node_id, f"runtime-stop-stop-first-cancel-{iteration}"),
                Principal(issuer_type=IssuerType.HUMAN),
            )
        )

    def activate():
        activation_attempted.set()
        return asyncio.run(
            service.activate(
                spawned.child_node_id,
                NodeActivate(activation_token=spawned.activation_token),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        cancellation = pool.submit(cancel)
        assert cancellation_written.wait(timeout=5)
        activation = pool.submit(activate)
        assert activation_attempted.wait(timeout=5)
        assert not activation.done()
        release_cancellation.set()
        command = cancellation.result(timeout=10)
        with pytest.raises(ConflictError):
            activation.result(timeout=10)

    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(RuntimeStopIntent.source_command_id == command.command_id)
        ).scalar_one()
        assert session.scalar(
            select(WorkerInstance.id).where(WorkerInstance.node_id == spawned.child_node_id)
        ) is None
    result = await RuntimeStopService(session_factory).materialize_targets(
        intent_id=intent.id, batch_size=10
    )
    assert result.inserted == 0
