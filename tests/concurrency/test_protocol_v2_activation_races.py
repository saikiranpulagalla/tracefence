from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event

import pytest
from sqlalchemy import func, select

from tests.helpers import create_v2_run
from tracefence.db.models import CredentialRecoveryEnvelope, Node, WorkerInstance
from tracefence.domain.enums import CommandType, IssuerType, ScopeStatus
from tracefence.domain.errors import AuthenticationError, ConflictError
from tracefence.domain.schemas import CommandCreate, NodeActivate, Principal, SpawnCreate
from tracefence.security import token_matches
from tracefence.services import control_service as control_module
from tracefence.services import spawn_service as spawn_module
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.spawn_service import SpawnService


async def _spawn_v2_child(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    service = SpawnService(session_factory)
    spawned = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="v2-race-child", capabilities=[]),
    )
    return run, service, spawned


def _cancel_request(node_id: str, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_SUBTREE,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="deterministic protocol-v2 activation cancellation race",
    )


async def test_v2_duplicate_activation_race_creates_one_worker_instance(session_factory):
    _run, service, spawned = await _spawn_v2_child(session_factory, "v2-duplicate-activation")
    barrier = Barrier(2)

    def activate_once(process_id: int):
        barrier.wait()
        return asyncio.run(
            service.activate(
                spawned.child_node_id,
                NodeActivate(
                    activation_token=spawned.activation_token,
                    process_id=process_id,
                ),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            pool.submit(activate_once, 5101),
            pool.submit(activate_once, 5102),
        ]
        values = [future.result(timeout=10) for future in results]

    assert values[0] == values[1]
    with session_factory() as session:
        workers = session.execute(
            select(WorkerInstance).where(WorkerInstance.node_id == spawned.child_node_id)
        ).scalars().all()
        assert len(workers) == 1
        assert workers[0].incarnation == 1
        assert workers[0].activation_intent_id is not None


async def test_v2_activation_writer_first_commits_before_cancellation(
    session_factory, monkeypatch
):
    run, service, spawned = await _spawn_v2_child(session_factory, "v2-activation-first")
    controls = ControlService(session_factory)
    activation_ready = Event()
    release_activation = Event()
    cancellation_attempted = Event()
    original = service._activate_v2_locked

    async def paused_activation(*args, **kwargs):
        result = await original(*args, **kwargs)
        activation_ready.set()
        assert release_activation.wait(timeout=5)
        return result

    monkeypatch.setattr(service, "_activate_v2_locked", paused_activation)

    def activate_child():
        return asyncio.run(
            service.activate(
                spawned.child_node_id,
                NodeActivate(activation_token=spawned.activation_token),
            )
        )

    def cancel_child():
        cancellation_attempted.set()
        return asyncio.run(
            controls.issue_command(
                _cancel_request(spawned.child_node_id, "v2-activation-first-cancel"),
                Principal(issuer_type=IssuerType.HUMAN),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        activation = pool.submit(activate_child)
        assert activation_ready.wait(timeout=5)
        cancellation = pool.submit(cancel_child)
        assert cancellation_attempted.wait(timeout=5)
        assert not cancellation.done()
        release_activation.set()
        activated = activation.result(timeout=10)
        command = cancellation.result(timeout=10)

    assert activated.node_id == spawned.child_node_id
    assert command.status == ScopeStatus.CANCELLED
    with session_factory() as session:
        node = session.get(Node, spawned.child_node_id)
        assert node is not None
        assert node.current_worker_instance_id is not None
        assert session.scalar(
            select(func.count(WorkerInstance.id)).where(
                WorkerInstance.node_id == spawned.child_node_id
            )
        ) == 1


async def test_v2_cancellation_writer_first_prevents_activation(
    session_factory, monkeypatch
):
    _run, service, spawned = await _spawn_v2_child(session_factory, "v2-cancellation-first")
    controls = ControlService(session_factory)
    cancellation_ready = Event()
    release_cancellation = Event()
    activation_attempted = Event()
    original = control_module.record_runtime_event

    def paused_event(*args, **kwargs):
        result = original(*args, **kwargs)
        if kwargs.get("event_type") == "SCOPE_CANCELLED":
            cancellation_ready.set()
            assert release_cancellation.wait(timeout=5)
        return result

    monkeypatch.setattr(control_module, "record_runtime_event", paused_event)

    def cancel_child():
        return asyncio.run(
            controls.issue_command(
                _cancel_request(spawned.child_node_id, "v2-cancellation-first-cancel"),
                Principal(issuer_type=IssuerType.HUMAN),
            )
        )

    def activate_child():
        activation_attempted.set()
        return asyncio.run(
            service.activate(
                spawned.child_node_id,
                NodeActivate(activation_token=spawned.activation_token),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        cancellation = pool.submit(cancel_child)
        assert cancellation_ready.wait(timeout=5)
        activation = pool.submit(activate_child)
        assert activation_attempted.wait(timeout=5)
        assert not activation.done()
        release_cancellation.set()
        cancellation.result(timeout=10)
        with pytest.raises(ConflictError):
            activation.result(timeout=10)

    with session_factory() as session:
        node = session.get(Node, spawned.child_node_id)
        assert node is not None and node.current_worker_instance_id is None
        assert session.scalar(
            select(func.count(WorkerInstance.id)).where(
                WorkerInstance.node_id == spawned.child_node_id
            )
        ) == 0


async def _activate_then_expire(session_factory, name: str):
    run, service, spawned = await _spawn_v2_child(session_factory, name)
    activated = await service.activate(
        spawned.child_node_id,
        NodeActivate(activation_token=spawned.activation_token),
    )
    with session_factory.begin() as session:
        envelope = session.execute(
            select(CredentialRecoveryEnvelope).where(
                CredentialRecoveryEnvelope.binding_version == 2,
                CredentialRecoveryEnvelope.subject_node_id == activated.node_id,
            )
        ).scalar_one()
        envelope.expires_at = utcnow() - timedelta(seconds=1)
    return run, service, spawned, activated


async def test_v2_recovery_writer_first_rotates_before_old_credential_authentication(
    session_factory, monkeypatch
):
    _run, service, spawned, first = await _activate_then_expire(
        session_factory, "v2-recovery-first"
    )
    recovery_ready = Event()
    release_recovery = Event()
    heartbeat_attempted = Event()
    original = service._recover_v2_activation_locked

    async def paused_recovery(*args, **kwargs):
        recovery_ready.set()
        assert release_recovery.wait(timeout=5)
        return await original(*args, **kwargs)

    monkeypatch.setattr(service, "_recover_v2_activation_locked", paused_recovery)

    def recover():
        return asyncio.run(
            service.activate(
                spawned.child_node_id,
                NodeActivate(activation_token=spawned.activation_token, process_id=5201),
            )
        )

    def heartbeat_old():
        heartbeat_attempted.set()
        return asyncio.run(service.heartbeat(first.node_id, first.node_token))

    with ThreadPoolExecutor(max_workers=2) as pool:
        recovery = pool.submit(recover)
        assert recovery_ready.wait(timeout=5)
        heartbeat = pool.submit(heartbeat_old)
        assert heartbeat_attempted.wait(timeout=5)
        assert not heartbeat.done()
        release_recovery.set()
        rotated = recovery.result(timeout=10)
        with pytest.raises(AuthenticationError):
            heartbeat.result(timeout=10)

    assert rotated.node_token != first.node_token
    assert (await service.heartbeat(rotated.node_id, rotated.node_token)).id == first.node_id


async def test_v2_first_authentication_writer_prevents_expired_recovery_rotation(
    session_factory, monkeypatch
):
    _run, service, spawned, first = await _activate_then_expire(
        session_factory, "v2-auth-first"
    )
    authentication_ready = Event()
    release_authentication = Event()
    recovery_attempted = Event()
    original = spawn_module.authenticate_execution_principal

    async def paused_authentication(*args, **kwargs):
        result = await original(*args, **kwargs)
        if kwargs.get("credential") == first.node_token:
            authentication_ready.set()
            assert release_authentication.wait(timeout=5)
        return result

    monkeypatch.setattr(spawn_module, "authenticate_execution_principal", paused_authentication)

    def heartbeat_current():
        return asyncio.run(service.heartbeat(first.node_id, first.node_token))

    def recover():
        recovery_attempted.set()
        return asyncio.run(
            service.activate(
                spawned.child_node_id,
                NodeActivate(activation_token=spawned.activation_token),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        heartbeat = pool.submit(heartbeat_current)
        assert authentication_ready.wait(timeout=5)
        recovery = pool.submit(recover)
        assert recovery_attempted.wait(timeout=5)
        assert not recovery.done()
        release_authentication.set()
        heartbeat.result(timeout=10)
        with pytest.raises(ConflictError) as captured:
            recovery.result(timeout=10)
    assert captured.value.code == "CREDENTIAL_RECOVERY_CONFIRMED"

    with session_factory() as session:
        worker = session.execute(
            select(WorkerInstance).where(WorkerInstance.node_id == first.node_id)
        ).scalar_one()
        assert worker.credential_confirmed_at is not None
        assert token_matches(first.node_token, worker.credential_hash)
