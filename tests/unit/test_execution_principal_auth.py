from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import text

from tests.helpers import create_seeded_run
from tracefence.db.models import Node, Run, WorkerInstance
from tracefence.domain.errors import AuthenticationError
from tracefence.domain.schemas import ActionExecute
from tracefence.security import hash_token
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import (
    authenticate_execution_principal,
    utcnow,
)
from tracefence.services.spawn_service import SpawnService


async def _synthetic_v2(session_factory):
    run = await create_seeded_run(session_factory, "synthetic-v2-principal")
    first_credential, second_credential, first_id = await _install_synthetic_v2(
        session_factory, run
    )
    return run, first_credential, second_credential, first_id


async def _install_synthetic_v2(session_factory, run):
    first_credential = "synthetic-worker-one-credential"
    second_credential = "synthetic-worker-two-credential"
    with session_factory.begin() as session:
        session.execute(text("DROP TRIGGER trg_runs_execution_protocol_version_immutable"))
        row = session.get(Run, run.run_id)
        assert row is not None
        row.execution_protocol_version = 2
        node = session.get(Node, run.root_node_id)
        assert node is not None
        now = utcnow()
        first = WorkerInstance(
            id=str(uuid4()),
            node_id=node.id,
            incarnation=1,
            observed_state="ACTIVE",
            activated_at=now,
            credential_hash=hash_token(first_credential),
        )
        session.add(first)
        session.flush()
        node.current_worker_instance_id = first.id
    return first_credential, second_credential, first.id


async def _switch_current_worker(session_factory, run_id: str, node_id: str, credential: str):
    with session_factory.begin() as session:
        node = session.get(Node, node_id)
        assert node is not None
        second = WorkerInstance(
            id=str(uuid4()),
            node_id=node.id,
            incarnation=2,
            observed_state="ACTIVE",
            activated_at=utcnow(),
            credential_hash=hash_token(credential),
        )
        session.add(second)
        session.flush()
        node.current_worker_instance_id = second.id
        return second.id


async def test_v2_auth_rejects_node_token_confirms_once_and_fences_old_instance(session_factory):
    service = SpawnService(session_factory)
    run, first, second, first_id = await _synthetic_v2(session_factory)

    with pytest.raises(AuthenticationError):
        await service.heartbeat(run.root_node_id, run.root_token)

    with session_factory() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        before_revision = session.get(Run, run.run_id).proof_revision
        await authenticate_execution_principal(
            session, node_id=run.root_node_id, credential=first
        )
        session.commit()
    with session_factory() as session:
        instance = session.get(WorkerInstance, first_id)
        assert instance is not None and instance.credential_confirmed_at is not None
        confirmed_at = instance.credential_confirmed_at
        assert session.get(Run, run.run_id).proof_revision == before_revision

    await service.heartbeat(run.root_node_id, first)
    with session_factory() as session:
        assert session.get(WorkerInstance, first_id).credential_confirmed_at == confirmed_at
        before_switch_revision = session.get(Run, run.run_id).proof_revision

    second_id = await _switch_current_worker(session_factory, run.run_id, run.root_node_id, second)
    with session_factory() as session:
        assert session.get(Run, run.run_id).proof_revision > before_switch_revision

    with pytest.raises(AuthenticationError):
        await service.heartbeat(run.root_node_id, first)
    with session_factory() as session:
        assert session.get(Node, run.root_node_id).current_worker_instance_id == second_id
    assert (await service.heartbeat(run.root_node_id, second)).id == run.root_node_id


async def test_v2_action_authenticates_before_node_scoped_replay(session_factory):
    run, first, second, _ = await _synthetic_v2(session_factory)
    gateway = ActionGateway(session_factory)
    request = ActionExecute(
        tool_name="read_metrics",
        arguments={},
        idempotency_key="v2-node-scoped-replay",
    )
    first_result = await gateway.execute(run.root_node_id, first, request)
    assert first_result.duplicate is False

    await _switch_current_worker(session_factory, run.run_id, run.root_node_id, second)
    with pytest.raises(AuthenticationError):
        await gateway.execute(run.root_node_id, first, request)
    replay = await gateway.execute(run.root_node_id, second, request)
    assert replay.duplicate is True

    current_request = ActionExecute(
        tool_name="read_metrics",
        arguments={},
        idempotency_key="v2-current-worker-action",
    )
    current = await gateway.execute(run.root_node_id, second, current_request)
    assert current.duplicate is False
    assert current.committed is True
    current_replay = await gateway.execute(
        run.root_node_id, second, current_request
    )
    assert current_replay.duplicate is True


async def test_v2_current_worker_confirmation_is_once_set_and_revision_neutral(
    session_factory,
):
    run, first, second, first_id = await _synthetic_v2(session_factory)
    second_id = await _switch_current_worker(
        session_factory, run.run_id, run.root_node_id, second
    )
    with session_factory() as session:
        before_revision = session.get(Run, run.run_id).proof_revision
        first_instance = session.get(WorkerInstance, first_id)
        second_instance = session.get(WorkerInstance, second_id)
        assert first_instance is not None and first_instance.credential_confirmed_at is None
        assert second_instance is not None and second_instance.credential_confirmed_at is None

    with session_factory() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        await authenticate_execution_principal(
            session, node_id=run.root_node_id, credential=second
        )
        session.commit()
    with session_factory() as session:
        second_instance = session.get(WorkerInstance, second_id)
        assert second_instance is not None
        assert second_instance.credential_confirmed_at is not None
        confirmed_at = second_instance.credential_confirmed_at
        assert session.get(Run, run.run_id).proof_revision == before_revision

    with session_factory() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        await authenticate_execution_principal(
            session, node_id=run.root_node_id, credential=second
        )
        session.commit()
    with session_factory() as session:
        first_instance = session.get(WorkerInstance, first_id)
        second_instance = session.get(WorkerInstance, second_id)
        assert first_instance is not None and first_instance.credential_confirmed_at is None
        assert second_instance is not None
        assert second_instance.credential_confirmed_at == confirmed_at
        assert session.get(Run, run.run_id).proof_revision == before_revision

    with session_factory() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        with pytest.raises(AuthenticationError):
            await authenticate_execution_principal(
                session, node_id=run.root_node_id, credential=first
            )
        session.rollback()
    with session_factory() as session:
        second_instance = session.get(WorkerInstance, second_id)
        assert second_instance is not None
        assert second_instance.credential_confirmed_at == confirmed_at
