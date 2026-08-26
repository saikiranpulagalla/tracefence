from __future__ import annotations

import pytest
from sqlalchemy import select

from tests.helpers import create_v2_run
from tracefence.db.models import (
    ActionAttempt,
    ActionAuthorityBinding,
    ControlScope,
    Node,
    Run,
    WorkerInstance,
)
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute
from tracefence.security import payload_digest
from tracefence.services.operation_lifecycle import OperationLifecycleService


def _request(key: str) -> ActionExecute:
    return ActionExecute(
        tool_name="restart_postgres",
        arguments={},
        idempotency_key=key,
    )


async def _worker(session_factory, node_id: str):
    with session_factory() as session:
        node = session.get(Node, node_id)
        assert node is not None and node.current_worker_instance_id is not None
        worker = session.get(WorkerInstance, node.current_worker_instance_id)
        assert worker is not None
        return worker


async def test_v2_reservation_captures_exact_worker_and_authority_vector(session_factory):
    run = await create_v2_run(session_factory, "operation-reservation")
    service = OperationLifecycleService(session_factory)

    reserved = await service.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request("reserve")
    )

    with session_factory() as session:
        action = session.get(ActionAttempt, reserved.id)
        assert action is not None
        worker = await _worker(session_factory, run.root_node_id)
        bindings = session.execute(
            select(ActionAuthorityBinding)
            .where(ActionAuthorityBinding.action_id == action.id)
            .order_by(ActionAuthorityBinding.scope_id)
        ).scalars().all()
        assert action.execution_state == "AUTHORIZED"
        assert action.lifecycle_version == 1
        assert action.worker_instance_id == worker.id
        assert action.worker_incarnation == worker.incarnation
        assert action.authorization_proof_revision is not None
        assert action.authority_vector_digest == payload_digest(
            {"scopes": tuple({"scope_id": row.scope_id, "bound_version": row.bound_version} for row in bindings)}
        )
        assert bindings


async def test_dispatched_result_accepts_after_unrelated_proof_revision_change(session_factory):
    run = await create_v2_run(session_factory, "operation-proof-neutral")
    service = OperationLifecycleService(session_factory)
    reserved = await service.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request("proof-neutral")
    )
    worker = await _worker(session_factory, run.root_node_id)
    await service.mark_dispatched(
        action_id=reserved.id,
        worker_instance_id=worker.id,
        worker_incarnation=worker.incarnation,
    )
    with session_factory.begin() as session:
        row = session.get(Run, run.run_id)
        assert row is not None
        row.proof_revision += 7

    accepted = await service.accept_result(
        action_id=reserved.id,
        worker_instance_id=worker.id,
        worker_incarnation=worker.incarnation,
        tool_name="restart_postgres",
        arguments_digest=payload_digest({}),
        result={"ok": True},
    )
    assert accepted.accepted is True
    assert accepted.action.execution_state == "SUCCEEDED"


async def test_scope_change_records_idempotent_stale_evidence(session_factory):
    run = await create_v2_run(session_factory, "operation-stale")
    service = OperationLifecycleService(session_factory)
    reserved = await service.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request("stale")
    )
    worker = await _worker(session_factory, run.root_node_id)
    await service.mark_dispatched(
        action_id=reserved.id,
        worker_instance_id=worker.id,
        worker_incarnation=worker.incarnation,
    )
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        scope = session.get(ControlScope, node.scope_snapshot_json[0]["scope_id"])
        assert scope is not None
        scope.status = "CANCELLED"
        scope.version += 1

    result = {"external_effect": "unknown"}
    first = await service.accept_result(
        action_id=reserved.id,
        worker_instance_id=worker.id,
        worker_incarnation=worker.incarnation,
        tool_name="restart_postgres",
        arguments_digest=payload_digest({}),
        result=result,
    )
    assert first.accepted is False
    assert first.action.execution_state == "STALE"
    with session_factory() as session:
        before = session.get(Run, run.run_id).proof_revision

    repeated = await service.accept_result(
        action_id=reserved.id,
        worker_instance_id=worker.id,
        worker_incarnation=worker.incarnation,
        tool_name="restart_postgres",
        arguments_digest=payload_digest({}),
        result=result,
    )
    assert repeated.accepted is False
    with session_factory() as session:
        after = session.get(Run, run.run_id).proof_revision
    assert after == before

    with pytest.raises(ConflictError, match="Conflicting stale"):
        await service.accept_result(
            action_id=reserved.id,
            worker_instance_id=worker.id,
            worker_incarnation=worker.incarnation,
            tool_name="restart_postgres",
            arguments_digest=payload_digest({}),
            result={"external_effect": "different"},
        )


async def test_v2_idempotency_fails_closed_for_replacement_worker(session_factory):
    run = await create_v2_run(session_factory, "operation-owner-fence")
    service = OperationLifecycleService(session_factory)
    await service.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request("owner")
    )
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        old = session.get(WorkerInstance, node.current_worker_instance_id)
        assert old is not None
        replacement = WorkerInstance(
            id="00000000-0000-0000-0000-000000000024",
            node_id=node.id,
            incarnation=old.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=old.activated_at,
            credential_hash=old.credential_hash,
        )
        session.add(replacement)
        session.flush()
        node.current_worker_instance_id = replacement.id

    with pytest.raises(ConflictError) as error:
        await service.reserve(
            node_id=run.root_node_id, credential=run.root_token, request=_request("owner")
        )
    assert error.value.code == "IDEMPOTENCY_OWNER_MISMATCH"
