from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import delete, event, func, select
from sqlalchemy.exc import OperationalError

import tracefence.services.operation_lifecycle as lifecycle_module
from tests.helpers import create_v2_run
from tracefence.db.models import (
    ActionAttempt,
    ActionAuthorityBinding,
    Node,
    Run,
    RuntimeEvent,
    WorkerInstance,
)
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import (
    ActionExecute,
    CommandCreate,
    NodeActivate,
    Principal,
    SpawnCreate,
)
from tracefence.security import hash_token, payload_digest
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.operation_lifecycle import (
    OperationAuthorityDecision,
    OperationAuthorityStatus,
    OperationCancellationContext,
    OperationLifecycleService,
)
from tracefence.services.spawn_service import SpawnService


def _request(key: str) -> ActionExecute:
    return ActionExecute(idempotency_key=key, tool_name="restart_postgres", arguments={})


def _cancel(node_id: str, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_SUBTREE,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="operation cancellation context",
    )


async def _reserved(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    service = OperationLifecycleService(session_factory)
    action = await service.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request(name)
    )
    return run, service, action, OperationCancellationContext.from_action(session_factory, action)


def _state(session_factory, action_id: str):
    with session_factory() as session:
        action = session.get(ActionAttempt, action_id)
        assert action is not None
        run = session.get(Run, action.run_id)
        assert run is not None
        events = session.scalar(select(func.count()).select_from(RuntimeEvent).where(RuntimeEvent.run_id == run.id))
        return action.execution_state, run.proof_revision, events


async def test_allowed_check_is_read_only_and_proof_neutral(session_factory):
    _run, _service, action, context = await _reserved(session_factory, "allowed")
    before = _state(session_factory, action.id)

    assert await context.check() == OperationAuthorityDecision(OperationAuthorityStatus.ALLOWED)
    assert _state(session_factory, action.id) == before


async def test_scope_revocation_is_read_only(session_factory):
    run = await create_v2_run(session_factory, "scope")
    spawns = SpawnService(session_factory)
    child = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="b1-scope", capabilities=["tool:restart_postgres"]),
    )
    activated = await spawns.activate(
        child.child_node_id, NodeActivate(activation_token=child.activation_token)
    )
    service = OperationLifecycleService(session_factory)
    action = await service.reserve(
        node_id=child.child_node_id,
        credential=activated.node_token,
        request=_request("scope-action"),
    )
    context = OperationCancellationContext.from_action(session_factory, action)
    await ControlService(session_factory).issue_command(
        _cancel(child.child_node_id, "cancel"),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="b1-scope"),
    )
    after_control = _state(session_factory, action.id)

    assert await context.check() == OperationAuthorityDecision(
        OperationAuthorityStatus.REVOKED, "SCOPE_CANCELLED"
    )
    assert _state(session_factory, action.id) == after_control


async def test_worker_replacement_is_revoked_without_pid_authority(session_factory):
    run, _service, action, context = await _reserved(session_factory, "worker")
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None and node.current_worker_instance_id is not None
        first = session.get(WorkerInstance, node.current_worker_instance_id)
        assert first is not None
        first.reported_process_id = 7788
        second = WorkerInstance(
            id="00000000-0000-0000-0000-0000000000b1",
            node_id=node.id,
            incarnation=first.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=first.activated_at,
            credential_hash=hash_token("b1-worker"),
            reported_process_id=7788,
        )
        session.add(second)
        session.flush()
        node.current_worker_instance_id = second.id

    assert await context.check() == OperationAuthorityDecision(
        OperationAuthorityStatus.REVOKED, "WORKER_NOT_CURRENT"
    )
    assert _state(session_factory, action.id)[0] == "AUTHORIZED"


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [("lease", "LEASE_EXPIRED"), ("run", "RUN_NOT_ACTIVE"), ("node", "NODE_NOT_ACTIVE")],
)
async def test_runtime_revocations(session_factory, mutation, reason):
    run, _service, _action, context = await _reserved(session_factory, f"runtime-{mutation}")
    with session_factory.begin() as session:
        node, row = session.get(Node, run.root_node_id), session.get(Run, run.run_id)
        assert node is not None and row is not None
        if mutation == "lease":
            node.lease_expires_at = utcnow() - timedelta(seconds=1)
        elif mutation == "run":
            row.status, row.finished_at = "CANCELLED", utcnow()
        else:
            node.status = "CANCELLED"

    assert await context.check() == OperationAuthorityDecision(OperationAuthorityStatus.REVOKED, reason)


async def test_malformed_binding_is_uncertain_and_read_only(session_factory):
    _run, _service, action, context = await _reserved(session_factory, "malformed")
    with session_factory.begin() as session:
        session.execute(delete(ActionAuthorityBinding).where(ActionAuthorityBinding.action_id == action.id))
    before = _state(session_factory, action.id)

    assert await context.check() == OperationAuthorityDecision(
        OperationAuthorityStatus.UNCERTAIN, "OPERATION_BINDING_INVALID"
    )
    assert _state(session_factory, action.id) == before


async def test_database_uncertainty_is_fail_closed(session_factory, monkeypatch):
    _run, _service, action, context = await _reserved(session_factory, "db-error")
    before = _state(session_factory, action.id)

    async def unavailable(*_args, **_kwargs):
        raise OperationalError("SELECT", {}, Exception("busy"))

    monkeypatch.setattr(lifecycle_module, "_evaluate_live_bound_action_authority", unavailable)
    assert await context.check() == OperationAuthorityDecision(
        OperationAuthorityStatus.UNCERTAIN, "OPERATION_AUTHORITY_UNCERTAIN"
    )
    assert _state(session_factory, action.id) == before


async def test_programming_error_propagates(session_factory, monkeypatch):
    _run, _service, _action, context = await _reserved(session_factory, "bugg")

    async def broken(*_args, **_kwargs):
        raise RuntimeError("programming error")

    monkeypatch.setattr(lifecycle_module, "evaluate_live_bound_action_authority", broken)
    with pytest.raises(RuntimeError, match="programming error"):
        await context.check()


async def test_cross_worker_context_is_revoked_and_repeated_checks_are_neutral(session_factory):
    run, _service, action, context = await _reserved(session_factory, "cross")
    with session_factory.begin() as session:
        row = session.get(Run, run.run_id)
        assert row is not None
        row.proof_revision += 3
    before = _state(session_factory, action.id)
    assert (await context.check()).status == OperationAuthorityStatus.ALLOWED
    assert (await context.check()).status == OperationAuthorityStatus.ALLOWED
    wrong = OperationCancellationContext(
        session_factory=session_factory,
        action_id=action.id,
        run_id=action.run_id,
        node_id=action.node_id,
        worker_instance_id="00000000-0000-0000-0000-0000000000c1",
        worker_incarnation=99,
    )
    assert await wrong.check() == OperationAuthorityDecision(
        OperationAuthorityStatus.REVOKED, "ACTION_WORKER_OWNER_MISMATCH"
    )
    assert _state(session_factory, action.id) == before


async def test_check_issues_no_writer_sql(session_factory):
    _run, _service, _action, context = await _reserved(session_factory, "readonly")
    engine = session_factory.kw["bind"]
    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.upper())

    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert (await context.check()).status == OperationAuthorityStatus.ALLOWED
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert not any("BEGIN IMMEDIATE" in statement for statement in statements)
    assert not any(statement.lstrip().startswith(("INSERT", "UPDATE", "DELETE")) for statement in statements)


async def test_uncertain_result_acceptance_rolls_back_without_stale(session_factory, monkeypatch):
    _run, service, action, _context = await _reserved(session_factory, "result")
    with session_factory() as session:
        node = session.get(Node, action.node_id)
        assert node is not None and node.current_worker_instance_id is not None
        worker = session.get(WorkerInstance, node.current_worker_instance_id)
        assert worker is not None
    await service.mark_dispatched(
        action_id=action.id, worker_instance_id=worker.id, worker_incarnation=worker.incarnation
    )
    before = _state(session_factory, action.id)

    async def unavailable(*_args, **_kwargs):
        raise OperationalError("SELECT", {}, Exception("busy"))

    monkeypatch.setattr(
        lifecycle_module, "_evaluate_live_bound_action_authority", unavailable
    )
    with pytest.raises(ConflictError) as error:
        await service.accept_result(
            action_id=action.id,
            worker_instance_id=worker.id,
            worker_incarnation=worker.incarnation,
            tool_name=action.tool_name,
            arguments_digest=payload_digest({}),
            result={"external_effect": "unknown"},
        )
    assert error.value.code == "OPERATION_AUTHORITY_UNCERTAIN"
    assert _state(session_factory, action.id) == before


