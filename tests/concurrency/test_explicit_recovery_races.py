from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import select, text

from tests.helpers import create_v2_run
from tests.unit.test_operation_recovery import (
    CAPABILITY,
    TOOL,
    Counts,
    Reconciler,
    _install_reconciler,
    _install_tool,
    _request,
)
from tracefence.db.models import ActionAttempt, ActionRecoveryLink, Node, Run, WorkerInstance
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import AuthenticationError, ConflictError
from tracefence.domain.schemas import (
    ActionExecute,
    CommandCreate,
    NodeActivate,
    Principal,
    SpawnCreate,
)
from tracefence.security import hash_token
from tracefence.services.control_service import ControlService
from tracefence.services.operation_lifecycle import DispatchClaimStatus, OperationLifecycleService
from tracefence.services.operation_reconciliation import (
    NotFoundStrength,
    ObservationKind,
    OperationReconciliationService,
    ReconciliationObservation,
)
from tracefence.services.operation_recovery import OperationRecoveryService, RecoveryCreationStatus
from tracefence.services.spawn_service import SpawnService

REPETITIONS = range(25)
CASES = (
    "create-before-cancel", "cancel-before-create",
    "create-before-replacement", "replacement-before-create",
    "scope-before-create", "create-before-conflict",
    "conflict-before-create", "concurrent-exact-creators",
    "concurrent-changed-payload", "concurrent-different-worker",
    "conflict-before-dispatch", "dispatch-before-conflict",
    "duplicate-dispatch",
)


def _principal(key: str) -> Principal:
    return Principal(issuer_type=IssuerType.HUMAN, principal_id=f"c3-race-{key}")


async def _source(session_factory, monkeypatch, key: str):
    counts = Counts()
    _install_tool(monkeypatch, counts)
    run = await create_v2_run(session_factory, key)
    spawns = SpawnService(session_factory)
    spawned = await spawns.create_spawn(
        run.root_node_id, run.root_token,
        SpawnCreate(role="c3-race", capabilities=["tool:restart_postgres"]),
    )
    activated = await spawns.activate(
        spawned.child_node_id, NodeActivate(activation_token=spawned.activation_token)
    )
    with session_factory.begin() as session:
        node = session.get(Node, spawned.child_node_id)
        assert node is not None
        node.capabilities_json = [CAPABILITY]
    lifecycle = OperationLifecycleService(session_factory)
    source = await lifecycle.reserve(
        node_id=spawned.child_node_id,
        credential=activated.node_token,
        request=_request(f"{key}-source"),
        required_capability=CAPABILITY,
    )
    reconciler = Reconciler(
        counts,
        ReconciliationObservation(
            ObservationKind.NOT_FOUND,
            not_found_strength=NotFoundStrength.DEFINITIVE_NONEXECUTION,
        ),
    )
    _install_reconciler(monkeypatch, reconciler)
    reconciliation = OperationReconciliationService(session_factory)
    identity = await reconciliation.create_binding(
        action_id=source.id,
        provider_adapter_id="test",
        provider_config_ref="cfg",
        provider_scope_ref="scope",
        tool_reconciliation_version="test-v1",
    )
    claim = await lifecycle.mark_dispatched(
        action_id=source.id,
        worker_instance_id=identity.worker_instance_id,
        worker_incarnation=identity.worker_incarnation,
    )
    assert claim.status == DispatchClaimStatus.CLAIMED
    applied = await reconciliation.reconcile_action(action_id=source.id)
    assert applied.accepted and applied.action.execution_state == "FAILED"
    return run, spawned.child_node_id, activated.node_token, source, reconciliation, reconciler, counts


def _links(session_factory, source: ActionAttempt):
    with session_factory() as session:
        return session.scalars(select(ActionRecoveryLink).where(
            ActionRecoveryLink.source_run_id == source.run_id,
            ActionRecoveryLink.source_action_id == source.id,
        )).all()


def _proof(session_factory, run_id: str) -> int:
    with session_factory() as session:
        run = session.get(Run, run_id)
        assert run is not None
        return run.proof_revision


def _assert_atomic(session_factory, source: ActionAttempt) -> None:
    links = _links(session_factory, source)
    linked = {link.recovery_action_id for link in links}
    with session_factory() as session:
        authorized = session.scalars(select(ActionAttempt).where(
            ActionAttempt.run_id == source.run_id,
            ActionAttempt.id != source.id,
            ActionAttempt.execution_state == "AUTHORIZED",
        )).all()
        assert {row.id for row in authorized} <= linked
        for link in links:
            assert session.get(ActionAttempt, link.recovery_action_id) is not None


def _replace(session_factory, node_id: str, token: str) -> WorkerInstance:
    with session_factory() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        try:
            node = session.get(Node, node_id)
            assert node is not None and node.current_worker_instance_id is not None
            old = session.get(WorkerInstance, node.current_worker_instance_id)
            assert old is not None
            w3 = WorkerInstance(
                id=str(uuid4()), node_id=node.id, incarnation=old.incarnation + 1,
                observed_state="ACTIVE", activated_at=old.activated_at,
                credential_hash=hash_token(token),
            )
            session.add(w3)
            session.flush()
            node.current_worker_instance_id = w3.id
            session.commit()
            return w3
        except Exception:
            session.rollback()
            raise


async def _command(session_factory, run, node_id: str, key: str, kind=CommandType.CANCEL_RUN) -> None:
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key=key,
            command_type=kind,
            target_node_id=run.root_node_id if kind == CommandType.CANCEL_RUN else node_id,
            reason_code="TEST",
            reason_text="deterministic C-C3 race ordering",
        ),
        _principal(key),
    )


async def _create(session_factory, node_id, node_token, source, key: str, identity: str, *, token=None, arguments=None):
    request = _request(f"request-{key}") if arguments is None else ActionExecute(
        idempotency_key=f"request-{key}", tool_name=TOOL, arguments=arguments
    )
    return await OperationRecoveryService(session_factory).create_recovery(
        source_action_id=source.id,
        node_id=node_id,
        node_token=token or node_token,
        request=request,
        recovery_request_identity=identity,
    )


async def _claim(session_factory, action, counts):
    claim = await OperationLifecycleService(session_factory).mark_dispatched(
        action_id=action.id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    if claim.status == DispatchClaimStatus.CLAIMED:
        executor = __import__("tracefence.services.tool_registry", fromlist=["TOOL_REGISTRY"]).TOOL_REGISTRY[TOOL].cooperative_executor
        assert executor is not None
        await executor(None, {})
    return claim


async def _conflict(reconciliation, reconciler, source) -> None:
    reconciler.observation = ReconciliationObservation(
        ObservationKind.CONFLICT, result={"provider": "incompatible"}
    )
    applied = await reconciliation.reconcile_action(action_id=source.id)
    assert applied.evidence_recorded and applied.status == "CONFLICT"


def _concurrent(*calls):
    barrier = Barrier(len(calls))

    def invoke(call):
        barrier.wait(timeout=5)
        return call()

    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        futures = [pool.submit(invoke, call) for call in calls]
        results = []
        for future in futures:
            try:
                results.append(future.result(timeout=15))
            except Exception as error:
                results.append(error)
    return results


@pytest.mark.parametrize("iteration", REPETITIONS)
@pytest.mark.parametrize("case", CASES)
async def test_explicit_recovery_deterministic_ordering_matrix(
    session_factory, monkeypatch, iteration, case
):
    run, node_id, node_token, source, reconciliation, reconciler, counts = await _source(
        session_factory, monkeypatch, f"c3-{case}-{iteration}"
    )
    if case == "create-before-cancel":
        created = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        await _command(session_factory, run, node_id, f"cancel-{iteration}")
        assert (await _claim(session_factory, created.action, counts)).status == DispatchClaimStatus.REVOKED
        assert len(_links(session_factory, source)) == 1

    elif case == "cancel-before-create":
        await _command(session_factory, run, node_id, f"cancel-{iteration}")
        denied = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        assert denied.status == RecoveryCreationStatus.CANONICAL_DENIED
        assert _links(session_factory, source) == []

    elif case == "create-before-replacement":
        created = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        w3 = _replace(session_factory, node_id, "w3-token")
        assert w3.id != created.action.worker_instance_id
        assert (await _claim(session_factory, created.action, counts)).status == DispatchClaimStatus.REVOKED

    elif case == "replacement-before-create":
        _replace(session_factory, node_id, "w3-token")
        after_replacement = _proof(session_factory, run.run_id)
        with pytest.raises(AuthenticationError):
            await _create(session_factory, node_id, node_token, source, "r1", "r1")
        assert _links(session_factory, source) == []
        assert _proof(session_factory, run.run_id) == after_replacement

    elif case == "scope-before-create":
        await _command(
            session_factory, run, node_id, f"scope-{iteration}", CommandType.CANCEL_SUBTREE
        )
        denied = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        assert denied.status == RecoveryCreationStatus.CANONICAL_DENIED
        assert _links(session_factory, source) == []

    elif case == "create-before-conflict":
        created = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        await _conflict(reconciliation, reconciler, source)
        assert (await _claim(session_factory, created.action, counts)).status == DispatchClaimStatus.REVOKED
        assert len(_links(session_factory, source)) == 1

    elif case == "conflict-before-create":
        await _conflict(reconciliation, reconciler, source)
        after_conflict = _proof(session_factory, run.run_id)
        with pytest.raises(ConflictError, match="material reconciliation conflict"):
            await _create(session_factory, node_id, node_token, source, "r1", "r1")
        assert _links(session_factory, source) == []
        assert _proof(session_factory, run.run_id) == after_conflict

    elif case == "concurrent-exact-creators":
        results = _concurrent(
            lambda: asyncio.run(_create(session_factory, node_id, node_token, source, "r1", "r1")),
            lambda: asyncio.run(_create(session_factory, node_id, node_token, source, "r1", "r1")),
        )
        assert {row.status for row in results} == {
            RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_CREATED,
            RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_REPLAY,
        }
        assert len({row.action.id for row in results}) == 1
        replay_proof = _proof(session_factory, run.run_id)
        replay = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        assert replay.status == RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_REPLAY
        assert _proof(session_factory, run.run_id) == replay_proof

    elif case == "concurrent-changed-payload":
        results = _concurrent(
            lambda: asyncio.run(_create(session_factory, node_id, node_token, source, "r1", "r1")),
            lambda: asyncio.run(_create(session_factory, node_id, node_token, source, "r2", "r2", arguments={"changed": True})),
        )
        assert sum(isinstance(row, ConflictError) for row in results) == 1
        assert sum(getattr(row, "status", None) == RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_CREATED for row in results) == 1

    elif case == "concurrent-different-worker":
        token = "w3-token"
        _replace(session_factory, node_id, token)
        results = _concurrent(
            lambda: asyncio.run(_create(session_factory, node_id, node_token, source, "w2", "r1")),
            lambda: asyncio.run(_create(session_factory, node_id, node_token, source, "w3", "r1", token=token)),
        )
        assert sum(isinstance(row, AuthenticationError) for row in results) == 1
        assert sum(getattr(row, "status", None) == RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_CREATED for row in results) == 1

    elif case == "conflict-before-dispatch":
        created = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        await _conflict(reconciliation, reconciler, source)
        before_claim = _proof(session_factory, run.run_id)
        assert (await _claim(session_factory, created.action, counts)).status == DispatchClaimStatus.REVOKED
        assert _proof(session_factory, run.run_id) > before_claim

    elif case == "dispatch-before-conflict":
        created = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        assert (await _claim(session_factory, created.action, counts)).status == DispatchClaimStatus.CLAIMED
        await _conflict(reconciliation, reconciler, source)
        assert (await _claim(session_factory, created.action, counts)).status == DispatchClaimStatus.ALREADY_DISPATCHED
        assert counts.executor_calls == 1

    elif case == "duplicate-dispatch":
        created = await _create(session_factory, node_id, node_token, source, "r1", "r1")
        results = _concurrent(
            lambda: asyncio.run(_claim(session_factory, created.action, counts)),
            lambda: asyncio.run(_claim(session_factory, created.action, counts)),
        )
        assert sorted(row.status for row in results) == [
            DispatchClaimStatus.ALREADY_DISPATCHED, DispatchClaimStatus.CLAIMED,
        ]
        assert counts.executor_calls == 1

    else:  # pragma: no cover
        raise AssertionError(case)

    with session_factory() as session:
        persisted = session.get(ActionAttempt, source.id)
        assert persisted is not None and persisted.execution_state == "FAILED"
    assert counts.executor_calls in {0, 1}
    _assert_atomic(session_factory, source)