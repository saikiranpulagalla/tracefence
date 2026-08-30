from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import func, select

import tracefence.services.operation_reconciliation as reconciliation_module
import tracefence.services.spawn_service as spawn_module
from tests.helpers import activate, create_seeded_run, create_v2_run
from tracefence.db.models import ActionAttempt, ControlCommand, Node, Run
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus, RunStatus
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal, SpawnCreate
from tracefence.security import payload_digest
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.lease_service import LeaseService
from tracefence.services.operation_lifecycle import OperationLifecycleService
from tracefence.services.operation_reconciliation import (
    NotFoundStrength,
    ObservationKind,
    OperationReconciliationService,
    ReconcilerCapabilities,
    ReconcilerContract,
    ReconcilerRegistry,
    ReconciliationObservation,
    RegisteredOperationReconciler,
)
from tracefence.services.operation_recovery import (
    OperationRecoveryService,
    RecoveryCreationStatus,
)
from tracefence.services.runtime_stop_service import RuntimeStopService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.tool_registry import TOOL_REGISTRY, ToolSpec


def _cancel_request(run, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_RUN,
        target_node_id=run.root_node_id,
        reason_code="CANCEL",
        reason_text="cancel run",
    )


async def test_late_cancel_against_completed_run_preserves_terminal_state(
    session_factory,
):
    run = await create_seeded_run(session_factory, "late-cancel-completed")
    await SpawnService(session_factory).complete(run.root_node_id, run.root_token)
    with session_factory() as session:
        completed = session.get(Run, run.run_id)
        assert completed is not None
        original_finished_at = completed.finished_at

    with pytest.raises(ConflictError) as captured:
        await ControlService(session_factory).issue_command(
            _cancel_request(run, "late-cancel-command"),
            Principal(issuer_type=IssuerType.HUMAN),
        )

    assert captured.value.code == "RUN_TERMINAL_STATE"
    with session_factory() as session:
        stored = session.get(Run, run.run_id)
        command_count = session.scalar(
            select(func.count(ControlCommand.id)).where(
                ControlCommand.run_id == run.run_id
            )
        )
        assert stored is not None
        assert stored.status == RunStatus.COMPLETED
        assert stored.finished_at == original_finished_at
        assert command_count == 0


async def test_concurrent_completion_and_cancellation_have_one_terminal_winner(
    session_factory,
):
    run = await create_seeded_run(session_factory, "complete-cancel-race")
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)

    def complete():
        return asyncio.run(spawns.complete(run.root_node_id, run.root_token))

    def cancel():
        return asyncio.run(
            controls.issue_command(
                _cancel_request(run, "concurrent-cancel-command"),
                Principal(issuer_type=IssuerType.HUMAN),
            )
        )

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = await asyncio.gather(
            loop.run_in_executor(pool, complete),
            loop.run_in_executor(pool, cancel),
            return_exceptions=True,
        )

    assert sum(not isinstance(outcome, Exception) for outcome in outcomes) == 1
    loser = next(outcome for outcome in outcomes if isinstance(outcome, Exception))
    assert isinstance(loser, ConflictError)
    assert loser.code in {"RUN_NOT_ACTIVE", "RUN_TERMINAL_STATE"}
    with session_factory() as session:
        stored = session.get(Run, run.run_id)
        assert stored is not None
        assert stored.status in {RunStatus.COMPLETED, RunStatus.CANCELLED}
        assert stored.finished_at is not None


async def test_root_lease_expiry_terminalizes_running_run(session_factory):
    run = await create_seeded_run(session_factory, "root-lease-expiry")
    with session_factory() as session, session.begin():
        root = session.get(Node, run.root_node_id)
        assert root is not None
        root.lease_expires_at = utcnow() - timedelta(seconds=1)

    expired = await LeaseService(session_factory).expire_stale_nodes(run.run_id)

    assert expired == 1
    with session_factory() as session:
        stored_run = session.get(Run, run.run_id)
        root = session.get(Node, run.root_node_id)
        assert stored_run is not None
        assert root is not None
        assert stored_run.status == RunStatus.FAILED
        assert stored_run.finished_at is not None
        assert root.status == NodeStatus.LEASE_EXPIRED


def _action_request(key: str) -> ActionExecute:
    return ActionExecute(
        tool_name="restart_postgres",
        arguments={},
        idempotency_key=key,
    )


async def test_root_completion_serializes_before_later_v2_reservation(
    session_factory,
    monkeypatch,
):
    """A completion that holds the writer first prevents later authorization."""
    original_predicate = spawn_module._has_unresolved_v2_actions

    for iteration in range(25):
        run = await create_v2_run(session_factory, f"complete-first-{iteration}")
        entered = threading.Event()
        release = threading.Event()

        def ordered_predicate(
            session,
            *,
            run_id,
            worker_instance_id=None,
            expected_run_id=run.run_id,
            entered=entered,
            release=release,
        ):
            if run_id == expected_run_id and worker_instance_id is None:
                entered.set()
                assert release.wait(timeout=5)
            return original_predicate(
                session,
                run_id=run_id,
                worker_instance_id=worker_instance_id,
            )

        monkeypatch.setattr(
            spawn_module, "_has_unresolved_v2_actions", ordered_predicate
        )
        spawns = SpawnService(session_factory)
        lifecycle = OperationLifecycleService(session_factory)

        def complete(
            spawns=spawns, node_id=run.root_node_id, node_token=run.root_token
        ):
            return asyncio.run(spawns.complete(node_id, node_token))

        def reserve(
            lifecycle=lifecycle,
            node_id=run.root_node_id,
            node_token=run.root_token,
            request_key=f"complete-first-{iteration}",
        ):
            return asyncio.run(
                lifecycle.reserve(
                    node_id=node_id,
                    credential=node_token,
                    request=_action_request(request_key),
                )
            )

        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=2) as pool:
            completion = loop.run_in_executor(pool, complete)
            assert entered.wait(timeout=5)
            reservation = loop.run_in_executor(pool, reserve)
            release.set()
            outcomes = await asyncio.gather(completion, reservation, return_exceptions=True)

        assert outcomes[0] is None
        assert isinstance(outcomes[1], ConflictError)
        assert outcomes[1].code in {"NODE_NOT_ACTIVE", "RUN_NOT_ACTIVE"}
        with session_factory() as session:
            stored_run = session.get(Run, run.run_id)
            assert stored_run is not None and stored_run.status == RunStatus.COMPLETED
            assert session.scalar(
                select(ActionAttempt.id).where(ActionAttempt.run_id == run.run_id)
            ) is None


async def test_v2_reservation_serializes_before_root_completion(session_factory):
    """A committed reservation remains a Run-level completion obligation."""
    for iteration in range(25):
        run = await create_v2_run(session_factory, f"reserve-first-{iteration}")
        await OperationLifecycleService(session_factory).reserve(
            node_id=run.root_node_id,
            credential=run.root_token,
            request=_action_request(f"reserve-first-{iteration}"),
        )

        with pytest.raises(ConflictError) as captured:
            await SpawnService(session_factory).complete(run.root_node_id, run.root_token)
        assert captured.value.code == "WORKER_HAS_UNRESOLVED_ACTIONS"
        with session_factory() as session:
            stored_run = session.get(Run, run.run_id)
            assert stored_run is not None and stored_run.status == RunStatus.RUNNING

RECOVERY_TOOL = "test_lifecycle_recovery"
RECOVERY_CAPABILITY = "tool:test_lifecycle_recovery"


class _LifecycleReconciler:
    def __init__(self, observation: ReconciliationObservation) -> None:
        self.observation = observation

    async def reconcile(self, _identity):
        return self.observation


def _install_lifecycle_reconciler(monkeypatch, reconciler: _LifecycleReconciler) -> None:
    registry = ReconcilerRegistry(
        (
            RegisteredOperationReconciler(
                ReconcilerContract(
                    provider_adapter_id="lifecycle-test",
                    provider_config_ref="cfg",
                    provider_scope_ref="scope",
                    tool_reconciliation_version="v1",
                    capabilities=ReconcilerCapabilities(
                        supports_definitive_nonexecution=True
                    ),
                ),
                reconciler,
            ),
        )
    )
    monkeypatch.setattr(
        reconciliation_module,
        "_resolve_registered_reconciler",
        registry.resolve,
    )


def _install_recovery_tool(monkeypatch) -> None:
    async def executor(_context, _arguments):
        raise AssertionError("recovery creation must not execute a protected effect")

    monkeypatch.setitem(
        TOOL_REGISTRY,
        RECOVERY_TOOL,
        ToolSpec(
            name=RECOVERY_TOOL,
            capability=RECOVERY_CAPABILITY,
            side_effecting=True,
            allowed_argument_keys=frozenset(),
            resources=frozenset({"test"}),
            execution_mode="cooperative",
            cooperative_executor=executor,
            explicit_recovery_policy_version="lifecycle-v1",
        ),
    )


async def _activated_child(session_factory, run, key: str, capability: str):
    with session_factory.begin() as session:
        root = session.get(Node, run.root_node_id)
        assert root is not None
        root.capabilities_json = [*(root.capabilities_json or []), capability]
    spawns = SpawnService(session_factory)
    created = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(
            operation_key=f"{key}-spawn",
            role="lifecycle-race-child",
            capabilities=[],
        ),
    )
    activated = await activate(spawns, created, process_id=100)
    with session_factory.begin() as session:
        child = session.get(Node, created.child_node_id)
        assert child is not None
        child.capabilities_json = [*(child.capabilities_json or []), capability]

    return created, activated


async def _reserve_child_action(session_factory, run, key: str, *, tool_name: str):
    capability = (
        RECOVERY_CAPABILITY
        if tool_name == RECOVERY_TOOL
        else "tool:restart_postgres"
    )
    created, activated = await _activated_child(session_factory, run, key, capability)
    action = await OperationLifecycleService(session_factory).reserve(
        node_id=created.child_node_id,
        credential=activated.node_token,
        request=ActionExecute(
            idempotency_key=f"{key}-action",
            tool_name=tool_name,
            arguments={},
        ),
        required_capability=capability,
    )
    return created, activated, action


async def _cancel_child(session_factory, run, child_node_id: str, key: str) -> None:
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key=f"{key}-cancel",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=child_node_id,
            reason_code="LIFECYCLE_RACE",
            reason_text="test-only lifecycle ordering",
        ),
        Principal(issuer_type=IssuerType.HUMAN, principal_id=f"{key}-operator"),
    )


async def _assert_run_completion_blocked(session_factory, run, action_id: str) -> None:
    with session_factory() as session:
        stored_run = session.get(Run, run.run_id)
        action = session.get(ActionAttempt, action_id)
        assert stored_run is not None
        assert action is not None
        revision = stored_run.proof_revision
        state = action.execution_state
    with pytest.raises(ConflictError) as captured:
        await SpawnService(session_factory).complete(run.root_node_id, run.root_token)
    assert captured.value.code == "RUN_HAS_UNRESOLVED_ACTIONS"
    with session_factory() as session:
        stored_run = session.get(Run, run.run_id)
        action = session.get(ActionAttempt, action_id)
        assert stored_run is not None and stored_run.status == RunStatus.RUNNING

        assert stored_run.proof_revision == revision
        assert action is not None and action.execution_state == state
async def _external_terminal_action(
    session_factory,
    monkeypatch,
    *,
    action: ActionAttempt,
    observation: ReconciliationObservation,
):
    reconciler = _LifecycleReconciler(observation)
    _install_lifecycle_reconciler(monkeypatch, reconciler)
    reconciliation = OperationReconciliationService(session_factory)
    identity = await reconciliation.create_binding(
        action_id=action.id,
        provider_adapter_id="lifecycle-test",
        provider_config_ref="cfg",
        provider_scope_ref="scope",
        tool_reconciliation_version="v1",
    )
    claim = await OperationLifecycleService(session_factory).mark_dispatched(
        action_id=action.id,
        worker_instance_id=identity.worker_instance_id,
        worker_incarnation=identity.worker_incarnation,
    )
    assert claim.status.value == "CLAIMED"
    applied = await reconciliation.reconcile_action(action_id=action.id)
    return applied.action


async def test_run_lifecycle_matrix_dispatch_before_complete(session_factory):
    """Case 3: a committed dispatch remains a Run-wide obligation."""
    for iteration in range(25):
        key = f"dispatch-before-complete-{iteration}"
        run = await create_v2_run(session_factory, key)
        child, _activated, action = await _reserve_child_action(
            session_factory, run, key, tool_name="restart_postgres"
        )
        claim = await OperationLifecycleService(session_factory).mark_dispatched(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        assert claim.status.value == "CLAIMED"
        await _cancel_child(session_factory, run, child.child_node_id, key)
        await _assert_run_completion_blocked(session_factory, run, action.id)


async def test_run_lifecycle_matrix_result_before_complete(session_factory):
    """Case 4: a terminal accepted result is not over-counted as unresolved."""
    for iteration in range(25):
        key = f"result-before-complete-{iteration}"
        run = await create_v2_run(session_factory, key)
        lifecycle = OperationLifecycleService(session_factory)
        action = await lifecycle.reserve(
            node_id=run.root_node_id,
            credential=run.root_token,
            request=_action_request(key),
        )
        await lifecycle.mark_dispatched(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        accepted = await lifecycle.accept_result(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            tool_name=action.tool_name,
            arguments_digest=payload_digest({}),
            result={"case": "result-before-complete"},
        )
        assert accepted.accepted
        assert accepted.action.execution_state == "SUCCEEDED"
        assert await SpawnService(session_factory).complete(run.root_node_id, run.root_token) is None
        with session_factory() as session:
            stored_run = session.get(Run, run.run_id)
            assert stored_run is not None and stored_run.status == RunStatus.COMPLETED


async def test_run_lifecycle_matrix_complete_before_later_result_replay(session_factory):
    """Case 5: terminal replay after completion cannot create new authority."""
    for iteration in range(25):
        key = f"complete-before-result-{iteration}"
        run = await create_v2_run(session_factory, key)
        lifecycle = OperationLifecycleService(session_factory)
        action = await lifecycle.reserve(
            node_id=run.root_node_id,
            credential=run.root_token,
            request=_action_request(key),
        )
        await lifecycle.mark_dispatched(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        result = {"case": "complete-before-later-result"}
        await lifecycle.accept_result(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            tool_name=action.tool_name,
            arguments_digest=payload_digest({}),
            result=result,
        )
        await SpawnService(session_factory).complete(run.root_node_id, run.root_token)
        with session_factory() as session:
            before = session.get(Run, run.run_id)
            assert before is not None
            revision = before.proof_revision
        replay = await lifecycle.accept_result(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            tool_name=action.tool_name,
            arguments_digest=payload_digest({}),
            result=result,
        )
        assert replay.accepted and replay.action.execution_state == "SUCCEEDED"
        with session_factory() as session:
            stored = session.get(Run, run.run_id)
            assert stored is not None and stored.status == RunStatus.COMPLETED
            assert stored.proof_revision == revision

async def test_run_lifecycle_matrix_ambiguous_before_complete(session_factory, monkeypatch):
    """Case 6: real conflicting reconciliation evidence stays unresolved."""
    for iteration in range(25):
        key = f"ambiguous-before-complete-{iteration}"
        run = await create_v2_run(session_factory, key)
        child, _activated, action = await _reserve_child_action(
            session_factory, run, key, tool_name="restart_postgres"
        )
        applied = await _external_terminal_action(
            session_factory,
            monkeypatch,
            action=action,
            observation=ReconciliationObservation(
                ObservationKind.CONFLICT, result={"case": "ambiguous"}
            ),
        )
        assert applied.execution_state == "AMBIGUOUS"
        await _cancel_child(session_factory, run, child.child_node_id, key)
        await _assert_run_completion_blocked(session_factory, run, action.id)


async def test_run_lifecycle_matrix_nonlive_child_dispatched(session_factory):
    """Case 7: a production CANCEL_SUBTREE does not hide a dispatched child action."""
    for iteration in range(25):
        key = f"nonlive-dispatched-{iteration}"
        run = await create_v2_run(session_factory, key)
        child, _activated, action = await _reserve_child_action(
            session_factory, run, key, tool_name="restart_postgres"
        )
        await OperationLifecycleService(session_factory).mark_dispatched(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        await _cancel_child(session_factory, run, child.child_node_id, key)
        await _assert_run_completion_blocked(session_factory, run, action.id)


async def test_run_lifecycle_matrix_nonexecution_source_does_not_block(
    session_factory, monkeypatch
):
    """Case 8: definitive NONEXECUTION produces terminal source truth, not a blocker."""
    for iteration in range(25):
        key = f"nonexecution-source-{iteration}"
        run = await create_v2_run(session_factory, key)
        action = await OperationLifecycleService(session_factory).reserve(
            node_id=run.root_node_id,
            credential=run.root_token,
            request=_action_request(key),
        )
        applied = await _external_terminal_action(
            session_factory,
            monkeypatch,
            action=action,
            observation=ReconciliationObservation(
                ObservationKind.NOT_FOUND,
                not_found_strength=NotFoundStrength.DEFINITIVE_NONEXECUTION,
            ),
        )
        assert applied.execution_state == "FAILED"
        assert await SpawnService(session_factory).complete(run.root_node_id, run.root_token) is None

async def test_run_lifecycle_matrix_unresolved_recovery_successor(
    session_factory, monkeypatch
):
    """Case 9: the authorized successor, not its terminal source, blocks completion."""
    _install_recovery_tool(monkeypatch)
    for iteration in range(25):
        key = f"recovery-successor-{iteration}"
        run = await create_v2_run(session_factory, key)
        child, activated, source = await _reserve_child_action(
            session_factory, run, key, tool_name=RECOVERY_TOOL
        )
        applied = await _external_terminal_action(
            session_factory,
            monkeypatch,
            action=source,
            observation=ReconciliationObservation(
                ObservationKind.NOT_FOUND,
                not_found_strength=NotFoundStrength.DEFINITIVE_NONEXECUTION,
            ),
        )
        assert applied.execution_state == "FAILED"
        created = await OperationRecoveryService(session_factory).create_recovery(
            source_action_id=source.id,
            node_id=child.child_node_id,
            node_token=activated.node_token,
            request=ActionExecute(
                idempotency_key=f"{key}-request",
                tool_name=RECOVERY_TOOL,
                arguments={},
            ),
            recovery_request_identity=key,
        )
        assert created.status == RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_CREATED
        assert created.action.id != source.id
        assert created.action.execution_state == "AUTHORIZED"
        await _cancel_child(session_factory, run, child.child_node_id, key)
        await _assert_run_completion_blocked(session_factory, run, created.action.id)


async def test_run_lifecycle_matrix_trusted_terminal_does_not_resolve_action(
    session_factory,
):
    """Case 10: physical terminal evidence never resolves a dispatched action."""
    for iteration in range(25):
        key = f"trusted-terminal-{iteration}"
        run = await create_v2_run(session_factory, key)
        child, _activated, action = await _reserve_child_action(
            session_factory, run, key, tool_name="restart_postgres"
        )
        await OperationLifecycleService(session_factory).mark_dispatched(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        await _cancel_child(session_factory, run, child.child_node_id, key)
        assert await RuntimeStopService(session_factory).record_trusted_terminal(
            worker_instance_id=action.worker_instance_id or "",
            terminal_state="EXITED",
        )
        await _assert_run_completion_blocked(session_factory, run, action.id)
