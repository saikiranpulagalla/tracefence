from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from uuid import uuid4

import pytest
from sqlalchemy import select

import tracefence.services.operation_reconciliation as reconciliation_module
from tests.helpers import create_v2_run
from tracefence.db.models import ActionAttempt, ActionReconciliationEvidence, Node, WorkerInstance
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import ServiceUnavailableError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal
from tracefence.security import hash_token, payload_digest
from tracefence.services.control_service import ControlService
from tracefence.services.operation_lifecycle import OperationLifecycleService
from tracefence.services.operation_reconciliation import (
    ObservationKind,
    OperationReconciliationService,
    ReconcilerCapabilities,
    ReconcilerContract,
    ReconcilerRegistry,
    ReconciliationObservation,
    RegisteredOperationReconciler,
)
from tracefence.services.reconciliation_controller import (
    ReconciliationActionStatus,
    ReconciliationController,
)

REPETITIONS = range(25)
CASES = (
    "duplicate-controller",
    "terminal-after-selection",
    "cancel-during-query",
    "w2-during-query",
    "scope-change-during-query",
    "crash-after-query",
    "batch-error-isolation",
    "conflicting-observations",
)


@dataclass
class GateReconciler:
    response: ReconciliationObservation | Exception
    expected_queries: int = 1
    queries: int = 0
    started: asyncio.Event = field(default_factory=asyncio.Event)
    all_started: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)

    async def reconcile(self, identity):
        self.queries += 1
        self.started.set()
        if self.queries == self.expected_queries:
            self.all_started.set()
        await self.release.wait()
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _registry(reconciler) -> ReconcilerRegistry:
    contract = ReconcilerContract(
        provider_adapter_id="fake",
        provider_config_ref="cfg-a",
        provider_scope_ref="tenant-a",
        tool_reconciliation_version="1",
        capabilities=ReconcilerCapabilities(supports_definitive_nonexecution=True),
    )
    return ReconcilerRegistry((RegisteredOperationReconciler(contract, reconciler),))


def _request(key: str) -> ActionExecute:
    return ActionExecute(tool_name="restart_postgres", arguments={}, idempotency_key=key)


async def _dispatched(session_factory, service, key: str):
    run = await create_v2_run(session_factory, key)
    lifecycle = OperationLifecycleService(session_factory)
    action = await lifecycle.reserve(
        node_id=run.root_node_id,
        credential=run.root_token,
        request=_request(key),
    )
    identity = await service.create_binding(
        action_id=action.id,
        provider_adapter_id="fake",
        provider_config_ref="cfg-a",
        provider_scope_ref="tenant-a",
        tool_reconciliation_version="1",
    )
    claim = await lifecycle.mark_dispatched(
        action_id=action.id,
        worker_instance_id=identity.worker_instance_id,
        worker_incarnation=identity.worker_incarnation,
    )
    assert claim.status.value == "CLAIMED"
    return run, action, identity


async def _cancel(session_factory, run, key: str) -> None:
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key=key,
            command_type=CommandType.CANCEL_RUN,
            target_node_id=run.root_node_id,
            reason_code="TEST",
            reason_text="deterministic reconciliation controller ordering",
        ),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="reconciliation-controller-race"),
    )


def _replace_worker(session_factory, action: ActionAttempt, identity) -> None:
    with session_factory.begin() as session:
        node = session.get(Node, action.node_id)
        old = session.get(WorkerInstance, identity.worker_instance_id)
        assert node is not None and old is not None
        replacement = WorkerInstance(
            id=str(uuid4()),
            node_id=node.id,
            incarnation=old.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=old.activated_at,
            credential_hash=hash_token("reconciliation-controller-w2"),
        )
        session.add(replacement)
        session.flush()
        node.current_worker_instance_id = replacement.id


def _state(session_factory, action_id: str) -> ActionAttempt:
    with session_factory() as session:
        action = session.get(ActionAttempt, action_id)
        assert action is not None
        return action


@pytest.mark.parametrize("iteration", REPETITIONS)
@pytest.mark.parametrize("case", CASES)
async def test_reconciliation_controller_ordering_matrix(
    session_factory, monkeypatch, iteration, case
):
    response = ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True})
    fake = GateReconciler(response, expected_queries=2 if case == "duplicate-controller" else 1)
    monkeypatch.setattr(
        reconciliation_module,
        "_resolve_registered_reconciler",
        _registry(fake).resolve,
    )
    service = OperationReconciliationService(session_factory)
    run, action, identity = await _dispatched(session_factory, service, f"c2-{case}-{iteration}")
    controller = ReconciliationController(session_factory, service)

    if case == "duplicate-controller":
        first = asyncio.create_task(controller.run_once(limit=1))
        second = asyncio.create_task(controller.run_once(limit=1))
        await fake.all_started.wait()
        fake.release.set()
        first_result, second_result = await asyncio.gather(first, second)
        assert fake.queries == 2
        assert _state(session_factory, action.id).execution_state == "SUCCEEDED"
        with session_factory() as session:
            assert session.scalars(
                select(ActionReconciliationEvidence).where(
                    ActionReconciliationEvidence.action_id == action.id
                )
            ).all().__len__() == 1
        assert {
            first_result.actions[0].status,
            second_result.actions[0].status,
        } == {ReconciliationActionStatus.RECONCILED_MATERIAL}
        return

    if case == "terminal-after-selection":
        ready, release = asyncio.Event(), asyncio.Event()
        original = controller._reconcile_one

        async def paused(action_id: str):
            ready.set()
            await release.wait()
            return await original(action_id)

        monkeypatch.setattr(controller, "_reconcile_one", paused)
        task = asyncio.create_task(controller.run_once(limit=1))
        await ready.wait()
        lifecycle = OperationLifecycleService(session_factory)
        await lifecycle.accept_result(
            action_id=action.id,
            worker_instance_id=identity.worker_instance_id,
            worker_incarnation=identity.worker_incarnation,
            tool_name=action.tool_name,
            arguments_digest=payload_digest({}),
            result={"ok": True},
        )
        release.set()
        fake.release.set()
        result = await task
        assert _state(session_factory, action.id).execution_state == "SUCCEEDED"
        assert result.actions[0].status == ReconciliationActionStatus.RECONCILED_MATERIAL
        return

    if case in {"cancel-during-query", "scope-change-during-query"}:
        task = asyncio.create_task(controller.run_once(limit=1))
        await fake.started.wait()
        await _cancel(session_factory, run, f"{case}-{iteration}-command")
        fake.release.set()
        result = await task
        assert _state(session_factory, action.id).execution_state == "STALE"
        assert result.actions[0].status == ReconciliationActionStatus.RECONCILED_MATERIAL
        return

    if case == "w2-during-query":
        task = asyncio.create_task(controller.run_once(limit=1))
        await fake.started.wait()
        _replace_worker(session_factory, action, identity)
        fake.release.set()
        result = await task
        assert _state(session_factory, action.id).execution_state == "STALE"
        assert result.actions[0].status == ReconciliationActionStatus.RECONCILED_MATERIAL
        return

    if case == "crash-after-query":
        original_apply = service._apply_reconciled_observation

        async def interrupted(**_kwargs):
            raise ServiceUnavailableError("simulated interruption", code="SIMULATED_CRASH")

        monkeypatch.setattr(service, "_apply_reconciled_observation", interrupted)
        fake.release.set()
        first = await controller.run_once(limit=1)
        assert first.actions[0].status == ReconciliationActionStatus.ERROR_TRANSIENT
        assert _state(session_factory, action.id).execution_state == "DISPATCHED"
        with session_factory() as session:
            assert session.scalars(
                select(ActionReconciliationEvidence).where(
                    ActionReconciliationEvidence.action_id == action.id
                )
            ).all() == []
        monkeypatch.setattr(service, "_apply_reconciled_observation", original_apply)
        second = await controller.run_once(limit=1)
        assert second.actions[0].status == ReconciliationActionStatus.RECONCILED_MATERIAL
        assert _state(session_factory, action.id).execution_state == "SUCCEEDED"
        return

    if case == "batch-error-isolation":
        other_run, other_action, _ = await _dispatched(session_factory, service, f"c2-batch-{iteration}")
        del other_run
        class RoutingReconciler:
            def __init__(self):
                self.queries = []
            async def reconcile(self, queried_identity):
                self.queries.append(queried_identity.action_id)
                if queried_identity.action_id == action.id:
                    raise ServiceUnavailableError("provider down", code="PROVIDER_DOWN")
                return ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True})
        routed = RoutingReconciler()
        monkeypatch.setattr(
            reconciliation_module,
            "_resolve_registered_reconciler",
            _registry(routed).resolve,
        )
        result = await controller.run_once(limit=2)
        assert result.error_count == result.material_count == 1
        assert _state(session_factory, action.id).execution_state == "DISPATCHED"
        assert _state(session_factory, other_action.id).execution_state == "SUCCEEDED"
        return

    if case == "conflicting-observations":
        class ConflictingReconciler:
            def __init__(self):
                self.queries = 0
                self.all_started = asyncio.Event()
                self.release = asyncio.Event()

            async def reconcile(self, queried_identity):
                self.queries += 1
                query_number = self.queries
                if query_number == 2:
                    self.all_started.set()
                await self.release.wait()
                if query_number == 1:
                    return ReconciliationObservation(ObservationKind.SUCCEEDED, result={"one": True})
                return ReconciliationObservation(ObservationKind.FAILED, result={"two": True})
        conflicting = ConflictingReconciler()
        monkeypatch.setattr(
            reconciliation_module,
            "_resolve_registered_reconciler",
            _registry(conflicting).resolve,
        )
        first = asyncio.create_task(controller.run_once(limit=1))
        second = asyncio.create_task(controller.run_once(limit=1))
        await conflicting.all_started.wait()
        conflicting.release.set()
        results = await asyncio.gather(first, second)
        assert conflicting.queries == 2
        with session_factory() as session:
            evidence = session.scalars(
                select(ActionReconciliationEvidence).where(
                    ActionReconciliationEvidence.action_id == action.id
                )
            ).all()
            assert len(evidence) == 2
        assert any(
            item.actions[0].status == ReconciliationActionStatus.RECONCILED_CONFLICT
            for item in results
        )
        return

    raise AssertionError(f"unhandled case {case}")
