from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field

import pytest

import tracefence.services.operation_reconciliation as reconciliation_module
from tests.helpers import create_v2_run
from tracefence.domain.errors import ServiceUnavailableError
from tracefence.domain.schemas import ActionExecute
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


@dataclass
class RoutingReconciler:
    responses: dict[str, ReconciliationObservation | Exception]
    queries: list[str] = field(default_factory=list)

    async def reconcile(self, identity):
        self.queries.append(identity.action_id)
        response = self.responses[identity.action_id]
        if isinstance(response, Exception):
            raise response
        return response


def _registry(reconciler: RoutingReconciler) -> ReconcilerRegistry:
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


async def _bound_dispatched(session_factory, service, key: str):
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
    return run, action


async def _controller_with_actions(session_factory, monkeypatch, count: int, prefix: str):
    reconciler = RoutingReconciler({})
    monkeypatch.setattr(
        reconciliation_module,
        "_resolve_registered_reconciler",
        _registry(reconciler).resolve,
    )
    service = OperationReconciliationService(session_factory)
    actions = []
    for index in range(count):
        _, action = await _bound_dispatched(session_factory, service, f"{prefix}-{index}")
        reconciler.responses[action.id] = ReconciliationObservation(ObservationKind.IN_PROGRESS)
        actions.append(action)
    return ReconciliationController(session_factory, service), reconciler, actions


async def test_keyset_selection_uses_bound_unresolved_lifecycle_actions(
    session_factory, monkeypatch
):
    controller, reconciler, actions = await _controller_with_actions(
        session_factory, monkeypatch, 3, "selection"
    )

    batch = await controller.run_once(limit=1)
    ordered_ids = sorted(action.id for action in actions)

    assert batch.selected_count == batch.attempted_count == 1
    assert batch.has_more
    assert batch.next_after_action_id == ordered_ids[0]
    assert [result.action_id for result in batch.actions] == [ordered_ids[0]]
    assert reconciler.queries == [ordered_ids[0]]

    second = await controller.run_once(limit=1, after_action_id=batch.next_after_action_id)
    assert [result.action_id for result in second.actions] == [ordered_ids[1]]
    assert second.has_more

    third = await controller.run_once(limit=1, after_action_id=second.next_after_action_id)
    assert [result.action_id for result in third.actions] == [ordered_ids[2]]
    assert not third.has_more


async def test_limit_validation_and_zero_action_cursor_are_deterministic(session_factory):
    controller = ReconciliationController(
        session_factory, OperationReconciliationService(session_factory)
    )

    for invalid in (0, -1):
        with pytest.raises(ValueError):
            await controller.run_once(limit=invalid)
    for invalid in (True, "1", 1.0):
        with pytest.raises(TypeError):
            await controller.run_once(limit=invalid)

    batch = await controller.run_once(limit=1, after_action_id="cursor")
    assert batch.actions == ()
    assert batch.next_after_action_id == "cursor"
    assert not batch.has_more


async def test_controller_maps_no_registered_reconciler_without_mutation(
    session_factory, monkeypatch
):
    service = OperationReconciliationService(session_factory)
    _, action = await _bound_dispatched(session_factory, service, "unregistered")
    controller = ReconciliationController(session_factory, service)

    batch = await controller.run_once(limit=1)

    assert batch.actions[0].action_id == action.id
    assert batch.actions[0].status == ReconciliationActionStatus.SKIPPED_NO_RECONCILER
    assert batch.skipped_no_reconciler_count == 1
    assert batch.material_count == batch.error_count == 0


async def test_non_material_and_material_outcomes_are_only_c1_classifications(
    session_factory, monkeypatch
):
    controller, reconciler, actions = await _controller_with_actions(
        session_factory, monkeypatch, 2, "outcomes"
    )
    ordered = sorted(actions, key=lambda action: action.id)
    reconciler.responses[ordered[0].id] = ReconciliationObservation(ObservationKind.IN_PROGRESS)
    reconciler.responses[ordered[1].id] = ReconciliationObservation(
        ObservationKind.SUCCEEDED, result={"external": "success"}
    )

    batch = await controller.run_once(limit=2)

    assert [result.status for result in batch.actions] == [
        ReconciliationActionStatus.RECONCILED_NON_MATERIAL,
        ReconciliationActionStatus.RECONCILED_MATERIAL,
    ]
    assert batch.non_material_count == batch.material_count == 1


async def test_conflict_and_expected_provider_failure_are_isolated(
    session_factory, monkeypatch
):
    controller, reconciler, actions = await _controller_with_actions(
        session_factory, monkeypatch, 3, "isolation"
    )
    ordered = sorted(actions, key=lambda action: action.id)
    reconciler.responses[ordered[0].id] = ReconciliationObservation(
        ObservationKind.CONFLICT, result={"provider": "conflict"}
    )
    reconciler.responses[ordered[1].id] = ServiceUnavailableError(
        "provider unavailable", code="PROVIDER_UNAVAILABLE"
    )
    reconciler.responses[ordered[2].id] = ReconciliationObservation(ObservationKind.IN_PROGRESS)

    batch = await controller.run_once(limit=3)

    assert [result.status for result in batch.actions] == [
        ReconciliationActionStatus.RECONCILED_CONFLICT,
        ReconciliationActionStatus.ERROR_TRANSIENT,
        ReconciliationActionStatus.RECONCILED_NON_MATERIAL,
    ]
    assert batch.conflict_count == batch.error_count == batch.non_material_count == 1
    assert reconciler.queries == [action.id for action in ordered]


async def test_programming_error_and_task_cancellation_propagate(session_factory, monkeypatch):
    controller, reconciler, actions = await _controller_with_actions(
        session_factory, monkeypatch, 1, "propagate"
    )
    reconciler.responses[actions[0].id] = RuntimeError("programming defect")

    with pytest.raises(RuntimeError, match="programming defect"):
        await controller.run_once(limit=1)

    started = asyncio.Event()
    release = asyncio.Event()

    class BlockingService:
        async def reconcile_action(self, *, action_id: str):
            started.set()
            await release.wait()
            raise AssertionError("cancelled task should not resume")

    blocking = ReconciliationController(session_factory, BlockingService())
    task = asyncio.create_task(blocking.run_once(limit=1))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_constructor_accepts_only_session_factory_and_c1_service():
    signature = inspect.signature(ReconciliationController)
    assert tuple(signature.parameters) == ("session_factory", "reconciliation_service")



async def test_selection_excludes_authorized_unbound_and_terminal_actions(
    session_factory, monkeypatch
):
    controller, reconciler, actions = await _controller_with_actions(
        session_factory, monkeypatch, 2, "exclusion"
    )
    selected, terminal = sorted(actions, key=lambda action: action.id)
    reconciler.responses[terminal.id] = ReconciliationObservation(
        ObservationKind.SUCCEEDED, result={"terminal": True}
    )
    service = OperationReconciliationService(session_factory)
    await service.reconcile_action(action_id=terminal.id)

    authorized_run = await create_v2_run(session_factory, "authorized-exclusion")
    await OperationLifecycleService(session_factory).reserve(
        node_id=authorized_run.root_node_id,
        credential=authorized_run.root_token,
        request=_request("authorized-exclusion"),
    )

    unbound_run = await create_v2_run(session_factory, "unbound-exclusion")
    lifecycle = OperationLifecycleService(session_factory)
    unbound = await lifecycle.reserve(
        node_id=unbound_run.root_node_id,
        credential=unbound_run.root_token,
        request=_request("unbound-exclusion"),
    )
    claim = await lifecycle.mark_dispatched(
        action_id=unbound.id,
        worker_instance_id=unbound.worker_instance_id,
        worker_incarnation=unbound.worker_incarnation,
    )
    assert claim.status.value == "CLAIMED"

    before = list(reconciler.queries)
    batch = await controller.run_once(limit=10)

    assert [result.action_id for result in batch.actions] == [selected.id]
    assert reconciler.queries[len(before) :] == [selected.id]
