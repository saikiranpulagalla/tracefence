from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

import tracefence.services.operation_reconciliation as reconciliation_module
from tests.helpers import create_v2_run
from tracefence.db.models import ActionAttempt, ActionRecoveryLink, Node
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute
from tracefence.services.operation_lifecycle import DispatchClaimStatus, OperationLifecycleService
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
from tracefence.services.tool_registry import TOOL_REGISTRY, ToolSpec

TOOL = "test_explicit_recovery"
CAPABILITY = "tool:test_explicit_recovery"


@dataclass
class Counts:
    provider_queries: int = 0
    executor_calls: int = 0


class Reconciler:
    def __init__(self, counts: Counts, observation: ReconciliationObservation) -> None:
        self.counts = counts
        self.observation = observation

    async def reconcile(self, _identity):
        self.counts.provider_queries += 1
        return self.observation


def _request(key: str) -> ActionExecute:
    return ActionExecute(idempotency_key=key, tool_name=TOOL, arguments={})


def _install_tool(monkeypatch, counts: Counts) -> None:
    async def executor(_context, _arguments):
        counts.executor_calls += 1
        return {"unexpected": True}

    monkeypatch.setitem(
        TOOL_REGISTRY,
        TOOL,
        ToolSpec(
            name=TOOL,
            capability=CAPABILITY,
            side_effecting=True,
            allowed_argument_keys=frozenset(),
            resources=frozenset({"test"}),
            execution_mode="cooperative",
            cooperative_executor=executor,
            explicit_recovery_policy_version="test-v1",
        ),
    )


def _install_reconciler(monkeypatch, reconciler: Reconciler) -> None:
    registry = ReconcilerRegistry(
        (
            RegisteredOperationReconciler(
                ReconcilerContract(
                    provider_adapter_id="test",
                    provider_config_ref="cfg",
                    provider_scope_ref="scope",
                    tool_reconciliation_version="test-v1",
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


async def _source(session_factory, monkeypatch, key: str):
    counts = Counts()
    _install_tool(monkeypatch, counts)
    run = await create_v2_run(session_factory, key)
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        node.capabilities_json = [*(node.capabilities_json or []), CAPABILITY]

    lifecycle = OperationLifecycleService(session_factory)
    action = await lifecycle.reserve(
        node_id=run.root_node_id,
        credential=run.root_token,
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
        action_id=action.id,
        provider_adapter_id="test",
        provider_config_ref="cfg",
        provider_scope_ref="scope",
        tool_reconciliation_version="test-v1",
    )
    claim = await lifecycle.mark_dispatched(
        action_id=action.id,
        worker_instance_id=identity.worker_instance_id,
        worker_incarnation=identity.worker_incarnation,
    )
    assert claim.status == DispatchClaimStatus.CLAIMED
    applied = await reconciliation.reconcile_action(action_id=action.id)
    assert applied.accepted and applied.action.execution_state == "FAILED"
    return run, action, reconciliation, reconciler, counts


async def test_explicit_recovery_creates_atomic_immutable_successor_and_replays(
    session_factory, monkeypatch
):
    run, source, _reconciliation, reconciler, counts = await _source(
        session_factory, monkeypatch, "recovery-create"
    )
    service = OperationRecoveryService(session_factory)
    created = await service.create_recovery(
        source_action_id=source.id,
        node_id=run.root_node_id,
        node_token=run.root_token,
        request=_request("client-request"),
        recovery_request_identity="recovery-r1",
    )
    assert created.status == RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_CREATED
    assert created.action.id != source.id
    assert created.action.execution_state == "AUTHORIZED"
    assert counts.executor_calls == 0
    assert reconciler.counts.provider_queries == 1

    replay = await service.create_recovery(
        source_action_id=source.id,
        node_id=run.root_node_id,
        node_token=run.root_token,
        request=_request("client-request"),
        recovery_request_identity="recovery-r1",
    )
    assert replay.status == RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_REPLAY
    assert replay.action.id == created.action.id
    with session_factory() as session:
        links = session.scalars(
            select(ActionRecoveryLink).where(
                ActionRecoveryLink.source_action_id == source.id
            )
        ).all()
        assert len(links) == 1
        with pytest.raises(IntegrityError):
            session.execute(
                ActionRecoveryLink.__table__.delete().where(
                    ActionRecoveryLink.source_action_id == source.id
                )
            )


async def test_denied_recovery_is_unlinked_and_new_request_can_authorize(
    session_factory, monkeypatch
):
    run, source, _reconciliation, _reconciler, _counts = await _source(
        session_factory, monkeypatch, "recovery-denied"
    )
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        node.capabilities_json = []

    service = OperationRecoveryService(session_factory)
    denied = await service.create_recovery(
        source_action_id=source.id,
        node_id=run.root_node_id,
        node_token=run.root_token,
        request=_request("denied"),
        recovery_request_identity="denied-r1",
    )
    assert denied.status == RecoveryCreationStatus.CANONICAL_DENIED
    assert denied.action.execution_state == "DENIED"
    replay = await service.create_recovery(
        source_action_id=source.id,
        node_id=run.root_node_id,
        node_token=run.root_token,
        request=_request("denied"),
        recovery_request_identity="denied-r1",
    )
    assert replay.status == RecoveryCreationStatus.CANONICAL_DENIED
    assert replay.action.id == denied.action.id
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        node.capabilities_json = [CAPABILITY]

    authorized = await service.create_recovery(
        source_action_id=source.id,
        node_id=run.root_node_id,
        node_token=run.root_token,
        request=_request("authorized"),
        recovery_request_identity="authorized-r2",
    )
    assert authorized.status == RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_CREATED
    with session_factory() as session:
        assert session.scalar(
            select(ActionRecoveryLink).where(
                ActionRecoveryLink.source_action_id == source.id
            )
        ) is not None


async def test_conflicting_source_evidence_blocks_recovery_dispatch(
    session_factory, monkeypatch
):
    run, source, reconciliation, reconciler, counts = await _source(
        session_factory, monkeypatch, "recovery-conflict"
    )
    service = OperationRecoveryService(session_factory)
    created = await service.create_recovery(
        source_action_id=source.id,
        node_id=run.root_node_id,
        node_token=run.root_token,
        request=_request("request"),
        recovery_request_identity="r1",
    )
    reconciler.observation = ReconciliationObservation(
        ObservationKind.CONFLICT,
        result={"provider": "incompatible"},
    )
    await reconciliation.reconcile_action(action_id=source.id)
    claim = await OperationLifecycleService(session_factory).mark_dispatched(
        action_id=created.action.id,
        worker_instance_id=created.action.worker_instance_id or "",
        worker_incarnation=created.action.worker_incarnation or 0,
    )
    assert claim.status == DispatchClaimStatus.REVOKED
    assert claim.action.execution_state == "STALE"
    assert counts.executor_calls == 0


async def test_changed_payload_and_owner_cannot_adopt_a_linked_successor(
    session_factory, monkeypatch
):
    run, source, _reconciliation, _reconciler, _counts = await _source(
        session_factory, monkeypatch, "recovery-mismatch"
    )
    service = OperationRecoveryService(session_factory)
    await service.create_recovery(
        source_action_id=source.id,
        node_id=run.root_node_id,
        node_token=run.root_token,
        request=_request("request"),
        recovery_request_identity="r1",
    )
    with pytest.raises(ConflictError, match="changes the protected effect"):
        await service.create_recovery(
            source_action_id=source.id,
            node_id=run.root_node_id,
            node_token=run.root_token,
            request=ActionExecute(
                idempotency_key="changed",
                tool_name=TOOL,
                arguments={"changed": True},
            ),
            recovery_request_identity="r1",
        )


async def test_reservation_helper_is_transaction_composable(session_factory, monkeypatch):
    counts = Counts()
    _install_tool(monkeypatch, counts)
    run = await create_v2_run(session_factory, "recovery-seam")
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        node.capabilities_json = [*(node.capabilities_json or []), CAPABILITY]

    from tracefence.services.action_gateway import ActionGateway

    gateway = ActionGateway(session_factory)
    with session_factory() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        reservation = await gateway._reserve_in_session(
            session,
            node_id=run.root_node_id,
            node_token=run.root_token,
            request=_request("seam-request"),
        )
        assert reservation.action.execution_state == "AUTHORIZED"
        assert counts.executor_calls == 0
        session.rollback()
    with session_factory() as session:
        assert session.scalar(
            select(ActionAttempt).where(ActionAttempt.node_id == run.root_node_id)
        ) is None
