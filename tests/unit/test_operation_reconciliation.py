from __future__ import annotations

import asyncio
import threading
from dataclasses import replace

import pytest
from sqlalchemy import select

import tracefence.services.operation_reconciliation as reconciliation_module
from tests.helpers import create_v2_run
from tracefence.db.models import (
    ActionAttempt,
    ActionReconciliationEvidence,
    Node,
    Run,
    WorkerInstance,
)
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal
from tracefence.services.control_service import ControlService
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


def _request(key: str) -> ActionExecute:
    return ActionExecute(tool_name="restart_postgres", arguments={}, idempotency_key=key)


class FakeReconciler:
    def __init__(self, observation: ReconciliationObservation) -> None:
        self.observation = observation
        self.queries = 0
        self.writer_transaction_held = False

    async def reconcile(self, identity) -> ReconciliationObservation:
        self.queries += 1
        assert identity.operation_key.startswith("tfop_")
        assert not self.writer_transaction_held
        return self.observation


class BlockingReconciler(FakeReconciler):
    """Test-only provider fake that exposes the query/apply boundary explicitly."""

    def __init__(self, observation: ReconciliationObservation) -> None:
        super().__init__(observation)
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def reconcile(self, identity) -> ReconciliationObservation:
        self.queries += 1
        assert identity.operation_key.startswith("tfop_")
        assert not self.writer_transaction_held
        self.started.set()
        await self.release.wait()
        return self.observation


def _registry(
    reconciler: FakeReconciler,
    *,
    provider_adapter_id: str = "fake",
    provider_config_ref: str = "cfg-a",
    provider_scope_ref: str = "tenant-a",
    tool_reconciliation_version: str = "1",
    supports_definitive_nonexecution: bool = True,
) -> ReconcilerRegistry:
    contract = ReconcilerContract(
        provider_adapter_id=provider_adapter_id,
        provider_config_ref=provider_config_ref,
        provider_scope_ref=provider_scope_ref,
        tool_reconciliation_version=tool_reconciliation_version,
        capabilities=ReconcilerCapabilities(
            supports_definitive_nonexecution=supports_definitive_nonexecution
        ),
    )
    return ReconcilerRegistry((RegisteredOperationReconciler(contract, reconciler),))


def _install_test_registry(monkeypatch, registry: ReconcilerRegistry) -> None:
    """Privileged test instrumentation for the private server-composition seam."""
    monkeypatch.setattr(reconciliation_module, "_resolve_registered_reconciler", registry.resolve)


async def _reconcile(
    service: OperationReconciliationService,
    reconciler: FakeReconciler,
    action_id: str,
    observation: ReconciliationObservation,
):
    reconciler.observation = observation
    return await service.reconcile_action(action_id=action_id)


async def _bound(
    session_factory,
    monkeypatch,
    key: str,
    *,
    supports_definitive_nonexecution: bool = True,
):
    run = await create_v2_run(session_factory, key)
    lifecycle = OperationLifecycleService(session_factory)
    action = await lifecycle.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request(key)
    )
    fake = FakeReconciler(ReconciliationObservation(ObservationKind.UNCERTAIN))
    _install_test_registry(
        monkeypatch,
        _registry(
            fake,
            supports_definitive_nonexecution=supports_definitive_nonexecution,
        ),
    )
    reconciliation = OperationReconciliationService(session_factory)
    identity = await reconciliation.create_binding(
        action_id=action.id,
        provider_adapter_id="fake",
        provider_config_ref="cfg-a",
        provider_scope_ref="tenant-a",
        tool_reconciliation_version="1",
    )
    await lifecycle.mark_dispatched(
        action_id=action.id,
        worker_instance_id=identity.worker_instance_id,
        worker_incarnation=identity.worker_incarnation,
    )
    return run, action, identity, reconciliation, fake


async def test_binding_is_pre_dispatch_immutable_and_handle_is_write_once(session_factory, monkeypatch):
    run = await create_v2_run(session_factory, "binding")
    lifecycle = OperationLifecycleService(session_factory)
    action = await lifecycle.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request("binding")
    )
    service = OperationReconciliationService(session_factory)
    identity = await service.create_binding(
        action_id=action.id,
        provider_adapter_id="fake",
        provider_config_ref="cfg",
        provider_scope_ref="tenant",
        tool_reconciliation_version="1",
    )
    first = await service.bind_provider_handle(identity=identity, provider_handle="H1")
    with pytest.raises(ConflictError, match="does not match"):
        await service.bind_provider_handle(
            identity=replace(first, provider_scope_ref="other"), provider_handle="H1"
        )
    assert (
        await service.bind_provider_handle(identity=first, provider_handle="H1")
    ).provider_handle == "H1"
    with pytest.raises(ConflictError, match="cannot be overwritten"):
        await service.bind_provider_handle(identity=first, provider_handle="H2")
    with pytest.raises(ConflictError):
        await service.create_binding(
            action_id=action.id,
            provider_adapter_id="other",
            provider_config_ref="cfg",
            provider_scope_ref="tenant",
            tool_reconciliation_version="1",
        )


async def test_reconciled_success_is_accepted_once_when_authority_is_live(session_factory, monkeypatch):
    run, action, identity, service, fake = await _bound(session_factory, monkeypatch, "success")
    observation = ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True})
    first = await _reconcile(service, fake, action.id, observation)
    assert first.accepted and first.action.execution_state == "SUCCEEDED"
    second = await _reconcile(service, fake, action.id, observation)
    assert second.status == "IDEMPOTENT"
    with session_factory() as session:
        assert (
            session.scalar(
                select(ActionReconciliationEvidence).where(
                    ActionReconciliationEvidence.action_id == action.id
                )
            )
            is not None
        )


async def test_reconciled_success_after_scope_change_is_stale_and_preserves_evidence(
    session_factory, monkeypatch,
):
    run, action, identity, service, fake = await _bound(session_factory, monkeypatch, "stale")
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="stale-cancel",
            command_type=CommandType.CANCEL_RUN,
            target_node_id=run.root_node_id,
            reason_code="TEST",
            reason_text="reconciliation ordering",
        ),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="reconciliation-test"),
    )
    result = await _reconcile(
        service,
        fake,
        action.id,
        ReconciliationObservation(ObservationKind.SUCCEEDED, result={"external": "success"}),
    )
    assert not result.accepted and result.action.execution_state == "STALE"
    with session_factory() as session:
        evidence = session.scalar(
            select(ActionReconciliationEvidence).where(
                ActionReconciliationEvidence.action_id == action.id
            )
        )
        assert evidence is not None and evidence.observation_kind == "SUCCEEDED"
        assert session.get(ActionAttempt, action.id).result_json is None


async def test_nonmaterial_observations_are_noop_and_nonexecution_is_terminal_failure(
    session_factory, monkeypatch,
):
    run, action, identity, service, fake = await _bound(session_factory, monkeypatch, "nonmaterial")
    with session_factory() as session:
        before = session.get(Run, run.run_id).proof_revision
    for observation in (
        ReconciliationObservation(ObservationKind.IN_PROGRESS),
        ReconciliationObservation(ObservationKind.UNCERTAIN),
        ReconciliationObservation(
            ObservationKind.NOT_FOUND, not_found_strength=NotFoundStrength.WEAK_NOT_FOUND
        ),
    ):
        result = await _reconcile(service, fake, action.id, observation)
        assert result.action.execution_state == "DISPATCHED" and not result.evidence_recorded
    with session_factory() as session:
        assert session.get(Run, run.run_id).proof_revision == before
    final = await _reconcile(
        service,
        fake,
        action.id,
        ReconciliationObservation(
            ObservationKind.NOT_FOUND,
            not_found_strength=NotFoundStrength.DEFINITIVE_NONEXECUTION,
        ),
    )
    assert final.accepted and final.action.execution_state == "FAILED"


async def test_conflict_transitions_unresolved_action_without_overwriting_terminal_history(
    session_factory, monkeypatch,
):
    run, action, identity, service, fake = await _bound(session_factory, monkeypatch, "conflict")
    conflict = ReconciliationObservation(
        ObservationKind.CONFLICT, result={"provider": "incompatible"}
    )
    first = await _reconcile(service, fake, action.id, conflict)
    assert first.action.execution_state == "AMBIGUOUS"
    assert (await _reconcile(service, fake, action.id, conflict)).status == "IDEMPOTENT"
    accepted = await _reconcile(
        service,
        fake,
        action.id,
        ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True}),
    )
    assert accepted.action.execution_state == "SUCCEEDED"
    later = await _reconcile(
        service,
        fake,
        action.id,
        ReconciliationObservation(ObservationKind.FAILED, result={"error": "provider"}),
    )
    assert later.status == "CONFLICT" and later.action.execution_state == "SUCCEEDED"


def test_observation_shapes_fail_closed():
    with pytest.raises(ValueError):
        ReconciliationObservation(ObservationKind.SUCCEEDED)
    with pytest.raises(ValueError):
        ReconciliationObservation(ObservationKind.IN_PROGRESS, result={"bad": True})
    with pytest.raises(ValueError):
        ReconciliationObservation(ObservationKind.NOT_FOUND)


async def test_reconciliation_proof_facts_are_exact_once(session_factory, monkeypatch):
    run = await create_v2_run(session_factory, "proof-facts")
    lifecycle = OperationLifecycleService(session_factory)
    action = await lifecycle.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request("proof-facts")
    )
    fake = FakeReconciler(ReconciliationObservation(ObservationKind.UNCERTAIN))
    _install_test_registry(
        monkeypatch,
        _registry(
            fake,
            provider_config_ref="cfg",
            provider_scope_ref="tenant",
        ),
    )
    service = OperationReconciliationService(session_factory)
    with session_factory() as session:
        before_binding = session.get(Run, run.run_id).proof_revision
    identity = await service.create_binding(
        action_id=action.id,
        provider_adapter_id="fake",
        provider_config_ref="cfg",
        provider_scope_ref="tenant",
        tool_reconciliation_version="1",
    )
    with session_factory() as session:
        assert session.get(Run, run.run_id).proof_revision == before_binding + 1
    identity = await service.bind_provider_handle(
        identity=identity, provider_handle="provider-handle"
    )
    with session_factory() as session:
        after_handle = session.get(Run, run.run_id).proof_revision
    assert after_handle == before_binding + 2
    identity = await service.bind_provider_handle(
        identity=identity, provider_handle="provider-handle"
    )
    with session_factory() as session:
        assert session.get(Run, run.run_id).proof_revision == after_handle
    with session_factory() as session:
        before_result = session.get(Run, run.run_id).proof_revision
    await lifecycle.mark_dispatched(
        action_id=action.id,
        worker_instance_id=identity.worker_instance_id,
        worker_incarnation=identity.worker_incarnation,
    )
    with session_factory() as session:
        before_result = session.get(Run, run.run_id).proof_revision
    observation = ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True})
    accepted = await _reconcile(service, fake, action.id, observation)
    assert accepted.accepted
    with session_factory() as session:
        after = session.get(Run, run.run_id).proof_revision
    assert after == before_result + 2
    replay = await _reconcile(service, fake, action.id, observation)
    assert replay.status == "IDEMPOTENT"
    with session_factory() as session:
        assert session.get(Run, run.run_id).proof_revision == after


async def test_provider_evidence_pair_is_required_and_identity_is_exact(session_factory, monkeypatch):
    with pytest.raises(ValueError, match="reference and digest"):
        ReconciliationObservation(ObservationKind.IN_PROGRESS, provider_evidence_ref="provider-ref")
    _, action, _, service, _ = await _bound(session_factory, monkeypatch, "identity")
    with pytest.raises(TypeError):
        await service.reconcile_action(action_id=action.id, identity="caller-controlled")


@pytest.mark.parametrize(
    "observation",
    [
        ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True}),
        ReconciliationObservation(ObservationKind.FAILED, result={"error": "known"}),
        ReconciliationObservation(ObservationKind.IN_PROGRESS),
        ReconciliationObservation(
            ObservationKind.NOT_FOUND, not_found_strength=NotFoundStrength.WEAK_NOT_FOUND
        ),
        ReconciliationObservation(
            ObservationKind.NOT_FOUND, not_found_strength=NotFoundStrength.DEFINITIVE_NONEXECUTION
        ),
        ReconciliationObservation(ObservationKind.UNCERTAIN),
        ReconciliationObservation(ObservationKind.CONFLICT, result={"conflict": True}),
    ],
)
async def test_fake_reconciler_queries_before_application(session_factory, monkeypatch, observation):
    _, action, identity, service, fake = await _bound(
        session_factory, monkeypatch, f"fake-{observation.kind}"
    )
    applied = await _reconcile(service, fake, action.id, observation)
    assert fake.queries == 1
    assert not fake.writer_transaction_held
    assert applied.action.id == identity.action_id


async def test_concurrent_identical_material_observations_are_exactly_once(session_factory, monkeypatch):
    _, action, _, service, fake = await _bound(session_factory, monkeypatch, "concurrent")
    fake.observation = ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True})
    barrier = threading.Barrier(2)

    def reconcile_from_independent_thread():
        barrier.wait()
        return asyncio.run(service.reconcile_action(action_id=action.id))

    first, second = await asyncio.gather(
        asyncio.to_thread(reconcile_from_independent_thread),
        asyncio.to_thread(reconcile_from_independent_thread),
    )
    assert sum(application.evidence_recorded for application in (first, second)) == 1
    with session_factory() as session:
        assert session.get(ActionAttempt, action.id).execution_state == "SUCCEEDED"
        assert (
            len(
                session.scalars(
                    select(ActionReconciliationEvidence).where(
                        ActionReconciliationEvidence.action_id == action.id
                    )
                ).all()
            )
            == 1
        )


async def test_reconciled_failure_uses_live_authority_fence(session_factory, monkeypatch):
    _, action, identity, service, fake = await _bound(session_factory, monkeypatch, "failure-live")
    live = await _reconcile(
        service,
        fake,
        action.id,
        ReconciliationObservation(ObservationKind.FAILED, result={"error": "known"}),
    )
    assert live.accepted and live.action.execution_state == "FAILED"
    run, stale_action, stale_identity, stale_service, stale_fake = await _bound(
        session_factory, monkeypatch, "failure-revoked"
    )
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="failure-cancel",
            command_type=CommandType.CANCEL_RUN,
            target_node_id=run.root_node_id,
            reason_code="TEST",
            reason_text="reconciliation ordering",
        ),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="reconciliation-test"),
    )
    stale = await _reconcile(
        stale_service,
        stale_fake,
        stale_action.id,
        ReconciliationObservation(ObservationKind.FAILED, result={"error": "known"}),
    )
    assert not stale.accepted and stale.action.execution_state == "STALE"
    with session_factory() as session:
        evidence = session.scalar(
            select(ActionReconciliationEvidence).where(
                ActionReconciliationEvidence.action_id == stale_action.id
            )
        )
        assert evidence is not None and evidence.observation_kind == "FAILED"


async def test_original_worker_result_stales_after_replacement(session_factory, monkeypatch):
    _, action, identity, service, fake = await _bound(session_factory, monkeypatch, "replacement")
    with session_factory.begin() as session:
        node = session.get(Node, action.node_id)
        old = session.get(WorkerInstance, identity.worker_instance_id)
        assert node is not None and old is not None
        replacement = WorkerInstance(
            id="00000000-0000-0000-0000-000000000025",
            node_id=node.id,
            incarnation=old.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=old.activated_at,
            credential_hash=old.credential_hash,
        )
        session.add(replacement)
        session.flush()
        node.current_worker_instance_id = replacement.id
    stale = await _reconcile(
        service,
        fake,
        action.id,
        ReconciliationObservation(ObservationKind.SUCCEEDED, result={"external": "success"}),
    )
    assert not stale.accepted and stale.action.execution_state == "STALE"
    with session_factory() as session:
        evidence = session.scalar(
            select(ActionReconciliationEvidence).where(
                ActionReconciliationEvidence.action_id == action.id
            )
        )
        assert evidence is not None and evidence.observation_kind == "SUCCEEDED"


@pytest.mark.parametrize(
    "observation",
    [
        ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True}),
        ReconciliationObservation(ObservationKind.FAILED, result={"error": "claimed"}),
        ReconciliationObservation(ObservationKind.CONFLICT, result={"conflict": "claimed"}),
        ReconciliationObservation(
            ObservationKind.NOT_FOUND,
            not_found_strength=NotFoundStrength.DEFINITIVE_NONEXECUTION,
        ),
    ],
)
async def test_raw_material_observations_cannot_mutate_durable_state(session_factory, monkeypatch, observation):
    run, action, identity, service, _ = await _bound(session_factory, monkeypatch, f"raw-{observation.kind}")
    with session_factory() as session:
        before = session.get(Run, run.run_id).proof_revision

    assert not hasattr(service, "apply")
    with pytest.raises(TypeError):
        await service.reconcile_action(action_id=action.id, observation=observation)
    with session_factory() as session:
        assert session.get(ActionAttempt, action.id).execution_state == "DISPATCHED"
        assert session.get(Run, run.run_id).proof_revision == before
        assert (
            session.scalar(
                select(ActionReconciliationEvidence).where(
                    ActionReconciliationEvidence.action_id == action.id
                )
            )
            is None
        )


async def test_unregistered_reconciler_cannot_produce_material_observation(
    session_factory, monkeypatch,
):
    run, action, identity, _, fake = await _bound(session_factory, monkeypatch, "unregistered")
    _install_test_registry(monkeypatch, ReconcilerRegistry())
    service = OperationReconciliationService(session_factory)
    with session_factory() as session:
        before = session.get(Run, run.run_id).proof_revision

    with pytest.raises(ConflictError) as raised:
        await service.reconcile_action(action_id=action.id)

    assert raised.value.code == "RECONCILER_CONTRACT_UNREGISTERED"
    with session_factory() as session:
        assert session.get(ActionAttempt, action.id).execution_state == "DISPATCHED"
        assert session.get(Run, run.run_id).proof_revision == before


@pytest.mark.parametrize(
    ("contract_override", "value"),
    [
        ("provider_adapter_id", "other-adapter"),
        ("provider_config_ref", "other-config"),
        ("provider_scope_ref", "other-scope"),
        ("tool_reconciliation_version", "2"),
    ],
)
async def test_reconciler_contract_must_match_complete_durable_binding(
    session_factory, monkeypatch, contract_override, value
):
    run, action, identity, _, _ = await _bound(session_factory, monkeypatch, f"mismatch-{contract_override}")
    fake = FakeReconciler(ReconciliationObservation(ObservationKind.SUCCEEDED, result={"ok": True}))
    _install_test_registry(monkeypatch, _registry(fake, **{contract_override: value}))
    service = OperationReconciliationService(session_factory)
    with session_factory() as session:
        before = session.get(Run, run.run_id).proof_revision

    with pytest.raises(ConflictError) as raised:
        await service.reconcile_action(action_id=action.id)

    assert raised.value.code == "RECONCILER_CONTRACT_UNREGISTERED"
    assert fake.queries == 0
    with session_factory() as session:
        assert session.get(ActionAttempt, action.id).execution_state == "DISPATCHED"
        assert session.get(Run, run.run_id).proof_revision == before


async def test_incapable_reconciler_cannot_claim_definitive_nonexecution(
    session_factory, monkeypatch,
):
    run, action, identity, service, fake = await _bound(
        session_factory,
        monkeypatch,
        "incapable-nonexecution",
        supports_definitive_nonexecution=False,
    )
    fake.observation = ReconciliationObservation(
        ObservationKind.NOT_FOUND,
        not_found_strength=NotFoundStrength.DEFINITIVE_NONEXECUTION,
    )
    with session_factory() as session:
        before = session.get(Run, run.run_id).proof_revision

    with pytest.raises(ConflictError) as raised:
        await service.reconcile_action(action_id=action.id)

    assert raised.value.code == "INVALID_RECONCILIATION_CAPABILITY"
    assert fake.queries == 1
    with session_factory() as session:
        assert session.get(ActionAttempt, action.id).execution_state == "DISPATCHED"
        assert session.get(Run, run.run_id).proof_revision == before
        assert (
            session.scalar(
                select(ActionReconciliationEvidence).where(
                    ActionReconciliationEvidence.action_id == action.id
                )
            )
            is None
        )


async def test_capable_nonexecution_uses_result_fence_after_revocation(
    session_factory, monkeypatch,
):
    run, action, identity, service, fake = await _bound(
        session_factory, monkeypatch, "capable-revoked-nonexecution"
    )
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="capable-nonexecution-cancel",
            command_type=CommandType.CANCEL_RUN,
            target_node_id=run.root_node_id,
            reason_code="TEST",
            reason_text="trusted nonexecution fence",
        ),
        Principal(
            issuer_type=IssuerType.HUMAN,
            principal_id="reconciliation-test",
        ),
    )

    application = await _reconcile(
        service,
        fake,
        action.id,
        ReconciliationObservation(
            ObservationKind.NOT_FOUND,
            not_found_strength=NotFoundStrength.DEFINITIVE_NONEXECUTION,
        ),
    )

    assert not application.accepted
    assert application.action.execution_state == "STALE"
    with session_factory() as session:
        evidence = session.scalar(
            select(ActionReconciliationEvidence).where(
                ActionReconciliationEvidence.action_id == action.id
            )
        )
        assert evidence is not None
        assert evidence.observation_kind == "NONEXECUTION"


async def test_forged_trusted_wrapper_and_registry_injection_have_no_entrypoint(
    session_factory, monkeypatch
):
    run, action, _, service, fake = await _bound(
        session_factory, monkeypatch, "forged-contract"
    )
    with session_factory() as session:
        before = session.get(Run, run.run_id).proof_revision

    assert not hasattr(reconciliation_module, "TrustedReconciliationObservation")
    assert not hasattr(service, "apply")
    assert not hasattr(service, "apply_trusted_observation")
    permissive_contract = ReconcilerContract(
        provider_adapter_id="fake",
        provider_config_ref="cfg-a",
        provider_scope_ref="tenant-a",
        tool_reconciliation_version="1",
        capabilities=ReconcilerCapabilities(supports_definitive_nonexecution=True),
    )
    permissive_registry = ReconcilerRegistry(
        (RegisteredOperationReconciler(permissive_contract, fake),)
    )
    with pytest.raises(TypeError):
        OperationReconciliationService(session_factory, permissive_registry)
    with pytest.raises(TypeError):
        await service.reconcile_action(
            action_id=action.id,
            contract=permissive_contract,
        )

    with session_factory() as session:
        assert session.get(ActionAttempt, action.id).execution_state == "DISPATCHED"
        assert session.get(Run, run.run_id).proof_revision == before


async def _bound_blocking(session_factory, monkeypatch, key: str):
    run = await create_v2_run(session_factory, key)
    lifecycle = OperationLifecycleService(session_factory)
    action = await lifecycle.reserve(
        node_id=run.root_node_id, credential=run.root_token, request=_request(key)
    )
    fake = BlockingReconciler(
        ReconciliationObservation(ObservationKind.SUCCEEDED, result={"external": "success"})
    )
    _install_test_registry(monkeypatch, _registry(fake))
    service = OperationReconciliationService(session_factory)
    identity = await service.create_binding(
        action_id=action.id,
        provider_adapter_id="fake",
        provider_config_ref="cfg-a",
        provider_scope_ref="tenant-a",
        tool_reconciliation_version="1",
    )
    await lifecycle.mark_dispatched(
        action_id=action.id,
        worker_instance_id=identity.worker_instance_id,
        worker_incarnation=identity.worker_incarnation,
    )
    return run, action, identity, service, fake


async def test_cancellation_during_registered_query_preserves_evidence_as_stale(
    session_factory, monkeypatch
):
    run, action, _, service, fake = await _bound_blocking(
        session_factory, monkeypatch, "query-cancel"
    )
    task = asyncio.create_task(service.reconcile_action(action_id=action.id))
    await fake.started.wait()
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="query-cancel-command",
            command_type=CommandType.CANCEL_RUN,
            target_node_id=run.root_node_id,
            reason_code="TEST",
            reason_text="cancel while reconciler query is in flight",
        ),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="reconciliation-test"),
    )
    fake.release.set()
    applied = await task

    assert fake.queries == 1
    assert not applied.accepted
    assert applied.action.execution_state == "STALE"
    with session_factory() as session:
        assert session.scalar(
            select(ActionReconciliationEvidence).where(
                ActionReconciliationEvidence.action_id == action.id
            )
        ) is not None


async def test_worker_replacement_during_registered_query_stales_only_w1(
    session_factory, monkeypatch
):
    _, action, identity, service, fake = await _bound_blocking(
        session_factory, monkeypatch, "query-replacement"
    )
    task = asyncio.create_task(service.reconcile_action(action_id=action.id))
    await fake.started.wait()
    with session_factory.begin() as session:
        node = session.get(Node, action.node_id)
        old = session.get(WorkerInstance, identity.worker_instance_id)
        assert node is not None and old is not None
        replacement = WorkerInstance(
            id="00000000-0000-0000-0000-000000000026",
            node_id=node.id,
            incarnation=old.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=old.activated_at,
            credential_hash=old.credential_hash,
        )
        session.add(replacement)
        session.flush()
        node.current_worker_instance_id = replacement.id
    fake.release.set()
    applied = await task

    assert fake.queries == 1
    assert not applied.accepted
    assert applied.action.execution_state == "STALE"
    with session_factory() as session:
        replacement = session.get(WorkerInstance, "00000000-0000-0000-0000-000000000026")
        assert replacement is not None
        assert session.get(ActionAttempt, action.id).worker_instance_id != replacement.id


async def test_scope_change_during_registered_query_preserves_evidence_as_stale(
    session_factory, monkeypatch
):
    run, action, _, service, fake = await _bound_blocking(
        session_factory, monkeypatch, "query-scope"
    )
    task = asyncio.create_task(service.reconcile_action(action_id=action.id))
    await fake.started.wait()
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="query-scope-command",
            command_type=CommandType.CANCEL_RUN,
            target_node_id=run.root_node_id,
            reason_code="TEST",
            reason_text="scope changes while reconciler query is in flight",
        ),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="reconciliation-test"),
    )
    fake.release.set()
    applied = await task

    assert fake.queries == 1
    assert not applied.accepted
    assert applied.action.execution_state == "STALE"
