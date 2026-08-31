from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text

import tracefence.services.provider_execution as provider_execution_module
from tests.unit.test_provider_execution_intents import _request, _rows, _run
from tracefence.db.models import (
    ActionAttempt,
    Node,
    ProviderExecutionIntent,
    WorkerInstance,
)
from tracefence.domain.errors import ConflictError
from tracefence.providers.contracts import (
    ProviderDispatchOutcome,
    ProviderDispatchOutcomeKind,
)
from tracefence.security import hash_token
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
from tracefence.services.operation_reconciliation import OperationReconciliationService
from tracefence.services.provider_execution import (
    ProviderDeliveryClaimStatus,
    ProviderExecutionService,
)


async def test_w2_cannot_replay_w1_provider_intent(session_factory, monkeypatch):
    run, _provider, _registry = await _run(session_factory, monkeypatch, "provider-w2")
    gateway = ActionGateway(session_factory)
    request = _request("w1-intent")
    await gateway.execute(run.root_node_id, run.root_token, request)
    action, _binding, intent, _proof = _rows(session_factory, run.run_id)

    w2_token = "provider-w2-token"
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None and node.current_worker_instance_id is not None
        w1 = session.get(WorkerInstance, node.current_worker_instance_id)
        assert w1 is not None
        w2 = WorkerInstance(
            id=str(uuid4()),
            node_id=node.id,
            incarnation=w1.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=w1.activated_at,
            credential_hash=hash_token(w2_token),
        )
        session.add(w2)
        session.flush()
        node.current_worker_instance_id = w2.id

    with pytest.raises(ConflictError) as error:
        await gateway.execute(run.root_node_id, w2_token, request)
    assert error.value.code == "IDEMPOTENCY_OWNER_MISMATCH"
    assert _rows(session_factory, run.run_id)[2].id == intent.id
    assert _rows(session_factory, run.run_id)[0].id == action.id


async def test_provider_idempotency_tokens_are_unique_per_action(
    session_factory, monkeypatch
):
    first, _provider, _registry = await _run(session_factory, monkeypatch, "provider-token-1")
    second, _provider, _registry = await _run(session_factory, monkeypatch, "provider-token-2")
    gateway = ActionGateway(session_factory)
    await gateway.execute(first.root_node_id, first.root_token, _request("token-1"))
    await gateway.execute(second.root_node_id, second.root_token, _request("token-2"))

    first_intent = _rows(session_factory, first.run_id)[2]
    second_intent = _rows(session_factory, second.run_id)[2]
    assert first_intent.provider_idempotency_key.startswith("tf3a_")
    assert second_intent.provider_idempotency_key.startswith("tf3a_")
    assert first_intent.provider_idempotency_key != second_intent.provider_idempotency_key


async def test_expired_claim_never_reauthorizes_or_rekeys_provider_action(
    session_factory, monkeypatch
):
    run, _provider, registry = await _run(session_factory, monkeypatch, "provider-expired")
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("expired")
    )
    action, _binding, intent, _proof = _rows(session_factory, run.run_id)
    service = ProviderExecutionService(session_factory, adapter_registry=registry)
    claimed = await service.claim_delivery(
        action_id=result.action_id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    assert claimed.status == ProviderDeliveryClaimStatus.CLAIMED

    with session_factory.begin() as session:
        session.execute(
            text(
                "UPDATE provider_execution_intents SET claim_expires_at = :expired "
                "WHERE id = :intent_id"
            ),
            {"expired": utcnow() - timedelta(seconds=1), "intent_id": intent.id},
        )

    duplicate = await service.claim_delivery(
        action_id=result.action_id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)
    assert duplicate.status == ProviderDeliveryClaimStatus.ALREADY_DISPATCHED
    assert current.execution_state == "DISPATCHED"
    assert current_intent.provider_idempotency_key == intent.provider_idempotency_key


async def test_active_claim_replay_rejects_w2_without_intent_disclosure(
    session_factory, monkeypatch
):
    run, _provider, registry = await _run(session_factory, monkeypatch, "provider-active-w2")
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("active-w2")
    )
    action, _binding, intent, _proof = _rows(session_factory, run.run_id)
    service = ProviderExecutionService(session_factory, adapter_registry=registry)
    first = await service.claim_delivery(
        action_id=result.action_id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    assert first.request is not None
    replay = await service.claim_delivery(
        action_id=result.action_id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    assert replay.status == ProviderDeliveryClaimStatus.ALREADY_CLAIMED
    assert replay.intent is not None
    assert replay.intent.provider_idempotency_key == intent.provider_idempotency_key

    with session_factory.begin() as session:
        node = session.get(Node, action.node_id)
        w1 = session.get(WorkerInstance, action.worker_instance_id)
        assert node is not None and w1 is not None
        w2 = WorkerInstance(
            id=str(uuid4()),
            node_id=w1.node_id,
            incarnation=w1.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=w1.activated_at,
            credential_hash=hash_token("provider-active-w2-token"),
        )
        session.add(w2)
        session.flush()
        node.current_worker_instance_id = w2.id
    _current, _binding, before_intent, before = _rows(session_factory, run.run_id)

    with pytest.raises(ConflictError) as error:
        await service.claim_delivery(
            action_id=result.action_id,
            worker_instance_id=w2.id,
            worker_incarnation=w2.incarnation,
        )
    with pytest.raises(ConflictError) as capability_error:
        await service.record_dispatch_outcome(
            claim_token=first.request.claim_token,
            worker_instance_id=w2.id,
            worker_incarnation=w2.incarnation,
            outcome=ProviderDispatchOutcome(
                ProviderDispatchOutcomeKind.ACCEPTED, provider_handle="w2-forbidden"
            ),
        )
    details = f"{error.value!r} {error.value} {capability_error.value!r} {capability_error.value}"
    assert error.value.code == "ACTION_WORKER_OWNER_MISMATCH"
    assert capability_error.value.code == "ACTION_WORKER_OWNER_MISMATCH"
    assert before_intent.provider_idempotency_key not in details
    assert before_intent.provider_request_digest not in details
    assert before_intent.claim_token not in details
    current, _binding, after_intent, after = _rows(session_factory, run.run_id)
    assert current.execution_state == "DISPATCHED"
    assert _binding.provider_handle is None
    assert after_intent.claim_token == before_intent.claim_token
    assert after.proof_revision == before.proof_revision


async def test_dispatch_outcome_requires_exact_claim_correlation_and_owner(
    session_factory, monkeypatch
):
    run, _provider, registry = await _run(session_factory, monkeypatch, "provider-outcome")
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("outcome")
    )
    action, _binding, _intent, _proof = _rows(session_factory, run.run_id)
    service = ProviderExecutionService(session_factory, adapter_registry=registry)
    claim = await service.claim_delivery(
        action_id=result.action_id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    assert claim.request is not None
    accepted_h1 = ProviderDispatchOutcome(
        ProviderDispatchOutcomeKind.ACCEPTED, provider_handle="trusted-h1"
    )
    before_invalid = _rows(session_factory, run.run_id)[3]

    with pytest.raises(ConflictError) as fabricated:
        await service.record_dispatch_outcome(
            claim_token="fabricated-correlation",
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            outcome=accepted_h1,
        )
    assert fabricated.value.code == "PROVIDER_DELIVERY_CLAIM_INVALID"
    _after_invalid_action, after_invalid_binding, _after_invalid_intent, after_invalid = _rows(
        session_factory, run.run_id
    )
    assert after_invalid_binding.provider_handle is None
    assert after_invalid.proof_revision == before_invalid.proof_revision

    first = await service.record_dispatch_outcome(
        claim_token=claim.request.claim_token,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
        outcome=accepted_h1,
    )
    after_first = _rows(session_factory, run.run_id)[3]
    replay = await service.record_dispatch_outcome(
        claim_token=claim.request.claim_token,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
        outcome=accepted_h1,
    )
    assert first == replay
    before = _rows(session_factory, run.run_id)[3]
    assert before.proof_revision == after_first.proof_revision
    with pytest.raises(ConflictError) as conflict:
        await service.record_dispatch_outcome(
            claim_token=claim.request.claim_token,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            outcome=ProviderDispatchOutcome(
                ProviderDispatchOutcomeKind.ACCEPTED, provider_handle="trusted-h2"
            ),
        )
    assert conflict.value.code == "ACTION_PROVIDER_HANDLE_CONFLICT"
    assert _rows(session_factory, run.run_id)[1].provider_handle == "trusted-h1"
    assert _rows(session_factory, run.run_id)[3].proof_revision == before.proof_revision

    other, _provider, _registry = await _run(
        session_factory, monkeypatch, "provider-outcome-other"
    )
    other_result = await ActionGateway(session_factory).execute(
        other.root_node_id, other.root_token, _request("outcome-other")
    )
    other_action, other_binding, _other_intent, _other_proof = _rows(
        session_factory, other.run_id
    )
    other_claim = await service.claim_delivery(
        action_id=other_result.action_id,
        worker_instance_id=other_action.worker_instance_id or "",
        worker_incarnation=other_action.worker_incarnation or 0,
    )
    assert other_claim.request is not None
    with pytest.raises(ConflictError) as cross_action:
        await service.record_dispatch_outcome(
            claim_token=claim.request.claim_token,
            worker_instance_id=other_action.worker_instance_id or "",
            worker_incarnation=other_action.worker_incarnation or 0,
            outcome=ProviderDispatchOutcome(
                ProviderDispatchOutcomeKind.ACCEPTED, provider_handle="wrong-action"
            ),
        )
    assert cross_action.value.code == "ACTION_WORKER_OWNER_MISMATCH"
    assert other_binding.provider_handle is None


async def test_provider_reservation_rollback_leaves_no_partial_intent(
    session_factory, monkeypatch
):
    run, _provider, _registry = await _run(session_factory, monkeypatch, "provider-reservation-rollback")
    original = ProviderExecutionService.create_intent_in_session

    def fail_after_intent(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("test reservation rollback")

    monkeypatch.setattr(
        ProviderExecutionService, "create_intent_in_session", fail_after_intent
    )
    with pytest.raises(RuntimeError, match="reservation rollback"):
        await ActionGateway(session_factory).execute(
            run.root_node_id, run.root_token, _request("rollback")
        )
    with session_factory() as session:
        assert session.scalars(
            select(ActionAttempt).where(ActionAttempt.run_id == run.run_id)
        ).all() == []
        assert session.scalars(
            select(ProviderExecutionIntent).where(
                ProviderExecutionIntent.run_id == run.run_id
            )
        ).all() == []


async def test_provider_handle_outcome_rollback_preserves_unbound_state(
    session_factory, monkeypatch
):
    run, _provider, registry = await _run(session_factory, monkeypatch, "provider-handle-rollback")
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("handle-rollback")
    )
    action, _binding, _intent, _proof = _rows(session_factory, run.run_id)
    claim = await ProviderExecutionService(
        session_factory, adapter_registry=registry
    ).claim_delivery(
        action_id=result.action_id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    assert claim.request is not None

    def fail_identity(*_args, **_kwargs):
        raise RuntimeError("test handle rollback")

    monkeypatch.setattr(
        OperationReconciliationService, "_identity", staticmethod(fail_identity)
    )
    with pytest.raises(RuntimeError, match="handle rollback"):
        await ProviderExecutionService(
            session_factory, adapter_registry=registry
        ).record_dispatch_outcome(
            claim_token=claim.request.claim_token,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            outcome=ProviderDispatchOutcome(
                ProviderDispatchOutcomeKind.ACCEPTED, provider_handle="rollback-handle"
            ),
        )
    current, binding, _intent, _proof = _rows(session_factory, run.run_id)
    assert current.execution_state == "DISPATCHED"
    assert binding.provider_handle is None


async def test_operational_metadata_rollback_preserves_provider_identity(
    session_factory, monkeypatch
):
    run, _provider, registry = await _run(session_factory, monkeypatch, "provider-metadata-rollback")
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("metadata-rollback")
    )
    action, _binding, intent, before = _rows(session_factory, run.run_id)

    def fail_clock():
        raise RuntimeError("test metadata rollback")

    monkeypatch.setattr(provider_execution_module, "utcnow", fail_clock)
    with pytest.raises(RuntimeError, match="metadata rollback"):
        await ProviderExecutionService(
            session_factory, adapter_registry=registry
        ).record_delivery_retry_metadata(
            action_id=result.action_id, error_class="TEST_METADATA_ERROR"
        )
    current, _binding, after_intent, after = _rows(session_factory, run.run_id)
    assert current.execution_state == "AUTHORIZED"
    assert after_intent.provider_idempotency_key == intent.provider_idempotency_key
    assert after_intent.last_error_class is None
    assert after.proof_revision == before.proof_revision
