from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from tests.unit.test_provider_execution_intents import _request, _rows, _run
from tracefence.db.models import Node, WorkerInstance
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute
from tracefence.providers.contracts import (
    ProviderDispatchOutcome,
    ProviderDispatchOutcomeKind,
)
from tracefence.security import hash_token
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.provider_execution import (
    ProviderDeliveryClaimStatus,
    ProviderExecutionService,
)

REPETITIONS = range(25)
CASES = (
    "reservation-creates-intent",
    "exact-replay-reuses-intent",
    "payload-mismatch-rejected",
    "trusted-claim-dispatches",
    "concurrent-claims-one-owner",
    "unknown-adapter-fails-closed",
    "retry-metadata-proof-neutral",
    "handle-first-bind",
    "handle-replay-idempotent",
    "handle-conflict-rejected",
    "intent-immutable",
    "intent-no-delete",
    "active-claim-w2-rejected",
    "correlated-handle-rejects-foreign",
)


@pytest.mark.parametrize("iteration", REPETITIONS)
@pytest.mark.parametrize("case", CASES)
async def test_provider_execution_intent_matrix(session_factory, monkeypatch, iteration, case):
    run, provider, registry = await _run(
        session_factory, monkeypatch, f"provider-intent-{case}-{iteration}"
    )
    gateway = ActionGateway(session_factory)
    request = _request(f"{case}-{iteration}")
    _result = await gateway.execute(run.root_node_id, run.root_token, request)
    action, binding, intent, before = _rows(session_factory, run.run_id)
    service = ProviderExecutionService(session_factory, adapter_registry=registry)

    if case == "reservation-creates-intent":
        assert action.execution_state == "AUTHORIZED"
        assert intent.delivery_status == "PENDING"
        assert binding.action_id == action.id
        assert provider.calls == 0
        return

    if case == "exact-replay-reuses-intent":
        replay = await gateway.execute(run.root_node_id, run.root_token, request)
        replay_action, replay_binding, replay_intent, _ = _rows(session_factory, run.run_id)
        assert replay.duplicate is True
        assert (replay.action_id, replay_intent.id, replay_binding.operation_key) == (
            action.id,
            intent.id,
            binding.operation_key,
        )
        assert replay_action.execution_state == "AUTHORIZED"
        return

    if case == "payload-mismatch-rejected":
        with pytest.raises(ConflictError) as error:
            await gateway.execute(
                run.root_node_id,
                run.root_token,
                ActionExecute(
                    idempotency_key=request.idempotency_key,
                    tool_name=request.tool_name,
                    arguments={"unexpected": True},
                ),
            )
        assert error.value.code == "IDEMPOTENCY_PAYLOAD_MISMATCH"
        assert _rows(session_factory, run.run_id)[2].id == intent.id
        return

    if case == "trusted-claim-dispatches":
        claim = await service.claim_delivery(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)
        assert claim.status == ProviderDeliveryClaimStatus.CLAIMED
        assert claim.request is not None
        assert current.execution_state == "DISPATCHED"
        assert current_intent.attempt_count == 1
        assert provider.calls == 0
        return

    if case == "concurrent-claims-one-owner":
        barrier = Barrier(2)

        def claim_once():
            barrier.wait(timeout=5)
            return asyncio.run(
                service.claim_delivery(
                    action_id=action.id,
                    worker_instance_id=action.worker_instance_id or "",
                    worker_incarnation=action.worker_incarnation or 0,
                )
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            first, second = list(executor.map(lambda _ignored: claim_once(), range(2)))
        statuses = {first.status, second.status}
        current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)
        assert statuses == {
            ProviderDeliveryClaimStatus.CLAIMED,
            ProviderDeliveryClaimStatus.ALREADY_CLAIMED,
        }
        assert current.execution_state == "DISPATCHED"
        assert current_intent.attempt_count == 1
        assert provider.calls == 0
        return

    if case == "unknown-adapter-fails-closed":
        with pytest.raises(ConflictError) as error:
            await ProviderExecutionService(session_factory).claim_delivery(
                action_id=action.id,
                worker_instance_id=action.worker_instance_id or "",
                worker_incarnation=action.worker_incarnation or 0,
            )
        assert error.value.code == "PROVIDER_ADAPTER_UNREGISTERED"
        assert _rows(session_factory, run.run_id)[0].execution_state == "AUTHORIZED"
        return

    if case == "retry-metadata-proof-neutral":
        await service.record_delivery_retry_metadata(
            action_id=action.id, error_class="TEST_DELIVERY_ERROR"
        )
        _action, _binding, current_intent, after = _rows(session_factory, run.run_id)
        assert current_intent.id == intent.id
        assert after.proof_revision == before.proof_revision
        return

    if case in {"handle-first-bind", "handle-replay-idempotent", "handle-conflict-rejected"}:
        claim = await service.claim_delivery(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        assert claim.request is not None
        outcome = ProviderDispatchOutcome(
            ProviderDispatchOutcomeKind.ACCEPTED,
            provider_handle=f"handle-{iteration}-{case}",
        )
        first = await service.record_dispatch_outcome(
            claim_token=claim.request.claim_token,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            outcome=outcome,
        )
        if case == "handle-first-bind":
            assert first.provider_handle
            return
        replay = await service.record_dispatch_outcome(
            claim_token=claim.request.claim_token,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            outcome=outcome,
        )
        assert replay == first
        if case == "handle-replay-idempotent":
            return
        with pytest.raises(ConflictError) as error:
            await service.record_dispatch_outcome(
                claim_token=claim.request.claim_token,
                worker_instance_id=action.worker_instance_id or "",
                worker_incarnation=action.worker_incarnation or 0,
                outcome=ProviderDispatchOutcome(
                    ProviderDispatchOutcomeKind.ACCEPTED,
                    provider_handle=f"other-{iteration}",
                ),
            )
        assert error.value.code == "ACTION_PROVIDER_HANDLE_CONFLICT"
        return

    if case == "active-claim-w2-rejected":
        claim = await service.claim_delivery(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        assert claim.request is not None
        _claimed_action, _claimed_binding, claimed_intent, _claimed_proof = _rows(
            session_factory, run.run_id
        )
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
                credential_hash=hash_token(f"provider-active-w2-{iteration}"),
            )
            session.add(w2)
            session.flush()
            node.current_worker_instance_id = w2.id
        _current, _binding, _current_intent, before = _rows(session_factory, run.run_id)
        with pytest.raises(ConflictError) as error:
            await service.claim_delivery(
                action_id=action.id,
                worker_instance_id=w2.id,
                worker_incarnation=w2.incarnation,
            )
        details = f"{error.value!r} {error.value}"
        assert error.value.code == "ACTION_WORKER_OWNER_MISMATCH"
        assert claimed_intent.provider_idempotency_key not in details
        assert claimed_intent.provider_request_digest not in details
        assert claimed_intent.claim_token not in details
        current, _binding, current_intent, after = _rows(session_factory, run.run_id)
        assert current.execution_state == "DISPATCHED"
        assert current_intent.claim_token == claimed_intent.claim_token
        assert after.proof_revision == before.proof_revision
        return

    if case == "correlated-handle-rejects-foreign":
        claim = await service.claim_delivery(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        assert claim.request is not None
        with pytest.raises(ConflictError) as error:
            await service.record_dispatch_outcome(
                claim_token=f"fabricated-{iteration}",
                worker_instance_id=action.worker_instance_id or "",
                worker_incarnation=action.worker_incarnation or 0,
                outcome=ProviderDispatchOutcome(
                    ProviderDispatchOutcomeKind.ACCEPTED,
                    provider_handle=f"evil-{iteration}",
                ),
            )
        assert error.value.code == "PROVIDER_DELIVERY_CLAIM_INVALID"
        _current, binding_after_invalid, _intent, after_invalid = _rows(
            session_factory, run.run_id
        )
        assert binding_after_invalid.provider_handle is None
        identity = await service.record_dispatch_outcome(
            claim_token=claim.request.claim_token,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
            outcome=ProviderDispatchOutcome(
                ProviderDispatchOutcomeKind.ACCEPTED,
                provider_handle=f"trusted-{iteration}",
            ),
        )
        assert identity.provider_handle == f"trusted-{iteration}"
        assert _rows(session_factory, run.run_id)[3].proof_revision > after_invalid.proof_revision
        return

    if case == "intent-immutable":
        with pytest.raises(IntegrityError):
            with session_factory.begin() as session:
                session.execute(
                    text(
                        "UPDATE provider_execution_intents "
                        "SET provider_idempotency_key = 'forbidden' WHERE id = :id"
                    ),
                    {"id": intent.id},
                )
        assert _rows(session_factory, run.run_id)[2].provider_idempotency_key == (
            intent.provider_idempotency_key
        )
        return

    assert case == "intent-no-delete"
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("DELETE FROM provider_execution_intents WHERE id = :id"),
                {"id": intent.id},
            )
    assert _rows(session_factory, run.run_id)[2].id == intent.id
