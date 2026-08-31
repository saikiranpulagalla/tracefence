from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import text

from tests.unit.test_provider_execution_intents import _request, _rows, _run
from tracefence.db.models import WorkerInstance
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import CommandCreate, Principal
from tracefence.security import hash_token
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.provider_execution import (
    ProviderDeliveryClaimStatus,
    ProviderExecutionService,
)

REPETITIONS = range(25)
CASES = (
    "cancel-before-reservation",
    "reservation-before-cancellation",
    "cancellation-before-claim",
    "claim-before-cancellation",
    "w2-claim-rejected",
)


async def _cancel_run(session_factory, run, key: str) -> None:
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key=key,
            command_type=CommandType.CANCEL_RUN,
            target_node_id=run.root_node_id,
            reason_code="TEST",
            reason_text="provider intent ordering",
        ),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="provider-race"),
    )


@pytest.mark.parametrize("iteration", REPETITIONS)
@pytest.mark.parametrize("case", CASES)
async def test_provider_intent_cancellation_and_owner_ordering(
    session_factory, monkeypatch, iteration, case
):
    run, _provider, registry = await _run(
        session_factory, monkeypatch, f"provider-control-{case}-{iteration}"
    )
    gateway = ActionGateway(session_factory)
    request = _request(f"{case}-{iteration}")

    if case == "cancel-before-reservation":
        await _cancel_run(session_factory, run, f"cancel-first-{iteration}")
        result = await gateway.execute(run.root_node_id, run.root_token, request)
        with session_factory() as session:
            intent = session.scalar(
                text("SELECT id FROM provider_execution_intents WHERE run_id = :run_id"),
                {"run_id": run.run_id},
            )
        assert result.decision.value == "DENY"
        assert result.denial_reason == "RUN_NOT_ACTIVE"
        assert intent is None
        return

    await gateway.execute(run.root_node_id, run.root_token, request)
    action, _binding, intent, _proof = _rows(session_factory, run.run_id)
    service = ProviderExecutionService(session_factory, adapter_registry=registry)

    if case == "reservation-before-cancellation":
        await _cancel_run(session_factory, run, f"cancel-after-reserve-{iteration}")
        current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)
        assert current.execution_state == "AUTHORIZED"
        assert current_intent.id == intent.id
        return

    if case == "cancellation-before-claim":
        await _cancel_run(session_factory, run, f"cancel-before-claim-{iteration}")
        claim = await service.claim_delivery(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)
        assert claim.status == ProviderDeliveryClaimStatus.REVOKED
        assert current.execution_state == "STALE"
        assert current_intent.delivery_status == "PENDING"
        return

    if case == "claim-before-cancellation":
        claim = await service.claim_delivery(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
        assert claim.status == ProviderDeliveryClaimStatus.CLAIMED
        await _cancel_run(session_factory, run, f"cancel-after-claim-{iteration}")
        current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)
        assert current.execution_state == "DISPATCHED"
        assert current_intent.id == intent.id
        return

    assert case == "w2-claim-rejected"
    with session_factory.begin() as session:
        worker = session.get(WorkerInstance, action.worker_instance_id)
        assert worker is not None
        replacement = WorkerInstance(
            id=str(uuid4()),
            node_id=worker.node_id,
            incarnation=worker.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=worker.activated_at,
            credential_hash=hash_token(f"provider-w2-{iteration}"),
        )
        session.add(replacement)
        session.flush()
        session.execute(
            text("UPDATE nodes SET current_worker_instance_id = :worker_id WHERE id = :node_id"),
            {"worker_id": replacement.id, "node_id": worker.node_id},
        )
    with pytest.raises(ConflictError):
        await service.claim_delivery(
            action_id=action.id,
            worker_instance_id=replacement.id,
            worker_incarnation=replacement.incarnation,
        )
    current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)
    assert current.execution_state == "AUTHORIZED"
    assert current_intent.id == intent.id
