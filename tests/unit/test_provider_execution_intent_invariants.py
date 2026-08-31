from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text

from tests.unit.test_provider_execution_intents import _request, _rows, _run
from tracefence.db.models import Node, WorkerInstance
from tracefence.domain.errors import ConflictError
from tracefence.security import hash_token
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
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
