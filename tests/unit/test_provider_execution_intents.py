from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import select

from tests.helpers import create_v2_run
from tracefence.db.models import (
    ActionAttempt,
    ActionExternalOperationBinding,
    Node,
    ProviderExecutionIntent,
    Run,
)
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute
from tracefence.providers.contracts import ProviderAdapterContract
from tracefence.providers.registry import ProviderAdapterRegistry, RegisteredProviderAdapter
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.provider_execution import (
    ProviderDeliveryClaimStatus,
    ProviderExecutionService,
)
from tracefence.services.tool_registry import TOOL_REGISTRY, ToolSpec

TOOL_NAME = "test_provider_execution_intent"
CAPABILITY = "tool:test_provider_execution_intent"
CONTRACT = ProviderAdapterContract(
    "test-provider",
    "test-config",
    "test-scope",
    "test-reconciliation-v1",
    "test-dispatch-v1",
)


@dataclass
class FakeProvider:
    calls: int = 0

    async def dispatch(self, _request) -> None:
        self.calls += 1


def _request(key: str) -> ActionExecute:
    return ActionExecute(idempotency_key=key, tool_name=TOOL_NAME, arguments={})


async def _run(session_factory, monkeypatch, name: str):
    provider = FakeProvider()
    registry = ProviderAdapterRegistry(
        (RegisteredProviderAdapter(CONTRACT, provider),)
    )
    monkeypatch.setitem(
        TOOL_REGISTRY,
        TOOL_NAME,
        ToolSpec(
            name=TOOL_NAME,
            capability=CAPABILITY,
            side_effecting=True,
            allowed_argument_keys=frozenset(),
            resources=frozenset({"test-provider"}),
            execution_mode="provider_external",
            provider_contract=CONTRACT,
        ),
    )
    run = await create_v2_run(session_factory, name)
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        node.capabilities_json = [*(node.capabilities_json or []), CAPABILITY]
    return run, provider, registry


def _rows(session_factory, run_id: str):
    with session_factory() as session:
        action = session.scalar(
            select(ActionAttempt).where(ActionAttempt.run_id == run_id)
        )
        binding = session.scalar(
            select(ActionExternalOperationBinding).where(
                ActionExternalOperationBinding.run_id == run_id
            )
        )
        intent = session.scalar(
            select(ProviderExecutionIntent).where(ProviderExecutionIntent.run_id == run_id)
        )
        run = session.get(Run, run_id)
        assert action is not None and binding is not None and intent is not None
        assert run is not None
        return action, binding, intent, run


async def test_gateway_atomically_persists_one_provider_intent(
    session_factory, monkeypatch
):
    run, provider, _registry = await _run(session_factory, monkeypatch, "provider-intent")
    gateway = ActionGateway(session_factory)

    result = await gateway.execute(run.root_node_id, run.root_token, _request("intent"))
    action, binding, intent, _proof = _rows(session_factory, run.run_id)

    assert result.action_id == action.id
    assert action.execution_state == "AUTHORIZED"
    assert binding.action_id == action.id
    assert intent.action_id == action.id
    assert intent.provider_idempotency_key.startswith("tf3a_")
    assert intent.delivery_status == "PENDING"
    assert intent.provider_request_digest
    assert provider.calls == 0

    replay = await gateway.execute(run.root_node_id, run.root_token, _request("intent"))
    replay_action, replay_binding, replay_intent, _ = _rows(session_factory, run.run_id)
    assert replay.duplicate is True
    assert replay.action_id == action.id
    assert (replay_action.id, replay_binding.operation_key, replay_intent.id) == (
        action.id,
        binding.operation_key,
        intent.id,
    )


async def test_provider_delivery_claim_is_atomic_and_never_calls_adapter(
    session_factory, monkeypatch
):
    run, provider, registry = await _run(session_factory, monkeypatch, "provider-claim")
    action_result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("claim")
    )
    action, _binding, intent, _proof = _rows(session_factory, run.run_id)
    assert action.id == action_result.action_id

    service = ProviderExecutionService(session_factory, adapter_registry=registry)
    claim = await service.claim_delivery(
        action_id=action.id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    duplicate = await service.claim_delivery(
        action_id=action.id,
        worker_instance_id=action.worker_instance_id or "",
        worker_incarnation=action.worker_incarnation or 0,
    )
    current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)

    assert claim.status == ProviderDeliveryClaimStatus.CLAIMED
    assert claim.request is not None
    assert duplicate.status == ProviderDeliveryClaimStatus.ALREADY_CLAIMED
    assert current.execution_state == "DISPATCHED"
    assert current_intent.id == intent.id
    assert current_intent.attempt_count == 1
    assert provider.calls == 0


async def test_unknown_provider_adapter_fails_closed_before_delivery(
    session_factory, monkeypatch
):
    run, provider, _registry = await _run(session_factory, monkeypatch, "provider-unknown")
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("unknown")
    )
    action, _binding, intent, _proof = _rows(session_factory, run.run_id)

    with pytest.raises(ConflictError) as error:
        await ProviderExecutionService(session_factory).claim_delivery(
            action_id=result.action_id,
            worker_instance_id=action.worker_instance_id or "",
            worker_incarnation=action.worker_incarnation or 0,
        )
    current, _binding, current_intent, _proof = _rows(session_factory, run.run_id)
    assert error.value.code == "PROVIDER_ADAPTER_UNREGISTERED"
    assert current.execution_state == "AUTHORIZED"
    assert current_intent.id == intent.id
    assert provider.calls == 0


async def test_intent_operational_retry_metadata_does_not_change_proof_revision(
    session_factory, monkeypatch
):
    run, _provider, registry = await _run(session_factory, monkeypatch, "provider-proof")
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("proof")
    )
    _action, _binding, intent, before = _rows(session_factory, run.run_id)

    await ProviderExecutionService(
        session_factory, adapter_registry=registry
    ).record_delivery_retry_metadata(
        action_id=result.action_id, error_class="TEST_DELIVERY_ERROR"
    )
    _action, _binding, after_intent, after = _rows(session_factory, run.run_id)
    assert after_intent.id == intent.id
    assert after_intent.last_error_class == "TEST_DELIVERY_ERROR"
    assert after.proof_revision == before.proof_revision

