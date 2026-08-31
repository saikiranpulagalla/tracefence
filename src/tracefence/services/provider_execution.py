"""Durable, provider-neutral execution-intent persistence and delivery claims.

This service creates and claims requests only. It never invokes a provider,
opens a controller loop, or treats a delivery retry as evidence of
nonexecution.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from tracefence.db.models import (
    ActionAttempt,
    ActionExternalOperationBinding,
    ProviderExecutionIntent,
)
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.providers.contracts import (
    ProviderAdapterContract,
    ProviderDispatchOutcome,
    ProviderDispatchOutcomeKind,
    ProviderDispatchRequest,
)
from tracefence.providers.registry import (
    PRODUCTION_PROVIDER_ADAPTER_REGISTRY,
    ProviderAdapterRegistry,
)
from tracefence.security import payload_digest
from tracefence.services.common import utcnow
from tracefence.services.operation_lifecycle import (
    DispatchClaimStatus,
    OperationAuthorityStatus,
    OperationLifecycleService,
    evaluate_live_bound_action_authority,
    evaluate_recovery_dispatch_basis,
)
from tracefence.services.operation_reconciliation import (
    OperationReconciliationService,
    ReconciliationIdentity,
)


class ProviderDeliveryClaimStatus(StrEnum):
    CLAIMED = "CLAIMED"
    ALREADY_CLAIMED = "ALREADY_CLAIMED"
    ALREADY_DISPATCHED = "ALREADY_DISPATCHED"
    REVOKED = "REVOKED"
    UNCERTAIN = "UNCERTAIN"
    TERMINAL = "TERMINAL"


@dataclass(frozen=True, slots=True)
class ProviderDeliveryClaim:
    action: ActionAttempt
    intent: ProviderExecutionIntent | None
    status: ProviderDeliveryClaimStatus
    request: ProviderDispatchRequest | None = None


class ProviderExecutionService:
    """Compose durable provider intent work with existing lifecycle fences."""

    def __init__(
        self,
        session_factory: sessionmaker,
        *,
        adapter_registry: ProviderAdapterRegistry = PRODUCTION_PROVIDER_ADAPTER_REGISTRY,
    ) -> None:
        self.session_factory = session_factory
        self.adapter_registry = adapter_registry

    @staticmethod
    def create_intent_in_session(
        session: Session,
        *,
        action: ActionAttempt,
        contract: ProviderAdapterContract,
    ) -> ProviderExecutionIntent:
        """Create one immutable binding and intent in the caller-owned writer TX."""
        if action.lifecycle_version != 1 or action.execution_state != "AUTHORIZED":
            raise ConflictError(
                "Provider execution intent requires an authorized lifecycle action",
                code="PROVIDER_EXECUTION_INTENT_STATE_INVALID",
            )
        binding = session.get(ActionExternalOperationBinding, action.id)
        identity = (
            contract.provider_adapter_id,
            contract.provider_config_ref,
            contract.provider_scope_ref,
            contract.reconciliation_version,
        )
        if binding is None:
            binding = ActionExternalOperationBinding(
                run_id=action.run_id,
                action_id=action.id,
                provider_adapter_id=identity[0],
                provider_config_ref=identity[1],
                provider_scope_ref=identity[2],
                tool_reconciliation_version=identity[3],
                operation_key=f"tfop_{uuid4().hex}",
                created_at=utcnow(),
            )
            session.add(binding)
        elif (
            binding.provider_adapter_id,
            binding.provider_config_ref,
            binding.provider_scope_ref,
            binding.tool_reconciliation_version,
        ) != identity:
            raise ConflictError(
                "Provider execution binding does not match the server tool contract",
                code="PROVIDER_EXECUTION_BINDING_MISMATCH",
            )

        intent = session.scalar(
            select(ProviderExecutionIntent).where(
                ProviderExecutionIntent.run_id == action.run_id,
                ProviderExecutionIntent.action_id == action.id,
        )
            )
        envelope = ProviderExecutionService._request_envelope(action, binding, contract)
        digest = payload_digest(envelope)
        if intent is None:
            intent = ProviderExecutionIntent(
                id=str(uuid4()),
                run_id=action.run_id,
                action_id=action.id,
                provider_idempotency_key=f"tf3a_{uuid4().hex}",
                provider_dispatch_contract_version=contract.dispatch_contract_version,
                provider_request_json=envelope,
                provider_request_digest=digest,
                delivery_status="PENDING",
                attempt_count=0,
                observation_attempt_count=0,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            session.add(intent)
            return intent
        if (
            intent.provider_dispatch_contract_version,
            intent.provider_request_digest,
        ) != (contract.dispatch_contract_version, digest):
            raise ConflictError(
                "Provider execution intent does not match the server tool contract",
                code="PROVIDER_EXECUTION_INTENT_MISMATCH",
            )
        return intent

    async def claim_delivery(
        self,
        *,
        action_id: str,
        worker_instance_id: str,
        worker_incarnation: int,
        claim_ttl_seconds: int = 60,
    ) -> ProviderDeliveryClaim:
        if claim_ttl_seconds <= 0:
            raise ValueError("claim_ttl_seconds must be positive")
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action = session.get(ActionAttempt, action_id)
                if action is None:
                    raise NotFoundError(f"Action attempt {action_id} was not found")
                lifecycle = OperationLifecycleService(self.session_factory)
                lifecycle._require_owner(
                    action, worker_instance_id, worker_incarnation
                )
                authority = await evaluate_live_bound_action_authority(session, action)
                if authority.status == OperationAuthorityStatus.ALLOWED:
                    authority = evaluate_recovery_dispatch_basis(session, action)
                if authority.status != OperationAuthorityStatus.ALLOWED:
                    if action.execution_state == "AUTHORIZED":
                        claim = await lifecycle._claim_dispatch_in_session(
                            session,
                            action_id=action_id,
                            worker_instance_id=worker_instance_id,
                            worker_incarnation=worker_incarnation,
                        )
                        session.commit()
                        return ProviderDeliveryClaim(
                            claim.action,
                            None,
                            ProviderDeliveryClaimStatus(claim.status.value),
                        )
                    session.commit()
                    status = (
                        ProviderDeliveryClaimStatus.REVOKED
                        if authority.status == OperationAuthorityStatus.REVOKED
                        else ProviderDeliveryClaimStatus.UNCERTAIN
                    )
                    return ProviderDeliveryClaim(action, None, status)
                intent = self._intent_for_action(session, action_id)
                binding = session.get(ActionExternalOperationBinding, action_id)
                if intent is None or binding is None:
                    raise ConflictError(
                        "Action has no provider execution intent",
                        code="PROVIDER_EXECUTION_INTENT_MISSING",
                    )
                contract = ProviderAdapterContract(
                    binding.provider_adapter_id,
                    binding.provider_config_ref,
                    binding.provider_scope_ref,
                    binding.tool_reconciliation_version,
                    intent.provider_dispatch_contract_version,
                )
                if self.adapter_registry.resolve(contract) is None:
                    raise ConflictError(
                        "No trusted provider adapter matches the execution intent",
                        code="PROVIDER_ADAPTER_UNREGISTERED",
                    )
                now = utcnow()
                if (
                    intent.delivery_status == "CLAIMED"
                    and intent.claim_expires_at is not None
                    and intent.claim_expires_at > now
                ):
                    session.commit()
                    return ProviderDeliveryClaim(
                        action, intent, ProviderDeliveryClaimStatus.ALREADY_CLAIMED
                    )
                if action.execution_state == "DISPATCHED":
                    # A later delivery policy must explicitly decide whether a
                    # provider contract supports a safe retry. This foundation
                    # never turns duplicate claim requests into redispatch.
                    session.commit()
                    return ProviderDeliveryClaim(
                        action, intent, ProviderDeliveryClaimStatus.ALREADY_DISPATCHED
                    )

                claim = await lifecycle._claim_dispatch_in_session(
                    session,
                    action_id=action_id,
                    worker_instance_id=worker_instance_id,
                    worker_incarnation=worker_incarnation,
                )
                if claim.status != DispatchClaimStatus.CLAIMED:
                    session.commit()
                    return ProviderDeliveryClaim(
                        claim.action,
                        intent,
                        ProviderDeliveryClaimStatus(claim.status.value),
                    )

                token = str(uuid4())
                intent.delivery_status = "CLAIMED"
                intent.claim_token = token
                intent.claim_expires_at = now + timedelta(seconds=claim_ttl_seconds)
                intent.attempt_count += 1
                intent.last_attempt_at = now
                intent.updated_at = now
                session.flush()
                request = ProviderDispatchRequest(
                    action_id=action.id,
                    run_id=action.run_id,
                    provider_idempotency_key=intent.provider_idempotency_key,
                    provider_request=dict(intent.provider_request_json),
                    claim_token=token,
                )
                session.commit()
                return ProviderDeliveryClaim(
                    action, intent, ProviderDeliveryClaimStatus.CLAIMED, request
                )
            except Exception:
                session.rollback()
                raise

    async def record_delivery_retry_metadata(
        self,
        *,
        action_id: str,
        error_class: str,
        next_delivery_at: Any | None = None,
    ) -> ProviderExecutionIntent:
        """Record operational metadata only; it cannot reauthorize or redispatch."""
        if not error_class:
            raise ValueError("error_class must be non-empty")
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                intent = self._intent_for_action(session, action_id)
                if intent is None:
                    raise NotFoundError(
                        f"Provider execution intent for {action_id} was not found"
                    )
                intent.last_error_class = error_class
                intent.next_delivery_at = next_delivery_at
                intent.updated_at = utcnow()
                session.commit()
                return intent
            except Exception:
                session.rollback()
                raise

    async def record_dispatch_outcome(
        self,
        *,
        claim_token: str,
        worker_instance_id: str,
        worker_incarnation: int,
        outcome: ProviderDispatchOutcome,
    ) -> ReconciliationIdentity:
        """Record a typed outcome only when its exact delivery claim authorizes it.

        The opaque claim token is a server-generated, process-internal
        correlation capability. It identifies one committed provider claim; it
        is not an external credential and cannot select an arbitrary action.
        """
        if not claim_token:
            raise ValueError("claim_token must be non-empty")
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                intents = session.scalars(
                    select(ProviderExecutionIntent).where(
                        ProviderExecutionIntent.claim_token == claim_token
                    )
                ).all()
                if len(intents) != 1:
                    raise ConflictError(
                        "Provider delivery claim correlation is invalid",
                        code="PROVIDER_DELIVERY_CLAIM_INVALID",
                    )
                intent = intents[0]
                action = session.get(ActionAttempt, intent.action_id)
                binding = session.get(ActionExternalOperationBinding, intent.action_id)
                if action is None or binding is None:
                    raise ConflictError(
                        "Provider execution intent binding is invalid",
                        code="PROVIDER_EXECUTION_INTENT_BINDING_INVALID",
                    )
                lifecycle = OperationLifecycleService(self.session_factory)
                lifecycle._require_owner(
                    action, worker_instance_id, worker_incarnation
                )
                if (
                    intent.delivery_status != "CLAIMED"
                    or action.execution_state != "DISPATCHED"
                ):
                    raise ConflictError(
                        "Provider delivery claim is not eligible for outcome recording",
                        code="PROVIDER_DELIVERY_CLAIM_INVALID",
                    )
                contract = ProviderAdapterContract(
                    binding.provider_adapter_id,
                    binding.provider_config_ref,
                    binding.provider_scope_ref,
                    binding.tool_reconciliation_version,
                    intent.provider_dispatch_contract_version,
                )
                if self.adapter_registry.resolve(contract) is None:
                    raise ConflictError(
                        "No trusted provider adapter matches the execution intent",
                        code="PROVIDER_ADAPTER_UNREGISTERED",
                    )
                if intent.provider_request_digest != payload_digest(
                    self._request_envelope(action, binding, contract)
                ):
                    raise ConflictError(
                        "Provider execution intent request identity is invalid",
                        code="PROVIDER_EXECUTION_INTENT_MISMATCH",
                    )
                if (
                    outcome.kind == ProviderDispatchOutcomeKind.ACCEPTED
                    and outcome.provider_handle is not None
                ):
                    if binding.provider_handle is None:
                        binding.provider_handle = outcome.provider_handle
                        binding.provider_handle_bound_at = utcnow()
                    elif binding.provider_handle != outcome.provider_handle:
                        raise ConflictError(
                            "Provider handle cannot be overwritten",
                            code="ACTION_PROVIDER_HANDLE_CONFLICT",
                        )
                session.flush()
                identity = OperationReconciliationService._identity(action, binding)
                session.commit()
                return identity
            except Exception:
                session.rollback()
                raise

    @staticmethod
    def _request_envelope(
        action: ActionAttempt,
        binding: ActionExternalOperationBinding,
        contract: ProviderAdapterContract,
    ) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "action_id": action.id,
            "run_id": action.run_id,
            "node_id": action.node_id,
            "worker_instance_id": action.worker_instance_id,
            "worker_incarnation": action.worker_incarnation,
            "tool_name": action.tool_name,
            "arguments": dict(action.arguments_json),
            "arguments_digest": action.arguments_digest,
            "request_payload_digest": action.request_payload_digest,
            "provider_adapter_id": binding.provider_adapter_id,
            "provider_config_ref": binding.provider_config_ref,
            "provider_scope_ref": binding.provider_scope_ref,
            "operation_key": binding.operation_key,
            "provider_dispatch_contract_version": contract.dispatch_contract_version,
        }

    @staticmethod
    def _intent_for_action(
        session: Session, action_id: str
    ) -> ProviderExecutionIntent | None:
        return session.scalar(
            select(ProviderExecutionIntent).where(
                ProviderExecutionIntent.action_id == action_id
            )
        )
