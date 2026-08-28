from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from tracefence.db.models import (
    ActionAttempt,
    ActionExternalOperationBinding,
    ActionReconciliationEvidence,
    ActionRecoveryLink,
)
from tracefence.domain.enums import ActionDecision
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.domain.schemas import ActionExecute
from tracefence.security import payload_digest
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
from tracefence.services.tool_registry import get_tool_spec


class RecoveryCreationStatus(StrEnum):
    AUTHORIZED_SUCCESSOR_CREATED = "AUTHORIZED_SUCCESSOR_CREATED"
    AUTHORIZED_SUCCESSOR_REPLAY = "AUTHORIZED_SUCCESSOR_REPLAY"
    CANONICAL_DENIED = "CANONICAL_DENIED"


@dataclass(frozen=True, slots=True)
class RecoveryCreation:
    action: ActionAttempt
    status: RecoveryCreationStatus


class OperationRecoveryService:
    """Create explicit, lineage-bound successors from C-C1 durable truth only."""

    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory
        self._gateway = ActionGateway(session_factory)

    async def create_recovery(
        self,
        *,
        source_action_id: str,
        node_id: str,
        node_token: str,
        request: ActionExecute,
        recovery_request_identity: str,
    ) -> RecoveryCreation:
        """Reserve one explicit successor without dispatching or provider I/O."""
        if not recovery_request_identity:
            raise ValueError("recovery_request_identity must be non-empty")
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                source = session.get(ActionAttempt, source_action_id)
                if source is None:
                    raise NotFoundError(f"Action attempt {source_action_id} was not found")
                binding = session.get(ActionExternalOperationBinding, source.id)
                if binding is None:
                    raise ConflictError(
                        "Recovery source has no external operation binding",
                        code="RECOVERY_BASIS_INVALID",
                    )
                evidence = self._definitive_nonexecution(session, source, binding)
                policy_version = self._validate_source_policy(source, request)
                internal_request = self._internal_request(
                    source=source,
                    evidence=evidence,
                    request=request,
                    recovery_request_identity=recovery_request_identity,
                )
                request_digest = self._lineage_request_digest(
                    source=source,
                    evidence=evidence,
                    policy_version=policy_version,
                    request=internal_request,
                )

                link = session.get(ActionRecoveryLink, (source.run_id, source.id))
                if link is not None:
                    if link.recovery_request_digest != request_digest:
                        raise ConflictError(
                            "Recovery source already has a different successor request",
                            code="RECOVERY_REQUEST_MISMATCH",
                        )
                    reservation = await self._gateway._reserve_in_session(
                        session,
                        node_id=node_id,
                        node_token=node_token,
                        request=internal_request,
                    )
                    if (
                        not reservation.duplicate
                        or reservation.action.id != link.recovery_action_id
                    ):
                        raise ConflictError(
                            "Recovery lineage does not match idempotency ownership",
                            code="RECOVERY_REQUEST_MISMATCH",
                        )
                    session.commit()
                    return RecoveryCreation(
                        reservation.action,
                        RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_REPLAY,
                    )

                reservation = await self._gateway._reserve_in_session(
                    session,
                    node_id=node_id,
                    node_token=node_token,
                    request=internal_request,
                )
                action = reservation.action
                if reservation.duplicate:
                    if action.execution_state == "DENIED":
                        session.commit()
                        return RecoveryCreation(action, RecoveryCreationStatus.CANONICAL_DENIED)
                    raise ConflictError(
                        "Recovery idempotency identity is already bound",
                        code="RECOVERY_REQUEST_MISMATCH",
                    )
                if action.decision == ActionDecision.DENY:
                    session.commit()
                    return RecoveryCreation(action, RecoveryCreationStatus.CANONICAL_DENIED)
                if action.execution_state != "AUTHORIZED":
                    raise ConflictError(
                        "Explicit recovery requires a dispatchable lifecycle action",
                        code="RECOVERY_ACTION_STATE_INVALID",
                    )
                link = ActionRecoveryLink(
                    source_run_id=source.run_id,
                    source_action_id=source.id,
                    recovery_run_id=action.run_id,
                    recovery_action_id=action.id,
                    basis_evidence_id=evidence.id,
                    recovery_policy_version=policy_version,
                    recovery_request_digest=request_digest,
                    created_at=utcnow(),
                )
                session.add(link)
                session.flush()
                session.commit()
                return RecoveryCreation(action, RecoveryCreationStatus.AUTHORIZED_SUCCESSOR_CREATED)
            except Exception:
                session.rollback()
                raise

    @staticmethod
    def _internal_request(
        *,
        source: ActionAttempt,
        evidence: ActionReconciliationEvidence,
        request: ActionExecute,
        recovery_request_identity: str,
    ) -> ActionExecute:
        key = payload_digest(
            {
                "domain": "explicit-action-recovery-v1",
                "source_action_id": source.id,
                "basis_evidence_id": evidence.id,
                "recovery_request_identity": recovery_request_identity,
            }
        )
        return ActionExecute(
            tool_name=request.tool_name,
            arguments=dict(request.arguments),
            idempotency_key=f"recovery:{key}",
        )

    @staticmethod
    def _lineage_request_digest(
        *,
        source: ActionAttempt,
        evidence: ActionReconciliationEvidence,
        policy_version: str,
        request: ActionExecute,
    ) -> str:
        return payload_digest(
            {
                "source_action_id": source.id,
                "basis_evidence_id": evidence.id,
                "recovery_policy_version": policy_version,
                "request_payload_digest": payload_digest(request.model_dump(mode="json")),
            }
        )

    @staticmethod
    def _validate_source_policy(source: ActionAttempt, request: ActionExecute) -> str:
        if source.lifecycle_version != 1 or source.execution_state not in {"FAILED", "STALE"}:
            raise ConflictError(
                "Recovery source is not terminal nonexecution history",
                code="RECOVERY_BASIS_INVALID",
            )
        if (
            source.tool_name != request.tool_name
            or source.arguments_digest != payload_digest(request.arguments)
        ):
            raise ConflictError(
                "Recovery request changes the protected effect",
                code="RECOVERY_REQUEST_MISMATCH",
            )
        spec = get_tool_spec(source.tool_name)
        if not spec.allows_explicit_recovery:
            raise ConflictError(
                "Tool does not permit explicit recovery successors",
                code="RECOVERY_POLICY_DISABLED",
            )
        return spec.explicit_recovery_policy_version or ""

    @staticmethod
    def _definitive_nonexecution(
        session: Session,
        source: ActionAttempt,
        binding: ActionExternalOperationBinding,
    ) -> ActionReconciliationEvidence:
        conflicts = session.scalars(
            select(ActionReconciliationEvidence).where(
                ActionReconciliationEvidence.run_id == source.run_id,
                ActionReconciliationEvidence.action_id == source.id,
                ActionReconciliationEvidence.observation_kind == "CONFLICT",
                ActionReconciliationEvidence.outcome_class == "CONFLICT",
            )
        ).all()
        if conflicts:
            raise ConflictError(
                "Recovery source has material reconciliation conflict",
                code="RECOVERY_SOURCE_CONFLICT",
            )
        evidence = session.scalars(
            select(ActionReconciliationEvidence).where(
                ActionReconciliationEvidence.run_id == binding.run_id,
                ActionReconciliationEvidence.action_id == binding.action_id,
                ActionReconciliationEvidence.observation_kind == "NONEXECUTION",
                ActionReconciliationEvidence.outcome_class == "NONEXECUTED",
            )
        ).all()
        if len(evidence) != 1:
            raise ConflictError(
                "Recovery requires exactly one definitive nonexecution evidence record",
                code="RECOVERY_BASIS_INVALID",
            )
        return evidence[0]
