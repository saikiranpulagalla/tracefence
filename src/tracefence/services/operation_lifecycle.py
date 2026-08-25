"""Internal durable lifecycle for future external-style protected effects.

The public protected-effect boundary remains ActionGateway. This service is
internal: it reserves and fences ActionAttempt rows without registering a
network or process-control tool.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from tracefence.db.models import ActionAttempt, ActionAuthorityBinding, Node, WorkerInstance
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.domain.schemas import ActionExecute
from tracefence.security import payload_digest
from tracefence.services.common import (
    authenticate_execution_principal,
    authority_vector,
    authority_vector_digest,
    get_run,
    utcnow,
    validate_node_runtime_state,
)


@dataclass(frozen=True, slots=True)
class ResultAcceptance:
    action: ActionAttempt
    accepted: bool
    stale_reason: str | None = None


class OperationLifecycleService:
    """Own ActionAttempt lifecycle transitions for eventual external execution."""

    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def reserve(
        self, *, node_id: str, credential: str, request: ActionExecute
    ) -> ActionAttempt:
        request_digest = payload_digest(request.model_dump(mode="json"))
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                principal = await authenticate_execution_principal(
                    session, node_id=node_id, credential=credential
                )
                node = principal.node
                worker = principal.worker_instance
                existing = session.scalar(
                    select(ActionAttempt).where(
                        ActionAttempt.node_id == node.id,
                        ActionAttempt.idempotency_key == request.idempotency_key,
                    )
                )
                if existing is not None:
                    if existing.request_payload_digest != request_digest:
                        raise ConflictError(
                            "Idempotency key was reused with a different action payload",
                            code="IDEMPOTENCY_PAYLOAD_MISMATCH",
                        )
                    if (
                        principal.protocol_version == 2
                        and worker is not None
                        and existing.lifecycle_version == 1
                        and existing.worker_instance_id != worker.id
                    ):
                        raise ConflictError(
                            "Idempotency key belongs to a different worker incarnation",
                            code="IDEMPOTENCY_OWNER_MISMATCH",
                        )
                    session.commit()
                    return cast(ActionAttempt, existing)

                allowed, reason, evaluation = await validate_node_runtime_state(session, node)
                if not allowed:
                    raise ConflictError(
                        f"Operation cannot be reserved: {reason}",
                        code=reason or "OPERATION_RESERVATION_DENIED",
                    )
                run = await get_run(session, node.run_id)
                action = ActionAttempt(
                    id=str(uuid4()),
                    run_id=node.run_id,
                    node_id=node.id,
                    tool_name=request.tool_name,
                    side_effecting=True,
                    idempotency_key=request.idempotency_key,
                    decision="ALLOW",
                    denial_reason=None,
                    scope_evaluation_json={
                        "allowed": evaluation.allowed,
                        "live_scopes": list(evaluation.live_scopes),
                    },
                    decision_explanation_json={
                        "schema_version": 1,
                        "idempotency": "NEW",
                        "final_decision": "ALLOW",
                        "lifecycle": "AUTHORIZED",
                    },
                    request_payload_digest=request_digest,
                    arguments_json=dict(request.arguments),
                    arguments_digest=payload_digest(request.arguments),
                    attempted_at=utcnow(),
                    lifecycle_version=1,
                    execution_state="AUTHORIZED",
                    worker_instance_id=worker.id if worker is not None else None,
                    worker_incarnation=worker.incarnation if worker is not None else None,
                    authority_vector_digest=authority_vector_digest(evaluation),
                    authorization_proof_revision=run.proof_revision + 1,
                )
                session.add(action)
                for scope in authority_vector(evaluation):
                    session.add(
                        ActionAuthorityBinding(
                            run_id=node.run_id,
                            action_id=action.id,
                            scope_id=scope["scope_id"],
                            bound_version=scope["bound_version"],
                        )
                    )
                session.commit()
                return action
            except Exception:
                session.rollback()
                raise

    def mark_dispatched(
        self, *, action_id: str, worker_instance_id: str, worker_incarnation: int
    ) -> ActionAttempt:
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action = self._action(session, action_id)
                self._require_owner(action, worker_instance_id, worker_incarnation)
                if action.execution_state == "DISPATCHED":
                    session.commit()
                    return action
                if action.execution_state != "AUTHORIZED":
                    raise ConflictError(
                        "Operation cannot be dispatched from its current lifecycle state",
                        code="ACTION_DISPATCH_STATE_INVALID",
                    )
                action.execution_state = "DISPATCHED"
                action.dispatched_at = utcnow()
                session.commit()
                return action
            except Exception:
                session.rollback()
                raise

    async def accept_result(
        self,
        *,
        action_id: str,
        worker_instance_id: str,
        worker_incarnation: int,
        tool_name: str,
        arguments_digest: str,
        result: dict[str, Any],
        failed: bool = False,
    ) -> ResultAcceptance:
        result_digest = payload_digest(result)
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action = self._action(session, action_id)
                self._require_result_identity(
                    action,
                    worker_instance_id=worker_instance_id,
                    worker_incarnation=worker_incarnation,
                    tool_name=tool_name,
                    arguments_digest=arguments_digest,
                )
                if action.execution_state in {"SUCCEEDED", "FAILED"}:
                    if action.result_digest == result_digest:
                        session.commit()
                        return ResultAcceptance(action, accepted=True)
                    raise ConflictError(
                        "A different authoritative result was already accepted",
                        code="ACTION_RESULT_ALREADY_TERMINAL",
                    )
                if action.execution_state == "STALE":
                    if action.stale_result_digest == result_digest:
                        session.commit()
                        return ResultAcceptance(
                            action, accepted=False, stale_reason=action.stale_reason_code
                        )
                    raise ConflictError(
                        "Conflicting stale result evidence cannot overwrite the first observation",
                        code="ACTION_STALE_EVIDENCE_CONFLICT",
                    )
                if action.execution_state != "DISPATCHED":
                    raise ConflictError(
                        "Operation result is not acceptable from its current lifecycle state",
                        code="ACTION_RESULT_STATE_INVALID",
                    )

                stale_reason = await self._stale_reason(session, action)
                if stale_reason is not None:
                    action.execution_state = "STALE"
                    action.stale_result_digest = result_digest
                    action.stale_reason_code = stale_reason
                    action.stale_observed_at = utcnow()
                    session.commit()
                    return ResultAcceptance(action, accepted=False, stale_reason=stale_reason)

                action.execution_state = "FAILED" if failed else "SUCCEEDED"
                action.result_json = result
                action.result_digest = result_digest
                action.committed_at = utcnow()
                session.commit()
                return ResultAcceptance(action, accepted=True)
            except Exception:
                session.rollback()
                raise

    def reject_stale_result(
        self,
        *,
        action_id: str,
        worker_instance_id: str,
        worker_incarnation: int,
        result: dict[str, Any],
        reason_code: str,
    ) -> ResultAcceptance:
        result_digest = payload_digest(result)
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action = self._action(session, action_id)
                self._require_owner(action, worker_instance_id, worker_incarnation)
                if action.execution_state == "STALE":
                    if (
                        action.stale_result_digest == result_digest
                        and action.stale_reason_code == reason_code
                    ):
                        session.commit()
                        return ResultAcceptance(action, accepted=False, stale_reason=reason_code)
                    raise ConflictError(
                        "Conflicting stale result evidence cannot overwrite the first observation",
                        code="ACTION_STALE_EVIDENCE_CONFLICT",
                    )
                if action.execution_state not in {"AUTHORIZED", "DISPATCHED", "AMBIGUOUS"}:
                    raise ConflictError(
                        "Operation cannot be marked stale from its current lifecycle state",
                        code="ACTION_STALE_STATE_INVALID",
                    )
                action.execution_state = "STALE"
                action.stale_result_digest = result_digest
                action.stale_reason_code = reason_code
                action.stale_observed_at = utcnow()
                session.commit()
                return ResultAcceptance(action, accepted=False, stale_reason=reason_code)
            except Exception:
                session.rollback()
                raise

    async def _stale_reason(self, session: Session, action: ActionAttempt) -> str | None:
        node = session.get(Node, action.node_id)
        worker = session.get(WorkerInstance, action.worker_instance_id)
        if node is None or worker is None:
            return "ACTION_BINDING_MISSING"
        if worker.incarnation != action.worker_incarnation:
            return "WORKER_INCARNATION_MISMATCH"
        if node.current_worker_instance_id != worker.id or worker.observed_state != "ACTIVE":
            return "WORKER_NOT_CURRENT"
        allowed, reason, evaluation = await validate_node_runtime_state(session, node)
        if not allowed:
            return reason or "AUTHORITY_NOT_LIVE"
        bindings = session.execute(
            select(ActionAuthorityBinding)
            .where(ActionAuthorityBinding.action_id == action.id)
            .order_by(ActionAuthorityBinding.scope_id)
        ).scalars().all()
        current = authority_vector(evaluation)
        bound = tuple(
            {"scope_id": row.scope_id, "bound_version": row.bound_version} for row in bindings
        )
        if (
            action.authority_vector_digest != authority_vector_digest(evaluation)
            or bound != current
        ):
            return "AUTHORITY_VECTOR_CHANGED"
        return None

    @staticmethod
    def _action(session: Session, action_id: str) -> ActionAttempt:
        action = session.get(ActionAttempt, action_id)
        if action is None:
            raise NotFoundError(f"Action attempt {action_id} was not found")
        return action

    @staticmethod
    def _require_owner(
        action: ActionAttempt, worker_instance_id: str, worker_incarnation: int
    ) -> None:
        if (
            action.lifecycle_version != 1
            or action.worker_instance_id != worker_instance_id
            or action.worker_incarnation != worker_incarnation
        ):
            raise ConflictError(
                "Operation result belongs to a different worker incarnation",
                code="ACTION_WORKER_OWNER_MISMATCH",
            )

    @classmethod
    def _require_result_identity(
        cls,
        action: ActionAttempt,
        *,
        worker_instance_id: str,
        worker_incarnation: int,
        tool_name: str,
        arguments_digest: str,
    ) -> None:
        cls._require_owner(action, worker_instance_id, worker_incarnation)
        if action.tool_name != tool_name or action.arguments_digest != arguments_digest:
            raise ConflictError(
                "Operation result does not match the reserved action identity",
                code="ACTION_RESULT_IDENTITY_MISMATCH",
            )
