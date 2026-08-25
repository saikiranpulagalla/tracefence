"""Internal durable lifecycle for future external-style protected effects.

The public protected-effect boundary remains ActionGateway. This service is
internal: it reserves and fences ActionAttempt rows without registering a
network or process-control tool.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.exc import DisconnectionError, InterfaceError, OperationalError
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


class OperationAuthorityStatus(StrEnum):
    """The live authority state of an already-bound lifecycle operation."""

    ALLOWED = "ALLOWED"
    REVOKED = "REVOKED"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True, slots=True)
class OperationAuthorityDecision:
    """Non-persistent authority decision for one exact evaluation point."""

    status: OperationAuthorityStatus
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class OperationCancellationContext:
    """Read-only cooperative authority observer for one lifecycle action.

    The context stores immutable expected identity only. Every checkpoint
    opens a fresh read session and re-evaluates durable authority; it never
    caches an ALLOWED decision or records a cancellation fact.
    """

    session_factory: sessionmaker
    action_id: str
    run_id: str
    node_id: str
    worker_instance_id: str
    worker_incarnation: int

    @classmethod
    def from_action(
        cls, session_factory: sessionmaker, action: ActionAttempt
    ) -> OperationCancellationContext:
        if (
            action.lifecycle_version != 1
            or action.worker_instance_id is None
            or action.worker_incarnation is None
        ):
            raise ValueError("Operation cancellation requires a bound lifecycle action")
        return cls(
            session_factory=session_factory,
            action_id=action.id,
            run_id=action.run_id,
            node_id=action.node_id,
            worker_instance_id=action.worker_instance_id,
            worker_incarnation=action.worker_incarnation,
        )

    async def check(self) -> OperationAuthorityDecision:
        """Return a fresh, read-only authority decision.

        SQLAlchemy uses synchronous I/O in this repository's service layer;
        callers run that layer through the established blocking-service
        boundary. This method stays async to share the existing canonical
        runtime-state evaluator without introducing a second evaluator.
        """
        try:
            with self.session_factory() as session:
                action = session.get(ActionAttempt, self.action_id)
                if action is None:
                    return _uncertain("OPERATION_BINDING_INVALID")
                return await evaluate_live_bound_action_authority(
                    session,
                    action,
                    expected_run_id=self.run_id,
                    expected_node_id=self.node_id,
                    expected_worker_instance_id=self.worker_instance_id,
                    expected_worker_incarnation=self.worker_incarnation,
                )
        except (OperationalError, DisconnectionError, InterfaceError):
            return _uncertain()


def _allowed() -> OperationAuthorityDecision:
    return OperationAuthorityDecision(OperationAuthorityStatus.ALLOWED)


def _revoked(reason_code: str) -> OperationAuthorityDecision:
    return OperationAuthorityDecision(OperationAuthorityStatus.REVOKED, reason_code)
async def evaluate_live_bound_action_authority(
    session: Session,
    action: ActionAttempt,
    *,
    expected_run_id: str | None = None,
    expected_node_id: str | None = None,
    expected_worker_instance_id: str | None = None,
    expected_worker_incarnation: int | None = None,
) -> OperationAuthorityDecision:
    """Return one structured live-authority decision for a bound action."""
    try:
        return await _evaluate_live_bound_action_authority(
            session,
            action,
            expected_run_id=expected_run_id,
            expected_node_id=expected_node_id,
            expected_worker_instance_id=expected_worker_instance_id,
            expected_worker_incarnation=expected_worker_incarnation,
        )
    except (OperationalError, DisconnectionError, InterfaceError):
        return _uncertain()




def _uncertain(
    reason_code: str = "OPERATION_AUTHORITY_UNCERTAIN",
) -> OperationAuthorityDecision:
    return OperationAuthorityDecision(OperationAuthorityStatus.UNCERTAIN, reason_code)


async def _evaluate_live_bound_action_authority(
    session: Session,
    action: ActionAttempt,
    *,
    expected_run_id: str | None = None,
    expected_node_id: str | None = None,
    expected_worker_instance_id: str | None = None,
    expected_worker_incarnation: int | None = None,
) -> OperationAuthorityDecision:
    """Evaluate durable, live authority for an already-bound v24 action.

    This sole post-reservation evaluator layers exact ActionAttempt,
    WorkerInstance, and authority-binding checks over
    validate_node_runtime_state, the canonical run/node/lease/scope evaluator
    shared with reservation and result acceptance.
    """
    if (
        action.lifecycle_version != 1
        or action.decision != "ALLOW"
        or action.worker_instance_id is None
        or action.worker_incarnation is None
        or action.authority_vector_digest is None
    ):
        return _uncertain("OPERATION_BINDING_INVALID")

    if expected_run_id is not None and action.run_id != expected_run_id:
        return _revoked("OPERATION_CONTEXT_IDENTITY_MISMATCH")
    if expected_node_id is not None and action.node_id != expected_node_id:
        return _revoked("OPERATION_CONTEXT_IDENTITY_MISMATCH")
    if (
        expected_worker_instance_id is not None
        and action.worker_instance_id != expected_worker_instance_id
    ) or (
        expected_worker_incarnation is not None
        and action.worker_incarnation != expected_worker_incarnation
    ):
        return _revoked("ACTION_WORKER_OWNER_MISMATCH")

    node = session.get(Node, action.node_id)
    worker = session.get(WorkerInstance, action.worker_instance_id)
    if node is None or worker is None or worker.node_id != action.node_id:
        return _uncertain("OPERATION_BINDING_INVALID")
    if worker.incarnation != action.worker_incarnation:
        return _revoked("WORKER_INCARNATION_MISMATCH")
    if node.current_worker_instance_id != worker.id or worker.observed_state != "ACTIVE":
        return _revoked("WORKER_NOT_CURRENT")

    allowed, reason, evaluation = await validate_node_runtime_state(session, node)
    if not allowed:
        if reason == "SCOPE_NOT_FOUND":
            return _uncertain("OPERATION_BINDING_INVALID")
        return _revoked(reason or "AUTHORITY_NOT_LIVE")

    bindings = session.execute(
        select(ActionAuthorityBinding)
        .where(ActionAuthorityBinding.action_id == action.id)
        .order_by(ActionAuthorityBinding.scope_id)
    ).scalars().all()
    if not bindings:
        return _uncertain("OPERATION_BINDING_INVALID")
    bound = tuple(
        {"scope_id": row.scope_id, "bound_version": row.bound_version} for row in bindings
    )
    current = authority_vector(evaluation)
    if bound != current or action.authority_vector_digest != authority_vector_digest(evaluation):
        return _uncertain("OPERATION_BINDING_INVALID")
    return _allowed()


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

                authority = await evaluate_live_bound_action_authority(session, action)
                if authority.status == OperationAuthorityStatus.REVOKED:
                    stale_reason = authority.reason_code or "AUTHORITY_NOT_LIVE"
                    action.execution_state = "STALE"
                    action.stale_result_digest = result_digest
                    action.stale_reason_code = stale_reason
                    action.stale_observed_at = utcnow()
                    session.commit()
                    return ResultAcceptance(action, accepted=False, stale_reason=stale_reason)
                if authority.status == OperationAuthorityStatus.UNCERTAIN:
                    raise ConflictError(
                        "Operation result authority could not be established",
                        code=authority.reason_code or "OPERATION_AUTHORITY_UNCERTAIN",
                    )

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
