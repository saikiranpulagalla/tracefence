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

from tracefence.db.models import (
    ActionAttempt,
    ActionAuthorityBinding,
    ActionExternalOperationBinding,
    ActionReconciliationEvidence,
    ActionRecoveryLink,
    Node,
    WorkerInstance,
)
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


class DispatchClaimStatus(StrEnum):
    """One caller's durable cooperative-dispatch outcome."""

    CLAIMED = "CLAIMED"
    ALREADY_DISPATCHED = "ALREADY_DISPATCHED"
    REVOKED = "REVOKED"
    UNCERTAIN = "UNCERTAIN"
    TERMINAL = "TERMINAL"


@dataclass(frozen=True, slots=True)
class OperationAuthorityDecision:
    """Non-persistent authority decision for one exact evaluation point."""

    status: OperationAuthorityStatus
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class DispatchClaim:
    """The outcome of one serialized attempt to claim cooperative dispatch."""

    action: ActionAttempt
    status: DispatchClaimStatus


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


class OperationRevoked(Exception):
    """A cooperative checkpoint positively observed revoked authority."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class OperationAuthorityUncertain(Exception):
    """A cooperative checkpoint could not safely establish authority."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class CooperativeOperationContext:
    """Immutable identity and checkpoint capability for cooperative execution.

    It deliberately holds no SQLAlchemy session. Each checkpoint delegates to
    the B1 read-only cancellation context, which opens its own short-lived read
    session and never caches a positive decision.
    """

    action_id: str
    run_id: str
    node_id: str
    worker_instance_id: str
    worker_incarnation: int
    cancellation: OperationCancellationContext

    @classmethod
    def from_action(
        cls, session_factory: sessionmaker, action: ActionAttempt
    ) -> CooperativeOperationContext:
        cancellation = OperationCancellationContext.from_action(session_factory, action)
        return cls(
            action_id=action.id,
            run_id=action.run_id,
            node_id=action.node_id,
            worker_instance_id=cancellation.worker_instance_id,
            worker_incarnation=cancellation.worker_incarnation,
            cancellation=cancellation,
        )

    async def checkpoint(self) -> None:
        decision = await self.cancellation.check()
        if decision.status == OperationAuthorityStatus.ALLOWED:
            return
        if decision.status == OperationAuthorityStatus.REVOKED:
            raise OperationRevoked(decision.reason_code or "AUTHORITY_NOT_LIVE")
        raise OperationAuthorityUncertain(
            decision.reason_code or "OPERATION_AUTHORITY_UNCERTAIN"
        )


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


def evaluate_recovery_dispatch_basis(
    session: Session, action: ActionAttempt
) -> OperationAuthorityDecision:
    """Validate immutable recovery lineage in the dispatch-claim writer TX."""
    link = session.scalar(
        select(ActionRecoveryLink).where(
            ActionRecoveryLink.recovery_action_id == action.id
        )
    )
    if link is None:
        return _allowed()
    source = session.get(ActionAttempt, link.source_action_id)
    binding = session.get(ActionExternalOperationBinding, link.source_action_id)
    evidence = session.get(ActionReconciliationEvidence, link.basis_evidence_id)
    if (
        source is None
        or binding is None
        or evidence is None
        or link.source_run_id != source.run_id
        or link.recovery_run_id != action.run_id
        or evidence.run_id != source.run_id
        or evidence.action_id != source.id
        or evidence.observation_kind != "NONEXECUTION"
        or evidence.outcome_class != "NONEXECUTED"
        or source.lifecycle_version != 1
        or source.tool_name != action.tool_name
        or source.arguments_digest != action.arguments_digest
    ):
        return _revoked("RECOVERY_BASIS_INVALID")
    conflict = session.scalar(
        select(ActionReconciliationEvidence.id).where(
            ActionReconciliationEvidence.run_id == source.run_id,
            ActionReconciliationEvidence.action_id == source.id,
            ActionReconciliationEvidence.observation_kind == "CONFLICT",
            ActionReconciliationEvidence.outcome_class == "CONFLICT",
        )
    )
    if conflict is not None:
        return _revoked("RECOVERY_SOURCE_CONFLICT")
    # Avoid importing the registry while it imports this module's cooperative context.
    from tracefence.services.tool_registry import get_tool_spec

    spec = get_tool_spec(action.tool_name)
    if (
        not spec.allows_explicit_recovery
        or spec.explicit_recovery_policy_version != link.recovery_policy_version
    ):
        return _revoked("RECOVERY_POLICY_INVALID")
    request_digest = payload_digest(
        {
            "source_action_id": source.id,
            "basis_evidence_id": evidence.id,
            "recovery_policy_version": link.recovery_policy_version,
            "request_payload_digest": action.request_payload_digest,
        }
    )
    if request_digest != link.recovery_request_digest:
        return _revoked("RECOVERY_REQUEST_MISMATCH")
    return _allowed()


class OperationLifecycleService:
    """Own ActionAttempt lifecycle transitions for eventual external execution."""

    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def reserve(
        self,
        *,
        node_id: str,
        credential: str,
        request: ActionExecute,
        required_capability: str | None = None,
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
                if required_capability is not None and required_capability not in set(
                    node.capabilities_json or []
                ):
                    raise ConflictError(
                        "Tool capability is not allowed for this node",
                        code="TOOL_NOT_ALLOWED",
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

    async def mark_dispatched(
        self, *, action_id: str, worker_instance_id: str, worker_incarnation: int
    ) -> DispatchClaim:
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action = self._action(session, action_id)
                self._require_owner(action, worker_instance_id, worker_incarnation)
                if action.execution_state == "DISPATCHED":
                    session.commit()
                    return DispatchClaim(action, DispatchClaimStatus.ALREADY_DISPATCHED)
                if action.execution_state != "AUTHORIZED":
                    session.commit()
                    return DispatchClaim(action, DispatchClaimStatus.TERMINAL)
                authority = await evaluate_live_bound_action_authority(session, action)
                if authority.status == OperationAuthorityStatus.ALLOWED:
                    authority = evaluate_recovery_dispatch_basis(session, action)
                if authority.status == OperationAuthorityStatus.REVOKED:
                    action.execution_state = "STALE"
                    action.stale_result_digest = payload_digest(
                        {"dispatch": "not_started", "reason": authority.reason_code}
                    )
                    action.stale_reason_code = authority.reason_code or "AUTHORITY_NOT_LIVE"
                    action.stale_observed_at = utcnow()
                    session.commit()
                    return DispatchClaim(action, DispatchClaimStatus.REVOKED)
                if authority.status == OperationAuthorityStatus.UNCERTAIN:
                    session.commit()
                    return DispatchClaim(action, DispatchClaimStatus.UNCERTAIN)
                action.execution_state = "DISPATCHED"
                action.dispatched_at = utcnow()
                session.commit()
                return DispatchClaim(action, DispatchClaimStatus.CLAIMED)
            except Exception:
                session.rollback()
                raise


    async def _claim_dispatch_in_session(
        self,
        session: Session,
        *,
        action_id: str,
        worker_instance_id: str,
        worker_incarnation: int,
    ) -> DispatchClaim:
        """Claim dispatch using the caller-owned serialized writer transaction."""
        action = self._action(session, action_id)
        self._require_owner(action, worker_instance_id, worker_incarnation)
        if action.execution_state == "DISPATCHED":
            return DispatchClaim(action, DispatchClaimStatus.ALREADY_DISPATCHED)
        if action.execution_state != "AUTHORIZED":
            return DispatchClaim(action, DispatchClaimStatus.TERMINAL)
        authority = await evaluate_live_bound_action_authority(session, action)
        if authority.status == OperationAuthorityStatus.ALLOWED:
            authority = evaluate_recovery_dispatch_basis(session, action)
        if authority.status == OperationAuthorityStatus.REVOKED:
            action.execution_state = "STALE"
            action.stale_result_digest = payload_digest(
                {"dispatch": "not_started", "reason": authority.reason_code}
            )
            action.stale_reason_code = authority.reason_code or "AUTHORITY_NOT_LIVE"
            action.stale_observed_at = utcnow()
            return DispatchClaim(action, DispatchClaimStatus.REVOKED)
        if authority.status == OperationAuthorityStatus.UNCERTAIN:
            return DispatchClaim(action, DispatchClaimStatus.UNCERTAIN)
        action.execution_state = "DISPATCHED"
        action.dispatched_at = utcnow()
        return DispatchClaim(action, DispatchClaimStatus.CLAIMED)

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
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action = self._action(session, action_id)
                accepted = await self._accept_result_in_session(
                    session,
                    action=action,
                    worker_instance_id=worker_instance_id,
                    worker_incarnation=worker_incarnation,
                    tool_name=tool_name,
                    arguments_digest=arguments_digest,
                    result=result,
                    failed=failed,
                )
                session.commit()
                return accepted
            except Exception:
                session.rollback()
                raise

    async def _accept_result_in_session(
        self,
        session: Session,
        *,
        action: ActionAttempt,
        worker_instance_id: str,
        worker_incarnation: int,
        tool_name: str,
        arguments_digest: str,
        result: dict[str, Any],
        failed: bool = False,
    ) -> ResultAcceptance:
        """Apply one result using the canonical v24 authority fence.

        The caller owns a short writer transaction.  This is shared by normal
        worker completion and C-C1 reconciliation evidence application.
        """
        result_digest = payload_digest(result)
        self._require_result_identity(
            action,
            worker_instance_id=worker_instance_id,
            worker_incarnation=worker_incarnation,
            tool_name=tool_name,
            arguments_digest=arguments_digest,
        )
        if action.execution_state in {"SUCCEEDED", "FAILED"}:
            if action.result_digest == result_digest:
                return ResultAcceptance(action, accepted=True)
            raise ConflictError(
                "A different authoritative result was already accepted",
                code="ACTION_RESULT_ALREADY_TERMINAL",
            )
        if action.execution_state == "STALE":
            if action.stale_result_digest == result_digest:
                return ResultAcceptance(action, accepted=False, stale_reason=action.stale_reason_code)
            raise ConflictError(
                "Conflicting stale result evidence cannot overwrite the first observation",
                code="ACTION_STALE_EVIDENCE_CONFLICT",
            )
        if action.execution_state not in {"DISPATCHED", "AMBIGUOUS"}:
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
        return ResultAcceptance(action, accepted=True)

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
