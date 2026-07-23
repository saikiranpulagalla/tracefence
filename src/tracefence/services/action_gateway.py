from __future__ import annotations

import logging
import time
from dataclasses import asdict
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from tracefence.config import settings
from tracefence.db.models import ActionAttempt, ActionCommandMatch, CommandAcknowledgement
from tracefence.domain.enums import AckType, ActionDecision
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute, ActionResult
from tracefence.security import payload_digest, token_matches
from tracefence.services.common import (
    commands_for_scope_mismatches,
    evaluate_scopes,
    get_node,
    get_run,
    utcnow,
)
from tracefence.services.tool_registry import get_tool_spec
from tracefence.telemetry.instruments import telemetry

logger = logging.getLogger(__name__)

STALE_REASONS = {"SCOPE_CANCELLED", "SCOPE_SUPERSEDED", "SCOPE_VERSION_MISMATCH"}


class ActionGateway:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def execute(
        self,
        node_id: str,
        node_token: str,
        request: ActionExecute,
    ) -> ActionResult:
        started = time.perf_counter()
        request_digest = payload_digest(request.model_dump(mode="json"))

        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                node = await get_node(session, node_id)
                if not token_matches(node_token, node.token_hash):
                    from tracefence.domain.errors import AuthenticationError

                    raise AuthenticationError("Invalid node token")

                # Tool existence and argument-shape errors are evaluated only after
                # node authentication so the gateway does not become a tool/capability
                # oracle for unauthenticated callers.
                spec = get_tool_spec(request.tool_name)
                spec.validate_arguments(request.arguments)

                existing = session.execute(
                    select(ActionAttempt).where(
                        ActionAttempt.node_id == node_id,
                        ActionAttempt.idempotency_key == request.idempotency_key,
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    if existing.request_payload_digest != request_digest:
                        raise ConflictError(
                            "Idempotency key was reused with a different action payload",
                            code="IDEMPOTENCY_PAYLOAD_MISMATCH",
                        )
                    session.commit()
                    return self._result(existing, duplicate=True)

                action_count = session.scalar(
                    select(func.count(ActionAttempt.id)).where(
                        ActionAttempt.run_id == node.run_id
                    )
                ) or 0
                if action_count >= settings.max_actions_per_run:
                    raise ConflictError(
                        "Action quota exceeded for run",
                        code="RUN_ACTION_QUOTA_EXCEEDED",
                    )

                run = await get_run(session, node.run_id)
                evaluation = await evaluate_scopes(session, node)

                denial_reason: str | None = None
                if run.status != "RUNNING":
                    denial_reason = "RUN_NOT_ACTIVE"
                elif node.status not in {"ACTIVE", "WAITING"}:
                    denial_reason = "NODE_NOT_ACTIVE"
                elif node.lease_expires_at is None or node.lease_expires_at <= utcnow():
                    denial_reason = "LEASE_EXPIRED"
                elif not evaluation.allowed:
                    denial_reason = evaluation.primary_reason or "SCOPE_INVALID"
                elif spec.capability not in set(node.capabilities_json or []):
                    denial_reason = "TOOL_NOT_ALLOWED"

                commands = []
                command = None
                matched_mismatch = None
                if denial_reason in STALE_REASONS:
                    commands = await commands_for_scope_mismatches(
                        session, evaluation.mismatches, run_id=node.run_id
                    )
                    command = commands[-1] if commands else None
                    if command is not None:
                        matched_mismatch = next(
                            (
                                mismatch
                                for mismatch in evaluation.mismatches
                                if mismatch.scope_id == command.target_scope_id
                            ),
                            None,
                        )
                    if matched_mismatch is None and evaluation.mismatches:
                        matched_mismatch = evaluation.mismatches[0]

                attempt = ActionAttempt(
                    id=str(uuid4()),
                    run_id=node.run_id,
                    node_id=node.id,
                    tool_name=request.tool_name,
                    side_effecting=spec.side_effecting,
                    idempotency_key=request.idempotency_key,
                    decision=(ActionDecision.DENY if denial_reason else ActionDecision.ALLOW),
                    denial_reason=denial_reason,
                    matched_command_id=command.id if command else None,
                    matched_scope_id=matched_mismatch.scope_id if matched_mismatch else None,
                    matched_snapshot_version=(
                        matched_mismatch.snapshot_version if matched_mismatch else None
                    ),
                    matched_live_version=matched_mismatch.live_version if matched_mismatch else None,
                    matched_live_status=matched_mismatch.live_status if matched_mismatch else None,
                    scope_evaluation_json={
                        "allowed": evaluation.allowed,
                        "effective_status": evaluation.effective_status,
                        "mismatches": [asdict(m) for m in evaluation.mismatches],
                        "live_scopes": list(evaluation.live_scopes),
                    },
                    request_payload_digest=request_digest,
                    arguments_json=dict(request.arguments),
                    arguments_digest=payload_digest(request.arguments),
                    attempted_at=utcnow(),
                )
                session.add(attempt)
                if commands:
                    for applicable_command in commands:
                        mismatch = next(
                            (
                                item
                                for item in evaluation.mismatches
                                if item.scope_id == applicable_command.target_scope_id
                            ),
                            None,
                        )
                        if mismatch is None or mismatch.live_version is None or mismatch.live_status is None:
                            continue
                        session.add(
                            ActionCommandMatch(
                                run_id=node.run_id,
                                action_id=attempt.id,
                                command_id=applicable_command.id,
                                scope_id=mismatch.scope_id,
                                snapshot_version=mismatch.snapshot_version,
                                live_version=mismatch.live_version,
                                live_status=mismatch.live_status,
                            )
                        )

                if denial_reason is not None:
                    if denial_reason in STALE_REASONS:
                        node.status = evaluation.effective_status
                    for applicable_command in commands:
                        self._record_gateway_ack(
                            session,
                            node.run_id,
                            applicable_command.id,
                            node.id,
                            applicable_command.to_version,
                        )
                    session.commit()
                    self._record_metrics(request, denial_reason, started)
                    with telemetry.tracer.start_as_current_span(
                        "tracefence.action.block"
                    ) as span:
                        self._set_span(span, node, request, attempt)
                        logger.warning(
                            "action_denied run_id=%s node_id=%s action_id=%s tool_name=%s "
                            "reason_code=%s command_id=%s scope_id=%s snapshot_version=%s "
                            "live_version=%s live_status=%s",
                            node.run_id,
                            node.id,
                            attempt.id,
                            request.tool_name,
                            denial_reason,
                            attempt.matched_command_id,
                            attempt.matched_scope_id,
                            attempt.matched_snapshot_version,
                            attempt.matched_live_version,
                            attempt.matched_live_status,
                            extra={
                                "event": "action_denied",
                                "run_id": node.run_id,
                                "node_id": node.id,
                                "action_id": attempt.id,
                                "tool_name": request.tool_name,
                                "reason_code": denial_reason,
                                "command_id": attempt.matched_command_id,
                                "scope_id": attempt.matched_scope_id,
                            },
                        )
                    return self._result(attempt)

                # The persisted ALLOW row is constrained to contain its final
                # result and commit timestamp. Tool executors may query/update
                # ServiceState, which would otherwise trigger a premature ORM
                # autoflush of the incomplete action row. Keep the whole mutation
                # in one transaction and flush only after the result is attached.
                with session.no_autoflush:
                    result = spec.execute(
                        session, node.run_id, attempt.id, request.arguments
                    )
                attempt.result_json = result
                attempt.result_digest = payload_digest(result)
                attempt.committed_at = utcnow()
                session.commit()

                telemetry.action_attempts_total.add(1, {"tool_name": request.tool_name})
                telemetry.actions_allowed_total.add(1, {"tool_name": request.tool_name})
                telemetry.action_gateway_duration_ms.record(
                    (time.perf_counter() - started) * 1000,
                    {"action_decision": ActionDecision.ALLOW.value},
                )
                with telemetry.tracer.start_as_current_span(
                    "tracefence.action.execute"
                ) as span:
                    self._set_span(span, node, request, attempt)
                    logger.info(
                        "action_committed run_id=%s node_id=%s action_id=%s tool_name=%s",
                        node.run_id,
                        node.id,
                        attempt.id,
                        request.tool_name,
                        extra={
                            "event": "action_committed",
                            "run_id": node.run_id,
                            "node_id": node.id,
                            "action_id": attempt.id,
                            "tool_name": request.tool_name,
                        },
                    )
                return self._result(attempt)
            except Exception:
                session.rollback()
                raise

    @staticmethod
    def _record_gateway_ack(
        session: Session, run_id: str, command_id: str, node_id: str, observed_version: int
    ) -> None:
        existing = session.execute(
            select(CommandAcknowledgement).where(
                CommandAcknowledgement.command_id == command_id,
                CommandAcknowledgement.node_id == node_id,
                CommandAcknowledgement.ack_type == AckType.GATEWAY_BLOCK,
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                CommandAcknowledgement(
                    id=str(uuid4()),
                    run_id=run_id,
                    command_id=command_id,
                    node_id=node_id,
                    ack_type=AckType.GATEWAY_BLOCK,
                    observed_at=utcnow(),
                    observed_scope_version=observed_version,
                )
            )

    @staticmethod
    def _result(attempt: ActionAttempt, *, duplicate: bool = False) -> ActionResult:
        return ActionResult(
            action_id=attempt.id,
            decision=ActionDecision(attempt.decision),
            denial_reason=attempt.denial_reason,
            committed=attempt.committed_at is not None,
            result=attempt.result_json,
            duplicate=duplicate,
        )

    @staticmethod
    def _set_span(
        span: object, node: object, request: ActionExecute, attempt: ActionAttempt
    ) -> None:
        span.set_attribute("tracefence.run.id", node.run_id)  # type: ignore[attr-defined]
        span.set_attribute("tracefence.node.id", node.id)  # type: ignore[attr-defined]
        span.set_attribute("tracefence.node.role", node.role)  # type: ignore[attr-defined]
        span.set_attribute("tracefence.action.tool", request.tool_name)  # type: ignore[attr-defined]
        span.set_attribute("tracefence.action.side_effecting", attempt.side_effecting)  # type: ignore[attr-defined]
        span.set_attribute("tracefence.action.decision", attempt.decision)  # type: ignore[attr-defined]
        if attempt.denial_reason:
            span.set_attribute("tracefence.action.denial_reason", attempt.denial_reason)  # type: ignore[attr-defined]
        if attempt.matched_command_id:
            span.set_attribute("tracefence.command.id", attempt.matched_command_id)  # type: ignore[attr-defined]
        if attempt.matched_scope_id:
            span.set_attribute("tracefence.scope.id", attempt.matched_scope_id)  # type: ignore[attr-defined]
        if attempt.matched_snapshot_version is not None:
            span.set_attribute(
                "tracefence.scope.snapshot_version", attempt.matched_snapshot_version
            )  # type: ignore[attr-defined]
        if attempt.matched_live_version is not None:
            span.set_attribute(
                "tracefence.scope.live_version", attempt.matched_live_version
            )  # type: ignore[attr-defined]
        if attempt.matched_live_status:
            span.set_attribute("tracefence.scope.status", attempt.matched_live_status)  # type: ignore[attr-defined]

    @staticmethod
    def _record_metrics(request: ActionExecute, reason: str, started: float) -> None:
        attrs = {"tool_name": request.tool_name, "denial_reason": reason}
        telemetry.action_attempts_total.add(1, {"tool_name": request.tool_name})
        telemetry.actions_denied_total.add(1, attrs)
        if reason in STALE_REASONS:
            telemetry.stale_attempts_total.add(1, {"tool_name": request.tool_name})
        telemetry.action_gateway_duration_ms.record(
            (time.perf_counter() - started) * 1000,
            {"action_decision": ActionDecision.DENY.value},
        )
