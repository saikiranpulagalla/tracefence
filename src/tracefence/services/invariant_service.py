from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from tracefence.db.models import (
    ActionAttempt,
    ControlCommand,
    InvariantViolation,
    Node,
    TelemetryOutbox,
)
from tracefence.domain.enums import ActionDecision, CommandType
from tracefence.services.common import iso_utc, utcnow
from tracefence.telemetry.instruments import (
    telemetry,
    update_stale_violation_gauge,
    update_telemetry_delivery_success,
)
from tracefence.telemetry.setup import force_flush_telemetry, telemetry_health

logger = logging.getLogger(__name__)

STALE_COMMIT_VIOLATION = "STALE_ACTION_COMMITTED"
STALE_COMMIT_EVENT = "tracefence.stale_action_committed"


@dataclass(frozen=True, slots=True)
class _ViolationCandidate:
    run_id: str
    command_id: str
    action_id: str
    node_id: str
    tool_name: str
    attempted_at: str
    committed_at: str


class InvariantService:
    """Persist safety violations and deliver their telemetry through an outbox."""

    def __init__(
        self,
        session_factory: sessionmaker,
        *,
        owner_id: str | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.owner_id = owner_id or f"{os.getpid()}:{uuid4()}"

    @staticmethod
    def _node_affected(command: ControlCommand, node: Node) -> bool:
        if node.registered_at > command.created_at:
            return False
        if command.command_type == CommandType.CANCEL_RUN:
            return True
        return any(
            item.get("scope_id") == command.target_scope_id
            and item.get("version") == command.from_version
            for item in (node.scope_snapshot_json or [])
        )

    def _discover_candidates(
        self,
        run_id: str | None,
    ) -> list[_ViolationCandidate]:
        candidates: list[_ViolationCandidate] = []
        with self.session_factory() as session:
            commands_query = select(ControlCommand).order_by(ControlCommand.created_at)
            if run_id is not None:
                commands_query = commands_query.where(ControlCommand.run_id == run_id)
            commands = session.execute(commands_query).scalars().all()
            for command in commands:
                nodes = session.execute(
                    select(Node).where(Node.run_id == command.run_id)
                ).scalars().all()
                affected_ids = {
                    node.id for node in nodes if self._node_affected(command, node)
                }
                if not affected_ids:
                    continue
                actions = session.execute(
                    select(ActionAttempt).where(
                        ActionAttempt.run_id == command.run_id,
                        ActionAttempt.node_id.in_(affected_ids),
                        ActionAttempt.side_effecting.is_(True),
                        ActionAttempt.decision == ActionDecision.ALLOW,
                        ActionAttempt.committed_at.is_not(None),
                        ActionAttempt.attempted_at >= command.created_at,
                    )
                ).scalars().all()
                for action in actions:
                    attempted_at = iso_utc(action.attempted_at)
                    committed_at = iso_utc(action.committed_at)
                    if attempted_at is None or committed_at is None:
                        continue
                    candidates.append(
                        _ViolationCandidate(
                            run_id=command.run_id,
                            command_id=command.id,
                            action_id=action.id,
                            node_id=action.node_id,
                            tool_name=action.tool_name,
                            attempted_at=attempted_at,
                            committed_at=committed_at,
                        )
                    )
        return candidates

    async def scan(self, run_id: str | None = None) -> int:
        created = 0
        for candidate in self._discover_candidates(run_id):
            violation_id = str(uuid4())
            details = {
                "violation_id": violation_id,
                "run_id": candidate.run_id,
                "command_id": candidate.command_id,
                "action_id": candidate.action_id,
                "node_id": candidate.node_id,
                "tool_name": candidate.tool_name,
                "attempted_at": candidate.attempted_at,
                "committed_at": candidate.committed_at,
            }
            with self.session_factory() as session:
                session.execute(text("BEGIN IMMEDIATE"))
                existing = session.execute(
                    select(InvariantViolation.id).where(
                        InvariantViolation.run_id == candidate.run_id,
                        InvariantViolation.command_id == candidate.command_id,
                        InvariantViolation.action_id == candidate.action_id,
                        InvariantViolation.violation_type == STALE_COMMIT_VIOLATION,
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    session.rollback()
                    continue
                session.add(
                        InvariantViolation(
                            id=violation_id,
                            run_id=candidate.run_id,
                            command_id=candidate.command_id,
                            action_id=candidate.action_id,
                            violation_type=STALE_COMMIT_VIOLATION,
                            details_json=details,
                            detected_at=utcnow(),
                        )
                    )
                session.add(
                        TelemetryOutbox(
                            id=str(uuid4()),
                            event_key=(
                                f"stale-commit:{candidate.command_id}:"
                                f"{candidate.action_id}"
                            ),
                            run_id=candidate.run_id,
                            event_type=STALE_COMMIT_EVENT,
                            payload_json=details,
                            created_at=utcnow(),
                        )
                    )
                try:
                    session.commit()
                    created += 1
                except IntegrityError:
                    session.rollback()
        with self.session_factory() as session:
            persistent_count = int(
                session.scalar(select(func.count(InvariantViolation.id))) or 0
            )
        update_stale_violation_gauge(persistent_count)
        return created

    def _claim_pending(self, limit: int) -> list[str]:
        now = utcnow()
        claim_expires = now + timedelta(seconds=30)
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            rows = session.execute(
                select(TelemetryOutbox)
                .where(
                    TelemetryOutbox.delivered_at.is_(None),
                    or_(
                        TelemetryOutbox.next_attempt_at.is_(None),
                        TelemetryOutbox.next_attempt_at <= now,
                    ),
                    or_(
                        TelemetryOutbox.claim_owner.is_(None),
                        TelemetryOutbox.claim_expires_at <= now,
                    ),
                )
                .order_by(TelemetryOutbox.created_at)
                .limit(limit)
            ).scalars().all()
            claimed_ids: list[str] = []
            for row in rows:
                row.claim_owner = self.owner_id
                row.claim_expires_at = claim_expires
                row.last_attempt_at = now
                row.attempts += 1
                claimed_ids.append(row.id)
            session.commit()
            return claimed_ids

    async def deliver_pending(self, limit: int = 100) -> int:
        """Export pending invariant events with at-least-once delivery semantics.

        Export and force-flush happen outside SQLite's write lock so a slow OTLP
        endpoint cannot delay command or action admission. The row is marked
        delivered only after the SDK confirms a flush. A crash after export but
        before acknowledgement may duplicate the metric/log on retry; the stable
        event key lets downstream log queries deduplicate, and the safety alert is
        intentionally thresholded as ``> 0``.
        """
        health = telemetry_health()
        if health["status"] != "READY":
            return 0

        pending_ids = self._claim_pending(limit)

        delivered = 0
        for row_id in pending_ids:
            with self.session_factory() as session:
                row = session.get(TelemetryOutbox, row_id)
                if (
                    row is None
                    or row.delivered_at is not None
                    or row.claim_owner != self.owner_id
                ):
                    continue
                event_type = row.event_type
                event_key = row.event_key
                run_id = row.run_id
                payload = dict(row.payload_json or {})

            try:
                if event_type != STALE_COMMIT_EVENT:
                    raise RuntimeError(f"Unknown outbox event type: {event_type}")
                telemetry.stale_committed_total.add(1)
                logger.critical(
                    "stale_action_committed event_key=%s run_id=%s command_id=%s "
                    "action_id=%s node_id=%s tool_name=%s",
                    event_key,
                    run_id,
                    payload.get("command_id"),
                    payload.get("action_id"),
                    payload.get("node_id"),
                    payload.get("tool_name"),
                    extra={
                        "event": "stale_action_committed",
                        "event_key": event_key,
                        **payload,
                    },
                )
                if not force_flush_telemetry():
                    raise RuntimeError("Telemetry exporters did not flush the outbox event")

                with self.session_factory() as session:
                    session.execute(text("BEGIN IMMEDIATE"))
                    current = session.get(TelemetryOutbox, row_id)
                    if (
                        current is None
                        or current.delivered_at is not None
                        or current.claim_owner != self.owner_id
                    ):
                        session.rollback()
                        continue
                    current.delivered_at = utcnow()
                    current.last_error = None
                    current.next_attempt_at = None
                    current.claim_owner = None
                    current.claim_expires_at = None
                    session.commit()
                    delivered += 1
                    update_telemetry_delivery_success(
                        int(current.delivered_at.timestamp())
                    )
            except Exception as exc:  # pragma: no cover - branch tested through state
                with self.session_factory() as session:
                    session.execute(text("BEGIN IMMEDIATE"))
                    failed = session.get(TelemetryOutbox, row_id)
                    if (
                        failed is not None
                        and failed.delivered_at is None
                        and failed.claim_owner == self.owner_id
                    ):
                        failed.last_error = f"{type(exc).__name__}: {exc}"[:1000]
                        backoff_seconds = min(300, 2 ** min(failed.attempts, 8))
                        failed.next_attempt_at = utcnow() + timedelta(
                            seconds=backoff_seconds
                        )
                        failed.claim_owner = None
                        failed.claim_expires_at = None
                        session.commit()
                    else:
                        session.rollback()
                logger.exception("Telemetry outbox delivery failed for %s", event_key)
        return delivered

    async def pending_count(self) -> int:
        with self.session_factory() as session:
            return int(
                session.scalar(
                    select(func.count(TelemetryOutbox.id)).where(
                        TelemetryOutbox.delivered_at.is_(None)
                    )
                )
                or 0
            )
