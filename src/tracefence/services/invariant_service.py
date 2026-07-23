from __future__ import annotations

import logging
from uuid import uuid4

from sqlalchemy import func, select, text
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
from tracefence.telemetry.instruments import telemetry
from tracefence.telemetry.setup import force_flush_telemetry, telemetry_health

logger = logging.getLogger(__name__)

STALE_COMMIT_VIOLATION = "STALE_ACTION_COMMITTED"
STALE_COMMIT_EVENT = "tracefence.stale_action_committed"


class InvariantService:
    """Persist safety violations and deliver their telemetry through an outbox."""

    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

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

    async def scan(self, run_id: str | None = None) -> int:
        created = 0
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
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
                    existing = session.execute(
                        select(InvariantViolation.id).where(
                            InvariantViolation.run_id == command.run_id,
                            InvariantViolation.command_id == command.id,
                            InvariantViolation.action_id == action.id,
                            InvariantViolation.violation_type == STALE_COMMIT_VIOLATION,
                        )
                    ).scalar_one_or_none()
                    if existing is not None:
                        continue
                    violation_id = str(uuid4())
                    event_key = f"stale-commit:{command.id}:{action.id}"
                    details = {
                        "violation_id": violation_id,
                        "run_id": command.run_id,
                        "command_id": command.id,
                        "action_id": action.id,
                        "node_id": action.node_id,
                        "tool_name": action.tool_name,
                        "attempted_at": iso_utc(action.attempted_at),
                        "committed_at": iso_utc(action.committed_at),
                    }
                    session.add(
                        InvariantViolation(
                            id=violation_id,
                            run_id=command.run_id,
                            command_id=command.id,
                            action_id=action.id,
                            violation_type=STALE_COMMIT_VIOLATION,
                            details_json=details,
                            detected_at=utcnow(),
                        )
                    )
                    session.add(
                        TelemetryOutbox(
                            id=str(uuid4()),
                            event_key=event_key,
                            run_id=command.run_id,
                            event_type=STALE_COMMIT_EVENT,
                            payload_json=details,
                            created_at=utcnow(),
                        )
                    )
                    created += 1
            try:
                session.commit()
            except IntegrityError:
                # A uniqueness race or corrupt insert rolls back the whole scan.
                # Report only durable rows; the next scanner iteration retries.
                session.rollback()
                created = 0
        return created

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

        with self.session_factory() as session:
            pending_ids = list(
                session.execute(
                    select(TelemetryOutbox.id)
                    .where(TelemetryOutbox.delivered_at.is_(None))
                    .order_by(TelemetryOutbox.created_at)
                    .limit(limit)
                ).scalars()
            )

        delivered = 0
        for row_id in pending_ids:
            with self.session_factory() as session:
                row = session.get(TelemetryOutbox, row_id)
                if row is None or row.delivered_at is not None:
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
                    if current is None or current.delivered_at is not None:
                        session.rollback()
                        continue
                    current.attempts += 1
                    current.delivered_at = utcnow()
                    current.last_error = None
                    session.commit()
                    delivered += 1
            except Exception as exc:  # pragma: no cover - branch tested through state
                with self.session_factory() as session:
                    session.execute(text("BEGIN IMMEDIATE"))
                    failed = session.get(TelemetryOutbox, row_id)
                    if failed is not None and failed.delivered_at is None:
                        failed.attempts += 1
                        failed.last_error = f"{type(exc).__name__}: {exc}"[:1000]
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
