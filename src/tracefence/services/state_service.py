from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from tracefence.db.models import (
    ActionAttempt,
    ControlCommand,
    InvariantViolation,
    Node,
    ServiceState,
)
from tracefence.domain.errors import ConflictError
from tracefence.services.common import get_run, iso_utc, utcnow


class StateService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def seed_scenario(self, run_id: str) -> None:
        """Initialize the deterministic fixture exactly once before execution starts.

        Resetting mutable state after commands or actions destroys causal history and
        can make a proof describe a state that no longer exists. The fixture endpoint
        therefore behaves as one-shot initialization, never as a reset operation.
        """
        with self.session_factory() as session, session.begin():
            run = await get_run(session, run_id)
            existing_states = session.scalar(
                select(func.count(ServiceState.service_name)).where(
                    ServiceState.run_id == run_id
                )
            ) or 0
            non_root_nodes = session.scalar(
                select(func.count(Node.id)).where(
                    Node.run_id == run_id,
                    Node.id != run.root_node_id,
                )
            ) or 0
            command_count = session.scalar(
                select(func.count(ControlCommand.id)).where(
                    ControlCommand.run_id == run_id
                )
            ) or 0
            action_count = session.scalar(
                select(func.count(ActionAttempt.id)).where(
                    ActionAttempt.run_id == run_id
                )
            ) or 0
            if existing_states:
                raise ConflictError(
                    "Scenario state is already initialized and cannot be reset",
                    code="SCENARIO_ALREADY_INITIALIZED",
                )
            if non_root_nodes or command_count or action_count:
                raise ConflictError(
                    "Scenario state must be initialized before spawning or executing",
                    code="SCENARIO_INITIALIZATION_TOO_LATE",
                )

            defaults = {
                "postgres": "healthy",
                "redis": "connection_pool_exhausted",
                "checkout": "degraded",
            }
            now = utcnow()
            for name, status in defaults.items():
                session.add(
                    ServiceState(
                        run_id=run_id,
                        service_name=name,
                        status=status,
                        restart_count=0,
                        pool_reset_count=0,
                        updated_at=now,
                    )
                )

    async def list_states(self, run_id: str) -> list[dict]:
        with self.session_factory() as session:
            await get_run(session, run_id)
            rows = session.execute(
                select(ServiceState)
                .where(ServiceState.run_id == run_id)
                .order_by(ServiceState.service_name)
            ).scalars()
            return [
                {
                    "run_id": row.run_id,
                    "service_name": row.service_name,
                    "status": row.status,
                    "restart_count": row.restart_count,
                    "pool_reset_count": row.pool_reset_count,
                    "last_action_id": row.last_action_id,
                    "updated_at": iso_utc(row.updated_at),
                }
                for row in rows
            ]

    async def list_actions(self, run_id: str) -> list[dict]:
        with self.session_factory() as session:
            await get_run(session, run_id)
            rows = session.execute(
                select(ActionAttempt)
                .where(ActionAttempt.run_id == run_id)
                .order_by(ActionAttempt.attempted_at)
            ).scalars()
            return [
                {
                    "id": row.id,
                    "node_id": row.node_id,
                    "tool_name": row.tool_name,
                    "side_effecting": row.side_effecting,
                    "idempotency_key": row.idempotency_key,
                    "decision": row.decision,
                    "denial_reason": row.denial_reason,
                    "matched_command_id": row.matched_command_id,
                    "matched_scope_id": row.matched_scope_id,
                    "matched_snapshot_version": row.matched_snapshot_version,
                    "matched_live_version": row.matched_live_version,
                    "matched_live_status": row.matched_live_status,
                    "request_payload_digest": row.request_payload_digest,
                    "arguments": row.arguments_json,
                    "arguments_digest": row.arguments_digest,
                    "result_digest": row.result_digest,
                    "committed": row.committed_at is not None,
                    "attempted_at": iso_utc(row.attempted_at),
                    "committed_at": iso_utc(row.committed_at),
                    "result": row.result_json,
                }
                for row in rows
            ]
    async def list_violations(self, run_id: str) -> list[dict]:
        with self.session_factory() as session:
            await get_run(session, run_id)
            rows = session.execute(
                select(InvariantViolation)
                .where(InvariantViolation.run_id == run_id)
                .order_by(InvariantViolation.detected_at)
            ).scalars()
            return [
                {
                    "id": row.id,
                    "run_id": row.run_id,
                    "command_id": row.command_id,
                    "action_id": row.action_id,
                    "violation_type": row.violation_type,
                    "details": row.details_json,
                    "detected_at": iso_utc(row.detected_at),
                }
                for row in rows
            ]
