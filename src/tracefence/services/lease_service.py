from __future__ import annotations

import logging
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from tracefence.config import settings
from tracefence.db.models import (
    ActionAttempt,
    ActionCommandMatch,
    CommandAcknowledgement,
    Node,
    Run,
    SpawnIntent,
)
from tracefence.domain.enums import AckType, NodeStatus, RunStatus
from tracefence.services.common import commands_for_scope_mismatches, evaluate_scopes, utcnow
from tracefence.services.run_lifecycle import transition_run
from tracefence.telemetry.instruments import telemetry, update_runtime_gauges

logger = logging.getLogger(__name__)


class LeaseService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def expire_stale_nodes(self, run_id: str | None = None) -> int:
        now = utcnow()
        expired = 0
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                query = select(Node).where(
                    Node.status.in_([NodeStatus.ACTIVE, NodeStatus.WAITING]),
                    Node.lease_expires_at.is_not(None),
                    Node.lease_expires_at < now,
                )
                if run_id is not None:
                    query = query.where(Node.run_id == run_id)
                nodes = session.execute(query).scalars().all()

                pending_query = (
                    select(Node)
                    .join(SpawnIntent, SpawnIntent.child_node_id == Node.id)
                    .where(
                        Node.status == NodeStatus.PENDING,
                        SpawnIntent.consumed_at.is_(None),
                        SpawnIntent.expires_at < now,
                    )
                )
                if run_id is not None:
                    pending_query = pending_query.where(Node.run_id == run_id)
                pending_nodes = session.execute(pending_query).scalars().all()

                for node in [*nodes, *pending_nodes]:
                    node.status = NodeStatus.LEASE_EXPIRED
                    run = session.get(Run, node.run_id)
                    if (
                        run is not None
                        and run.root_node_id == node.id
                        and run.status == RunStatus.RUNNING
                    ):
                        transition_run(
                            session,
                            run,
                            RunStatus.FAILED,
                            finished_at=now,
                        )
                    evaluation = await evaluate_scopes(session, node)
                    commands = await commands_for_scope_mismatches(
                        session, evaluation.mismatches, run_id=node.run_id
                    )
                    for command in commands:
                        existing = session.execute(
                            select(CommandAcknowledgement).where(
                                CommandAcknowledgement.command_id == command.id,
                                CommandAcknowledgement.node_id == node.id,
                                CommandAcknowledgement.ack_type == AckType.LEASE_EXPIRED,
                            )
                        ).scalar_one_or_none()
                        if existing is None:
                            session.add(
                                CommandAcknowledgement(
                                    id=str(uuid4()),
                                    run_id=node.run_id,
                                    command_id=command.id,
                                    node_id=node.id,
                                    ack_type=AckType.LEASE_EXPIRED,
                                    observed_at=now,
                                    observed_scope_version=command.to_version,
                                )
                            )
                    expired += 1
                session.commit()
            except Exception:
                session.rollback()
                raise

        if expired:
            telemetry.leases_expired_total.add(expired)
            logger.warning("leases_expired count=%s", expired)
        await self.refresh_runtime_gauges()
        return expired

    async def refresh_runtime_gauges(self) -> None:
        now = utcnow()
        active_nodes = 0
        live_affected_nodes = 0
        unacknowledged = 0
        orphan_nodes = 0
        with self.session_factory() as session:
            nodes = session.execute(
                select(Node).where(
                    Node.status.in_([NodeStatus.ACTIVE, NodeStatus.WAITING]),
                    Node.lease_expires_at.is_not(None),
                    Node.lease_expires_at > now,
                )
            ).scalars().all()
            for node in nodes:
                evaluation = await evaluate_scopes(session, node)
                if evaluation.allowed:
                    active_nodes += 1
                    continue
                live_affected_nodes += 1
                commands = await commands_for_scope_mismatches(
                    session, evaluation.mismatches, run_id=node.run_id
                )
                unresolved = []
                for command in commands:
                    ack = session.execute(
                        select(CommandAcknowledgement.id).where(
                            CommandAcknowledgement.command_id == command.id,
                            CommandAcknowledgement.node_id == node.id,
                        ).limit(1)
                    ).scalar_one_or_none()
                    blocked = session.execute(
                        select(ActionCommandMatch.action_id)
                        .join(ActionAttempt, ActionAttempt.id == ActionCommandMatch.action_id)
                        .where(
                            ActionCommandMatch.command_id == command.id,
                            ActionAttempt.node_id == node.id,
                            ActionAttempt.decision == "DENY",
                        )
                        .limit(1)
                    ).scalar_one_or_none()
                    if ack is None and blocked is None:
                        unresolved.append(command)
                if not commands or unresolved:
                    unacknowledged += 1
                    if unresolved and any(
                        (now - command.created_at).total_seconds()
                        >= settings.control_convergence_slo_seconds
                        for command in unresolved
                    ):
                        orphan_nodes += 1

        update_runtime_gauges(
            active_nodes=active_nodes,
            live_affected_nodes=live_affected_nodes,
            unacknowledged_live_nodes=unacknowledged,
            orphan_nodes=orphan_nodes,
        )
