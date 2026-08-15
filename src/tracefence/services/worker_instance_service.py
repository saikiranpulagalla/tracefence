from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from tracefence.db.models import WorkerInstance
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.services.common import get_node, utcnow


class WorkerInstanceService:
    """Persist physical worker incarnations without granting them authority."""

    _ALLOWED_TRANSITIONS = {
        "PENDING": frozenset({"ACTIVE", "FAILED"}),
        "ACTIVE": frozenset({"EXITED", "FAILED"}),
        "EXITED": frozenset(),
        "FAILED": frozenset(),
    }

    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    @classmethod
    def validate_transition(cls, current_state: str, target_state: str) -> None:
        if target_state not in cls._ALLOWED_TRANSITIONS.get(current_state, frozenset()):
            raise ConflictError(
                f"Worker instance transition {current_state} -> {target_state} is invalid",
                code="WORKER_INSTANCE_TRANSITION_INVALID",
            )

    async def create_pending_instance(
        self,
        *,
        instance_id: str,
        node_id: str,
        incarnation: int,
        created_at: datetime | None = None,
    ) -> WorkerInstance:
        """Store a caller-provided incarnation; allocation stays with Phase 1B."""
        with self.session_factory() as session, session.begin():
            await get_node(session, node_id)
            instance = WorkerInstance(
                id=instance_id,
                node_id=node_id,
                incarnation=incarnation,
                observed_state="PENDING",
                created_at=created_at or utcnow(),
            )
            session.add(instance)
            session.flush()
        return instance

    async def get_instance(self, instance_id: str) -> WorkerInstance:
        with self.session_factory() as session:
            instance: WorkerInstance | None = session.get(WorkerInstance, instance_id)
            if instance is None:
                raise NotFoundError(f"Worker instance {instance_id} was not found")
            return instance

    async def list_instances_for_node(self, node_id: str) -> list[WorkerInstance]:
        with self.session_factory() as session:
            return list(
                session.execute(
                    select(WorkerInstance)
                    .where(WorkerInstance.node_id == node_id)
                    .order_by(WorkerInstance.incarnation)
                ).scalars()
            )

    async def transition_observed_state(
        self,
        instance_id: str,
        target_state: str,
        *,
        observed_at: datetime | None = None,
    ) -> WorkerInstance:
        now = observed_at or utcnow()
        with self.session_factory() as session, session.begin():
            instance: WorkerInstance | None = session.get(WorkerInstance, instance_id)
            if instance is None:
                raise NotFoundError(f"Worker instance {instance_id} was not found")
            self.validate_transition(instance.observed_state, target_state)
            instance.observed_state = target_state
            if target_state == "ACTIVE":
                instance.activated_at = now
            else:
                instance.terminal_at = now
            session.flush()
        return instance
