from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from tracefence.db.models import (
    Node,
    Run,
    RuntimeStopIntent,
    RuntimeStopTarget,
    WorkerInstance,
    WorkerStopTask,
)
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.services.common import utcnow

CAUSE_COMMAND_CANCEL_RUN = "COMMAND_CANCEL_RUN"
CAUSE_COMMAND_CANCEL_SUBTREE = "COMMAND_CANCEL_SUBTREE"
CAUSE_COMMAND_CORRECT_SUBTREE = "COMMAND_CORRECT_SUBTREE"
CAUSE_LEASE_EXPIRED = "LEASE_EXPIRED"
CAUSE_LOGICAL_COMPLETION = "LOGICAL_COMPLETION"

DOMAIN_RUN = "RUN"
DOMAIN_SCOPE = "SCOPE"
DOMAIN_NODE = "NODE"


@dataclass(frozen=True, slots=True)
class TargetMaterialization:
    inserted: int
    batch_exhausted: bool


@dataclass(frozen=True, slots=True)
class TaskMaterialization:
    inserted: int
    batch_exhausted: bool


class RuntimeStopService:
    """Persist and discover conservative physical-stop reconciliation work.

    The service never decides semantic authority and never controls processes.
    Intent recording uses a caller-owned transaction; target materialization is
    a bounded, level-triggered SQLite writer operation.
    """

    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    @staticmethod
    def ensure_intent(
        session: Session,
        *,
        run: Run,
        cause_type: str,
        target_domain: str,
        source_command_id: str | None = None,
        source_scope_id: str | None = None,
        source_node_id: str | None = None,
    ) -> RuntimeStopIntent:
        """Insert one immutable intent after the caller's semantic writes.

        This helper deliberately does not open, commit, roll back, or close a
        transaction.  Flushing before the revision read makes the source stamp
        the final proof revision for the already-decided causal transition.
        """

        if source_command_id is not None:
            existing = session.scalar(
                select(RuntimeStopIntent).where(
                    RuntimeStopIntent.source_command_id == source_command_id
                )
            )
            if existing is not None:
                return existing

        session.flush()
        session.refresh(run, attribute_names=["proof_revision"])
        source_revision = run.proof_revision

        if source_command_id is None:
            if source_node_id is None:
                raise ConflictError(
                    "Autonomous runtime stop intent requires a source node",
                    code="RUNTIME_STOP_SOURCE_NODE_REQUIRED",
                )
            existing = session.scalar(
                select(RuntimeStopIntent).where(
                    RuntimeStopIntent.run_id == run.id,
                    RuntimeStopIntent.cause_type == cause_type,
                    RuntimeStopIntent.source_node_id == source_node_id,
                    RuntimeStopIntent.source_revision == source_revision,
                )
            )
            if existing is not None:
                return existing

        intent = RuntimeStopIntent(
            id=str(uuid4()),
            run_id=run.id,
            cause_type=cause_type,
            target_domain=target_domain,
            source_revision=source_revision,
            source_command_id=source_command_id,
            source_scope_id=source_scope_id,
            source_node_id=source_node_id,
            created_at=utcnow(),
        )
        session.add(intent)
        session.flush()
        return intent

    @staticmethod
    def _candidate_sql(*, exists_only: bool = False) -> str:
        # Phase 2A intentionally does not inspect mutable observed state or
        # terminal_revision. Phase 2B must first define a trusted terminal
        # ordering comparable with source_revision before either can omit a
        # conservative historical convergence candidate.
        predicate = """
            FROM worker_instances AS worker
            JOIN nodes AS node ON node.id = worker.node_id
            WHERE node.run_id = :run_id
              AND worker.activated_at IS NOT NULL
              AND (
                    worker.activated_revision IS NULL
                    OR worker.activated_revision <= :source_revision
              )
              AND (
                    worker.terminal_revision IS NULL
                    OR worker.terminal_revision > :source_revision
              )
              AND (
                    :target_domain = 'RUN'
                    OR (
                        :target_domain = 'SCOPE'
                        AND EXISTS (
                            SELECT 1
                            FROM json_each(node.scope_snapshot_json) AS snapshot
                            WHERE json_extract(snapshot.value, '$.scope_id')
                                  = :source_scope_id
                        )
                    )
                    OR (
                        :target_domain = 'NODE'
                        AND node.id = :source_node_id
                    )
              )
              AND NOT EXISTS (
                    SELECT 1
                    FROM runtime_stop_targets AS target
                    WHERE target.stop_intent_id = :intent_id
                      AND target.worker_instance_id = worker.id
              )
        """
        if exists_only:
            return "SELECT 1 " + predicate
        return "SELECT worker.id " + predicate + " ORDER BY worker.id LIMIT :batch_size"

    @staticmethod
    def _params(intent: RuntimeStopIntent, *, batch_size: int | None = None) -> dict:
        params = {
            "intent_id": intent.id,
            "run_id": intent.run_id,
            "source_revision": intent.source_revision,
            "target_domain": intent.target_domain,
            "source_scope_id": intent.source_scope_id,
            "source_node_id": intent.source_node_id,
        }
        if batch_size is not None:
            params["batch_size"] = batch_size
        return params

    async def materialize_targets(
        self,
        *,
        intent_id: str,
        batch_size: int,
    ) -> TargetMaterialization:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                intent = session.get(RuntimeStopIntent, intent_id)
                if intent is None:
                    raise NotFoundError(f"Runtime stop intent {intent_id} was not found")
                worker_ids = list(
                    session.execute(
                        text(self._candidate_sql()),
                        self._params(intent, batch_size=batch_size),
                    ).scalars()
                )
                for worker_id in worker_ids:
                    session.add(
                        RuntimeStopTarget(
                            id=str(uuid4()),
                            stop_intent_id=intent.id,
                            worker_instance_id=str(worker_id),
                            created_at=utcnow(),
                        )
                    )
                session.commit()
            except Exception:
                session.rollback()
                raise
        return TargetMaterialization(
            inserted=len(worker_ids),
            batch_exhausted=len(worker_ids) == batch_size,
        )

    async def pending_intent_ids(self, *, limit: int) -> list[str]:
        if limit < 1:
            raise ValueError("limit must be positive")
        with self.session_factory() as session:
            # The EXISTS predicate makes completed older intents invisible to
            # discovery, so they cannot starve later unfinished work.
            rows = session.execute(
                text(
                    """
                    SELECT intent.id
                    FROM runtime_stop_intents AS intent
                    WHERE EXISTS (
                        SELECT 1
                        FROM worker_instances AS worker
                        JOIN nodes AS node ON node.id = worker.node_id
                        WHERE node.run_id = intent.run_id
                          AND worker.activated_at IS NOT NULL
                          AND (
                                worker.activated_revision IS NULL
                                OR worker.activated_revision <= intent.source_revision
                          )
                          AND (
                                worker.terminal_revision IS NULL
                                OR worker.terminal_revision > intent.source_revision
                          )
                          AND (
                                intent.target_domain = 'RUN'
                                OR (
                                    intent.target_domain = 'SCOPE'
                                    AND EXISTS (
                                        SELECT 1
                                        FROM json_each(node.scope_snapshot_json) AS snapshot
                                        WHERE json_extract(snapshot.value, '$.scope_id')
                                              = intent.source_scope_id
                                    )
                                )
                                OR (
                                    intent.target_domain = 'NODE'
                                    AND node.id = intent.source_node_id
                                )
                          )
                          AND NOT EXISTS (
                                SELECT 1
                                FROM runtime_stop_targets AS target
                                WHERE target.stop_intent_id = intent.id
                                  AND target.worker_instance_id = worker.id
                          )
                    )
                    ORDER BY intent.created_at, intent.id
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            )
            return [str(intent_id) for intent_id in rows.scalars()]


    async def materialize_tasks(self, *, batch_size: int, now: datetime | None = None) -> TaskMaterialization:
        """Create one bounded, immutable-identity task per targeted WorkerInstance."""

        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        observed_at = now or utcnow()
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                worker_ids = list(
                    session.execute(
                        text(
                            """
                            SELECT DISTINCT target.worker_instance_id
                            FROM runtime_stop_targets AS target
                            LEFT JOIN worker_stop_tasks AS task
                              ON task.worker_instance_id = target.worker_instance_id
                            WHERE task.id IS NULL
                            ORDER BY target.worker_instance_id
                            LIMIT :batch_size
                            """
                        ),
                        {"batch_size": batch_size},
                    ).scalars()
                )
                for worker_id in worker_ids:
                    worker = session.get(WorkerInstance, str(worker_id))
                    if worker is None:
                        raise NotFoundError(f"Worker instance {worker_id} was not found")
                    session.add(
                        WorkerStopTask(
                            id=str(uuid4()),
                            worker_instance_id=worker.id,
                            state="CONVERGED" if worker.terminal_revision is not None else "PENDING",
                            attempt_count=0,
                            next_attempt_at=observed_at,
                            last_attempt_at=None,
                            last_error_code=None,
                            last_error_at=None,
                            created_at=observed_at,
                            updated_at=observed_at,
                        )
                    )
                session.commit()
            except Exception:
                session.rollback()
                raise
        return TaskMaterialization(
            inserted=len(worker_ids),
            batch_exhausted=len(worker_ids) == batch_size,
        )

    async def record_trusted_terminal(
        self,
        *,
        worker_instance_id: str,
        terminal_state: str,
        now: datetime | None = None,
    ) -> bool:
        """Stamp one trusted physical terminal observation in Run revision order."""

        if terminal_state not in {"EXITED", "FAILED"}:
            raise ValueError("terminal_state must be EXITED or FAILED")
        observed_at = now or utcnow()
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                worker = session.get(WorkerInstance, worker_instance_id)
                if worker is None:
                    raise NotFoundError(f"Worker instance {worker_instance_id} was not found")
                if worker.terminal_revision is not None:
                    session.commit()
                    return False
                node = session.get(Node, worker.node_id)
                if node is None:
                    raise NotFoundError(f"Node {worker.node_id} was not found")
                run = session.get(Run, node.run_id)
                if run is None:
                    raise NotFoundError(f"Run {node.run_id} was not found")
                if worker.observed_state in {"EXITED", "FAILED"}:
                    final_state = worker.observed_state
                elif worker.observed_state == "ACTIVE":
                    final_state = terminal_state
                    worker.observed_state = final_state
                    worker.terminal_at = observed_at
                elif worker.observed_state == "PENDING":
                    final_state = "FAILED"
                    worker.observed_state = final_state
                    worker.terminal_at = observed_at
                else:
                    raise ConflictError(
                        "Worker instance cannot accept trusted terminal observation",
                        code="WORKER_TERMINAL_STATE_INVALID",
                    )
                session.flush()
                run.proof_revision += 1
                session.flush()
                session.refresh(run, attribute_names=["proof_revision"])
                worker.terminal_revision = run.proof_revision
                task = session.scalar(
                    select(WorkerStopTask).where(
                        WorkerStopTask.worker_instance_id == worker.id
                    )
                )
                if task is not None and task.state != "CONVERGED":
                    if task.state == "PENDING":
                        task.state = "STOP_REQUESTED"
                        session.flush()
                    task.state = "CONVERGED"
                    task.last_error_code = None
                    task.last_error_at = None
                    task.updated_at = observed_at
                session.commit()
            except Exception:
                session.rollback()
                raise
        return True
