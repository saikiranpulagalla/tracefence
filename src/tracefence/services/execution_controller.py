"""Bounded, level-triggered reconciliation of runtime-stop tasks.

This module is intentionally not wired into application lifecycle.  It performs
no process control itself; a caller supplies an idempotent RuntimeAdapter with
its own trusted runtime binding.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy import exists, select, text
from sqlalchemy.orm import Session, sessionmaker

from tracefence.db.models import Node, RuntimeStopTarget, WorkerInstance, WorkerStopTask
from tracefence.runtime.adapter import RuntimeAdapter, StopRequestOutcome, TerminalObservation
from tracefence.services.common import utcnow, validate_node_runtime_state
from tracefence.services.runtime_stop_service import RuntimeStopService


@dataclass(frozen=True, slots=True)
class ControllerTick:
    targets_materialized: int
    tasks_materialized: int
    tasks_reserved: int
    adapter_calls: int


@dataclass(frozen=True, slots=True)
class _ReservedWork:
    task_id: str
    worker_instance: WorkerInstance
    operation: Literal["REQUEST", "OBSERVE"]


class ExecutionController:
    """Stateless, bounded convergence controller with at-least-once adapter calls."""

    def __init__(
        self,
        session_factory: sessionmaker,
        adapter: RuntimeAdapter,
        *,
        clock: Callable[[], datetime] = utcnow,
        reservation_seconds: int = 30,
        verification_seconds: int = 5,
        blocked_recheck_seconds: int = 60,
    ) -> None:
        self.session_factory = session_factory
        self.adapter = adapter
        self.clock = clock
        self.reservation_seconds = reservation_seconds
        self.verification_seconds = verification_seconds
        self.blocked_recheck_seconds = blocked_recheck_seconds
        self.stop_service = RuntimeStopService(session_factory)

    async def tick(
        self,
        *,
        target_materialization_limit: int,
        target_batch_size: int,
        task_materialization_limit: int,
        task_execution_limit: int,
    ) -> ControllerTick:
        if min(
            target_materialization_limit,
            target_batch_size,
            task_materialization_limit,
            task_execution_limit,
        ) < 1:
            raise ValueError("controller limits must be positive")

        targets_materialized = 0
        for intent_id in await self.stop_service.pending_intent_ids(
            limit=target_materialization_limit
        ):
            result = await self.stop_service.materialize_targets(
                intent_id=intent_id,
                batch_size=target_batch_size,
            )
            targets_materialized += result.inserted

        tasks = await self.stop_service.materialize_tasks(
            batch_size=task_materialization_limit,
            now=self.clock(),
        )
        reserved = 0
        adapter_calls = 0
        for _ in range(task_execution_limit):
            work = await self._reserve_next_due()
            if work is None:
                break
            reserved += 1
            adapter_calls += await self._perform(work)
        return ControllerTick(
            targets_materialized=targets_materialized,
            tasks_materialized=tasks.inserted,
            tasks_reserved=reserved,
            adapter_calls=adapter_calls,
        )

    async def _reserve_next_due(self) -> _ReservedWork | None:
        now = self.clock()
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                task = session.scalar(
                    select(WorkerStopTask)
                    .where(
                        WorkerStopTask.state != "CONVERGED",
                        WorkerStopTask.next_attempt_at <= now,
                    )
                    .order_by(WorkerStopTask.next_attempt_at, WorkerStopTask.id)
                    .limit(1)
                )
                if task is None:
                    session.commit()
                    return None
                worker = session.get(WorkerInstance, task.worker_instance_id)
                if worker is None:
                    task.state = "BLOCKED"
                    self._set_error(task, "WORKER_INSTANCE_MISSING", now)
                    task.next_attempt_at = now + timedelta(
                        seconds=self.blocked_recheck_seconds
                    )
                    task.updated_at = now
                    session.commit()
                    return None
                target_exists = session.scalar(
                    select(
                        exists().where(
                            RuntimeStopTarget.worker_instance_id == worker.id
                        )
                    )
                )
                if not target_exists:
                    self._to_blocked(session, task, "CAUSAL_TARGET_MISSING", now)
                    session.commit()
                    return None
                if worker.terminal_revision is not None:
                    self._to_converged(session, task, now)
                    session.commit()
                    return None
                node = session.get(Node, worker.node_id)
                if node is None:
                    self._to_blocked(session, task, "NODE_MISSING", now)
                    session.commit()
                    return None
                allowed, _reason, _evaluation = await validate_node_runtime_state(
                    session, node
                )
                currently_authoritative = (
                    allowed
                    and node.current_worker_instance_id == worker.id
                    and worker.observed_state == "ACTIVE"
                )
                if currently_authoritative:
                    self._to_blocked(session, task, "CURRENT_AUTHORITY_VALID", now)
                    session.commit()
                    return None
                if task.state == "BLOCKED":
                    task.state = "PENDING"
                    task.next_attempt_at = now
                    task.updated_at = now
                    task.last_error_code = None
                    task.last_error_at = None
                    session.commit()
                    return None

                operation: Literal["REQUEST", "OBSERVE"]
                if task.state == "VERIFYING":
                    operation = "OBSERVE"
                else:
                    if task.state == "PENDING":
                        task.state = "STOP_REQUESTED"
                    operation = "REQUEST"
                task.attempt_count += 1
                task.last_attempt_at = now
                task.next_attempt_at = now + timedelta(seconds=self.reservation_seconds)
                task.updated_at = now
                session.commit()
                return _ReservedWork(task.id, worker, operation)
            except Exception:
                session.rollback()
                raise

    async def _perform(self, work: _ReservedWork) -> int:
        if work.operation == "REQUEST":
            try:
                outcome = self.adapter.request_stop(work.worker_instance)
            except Exception:
                outcome = StopRequestOutcome.RETRYABLE_ERROR
            if outcome in {
                StopRequestOutcome.ACCEPTED,
                StopRequestOutcome.ALREADY_TERMINAL,
            }:
                if outcome == StopRequestOutcome.ACCEPTED:
                    await self._set_verifying(work.task_id)
                    return 1
                return await self._observe(work.task_id, work.worker_instance)
            if outcome in {
                StopRequestOutcome.RETRYABLE_ERROR,
                StopRequestOutcome.UNKNOWN,
            }:
                await self._set_retryable(work.task_id, "STOP_REQUEST_" + outcome.value)
            else:
                await self._set_blocked(work.task_id, "STOP_REQUEST_" + outcome.value)
            return 1
        return await self._observe(work.task_id, work.worker_instance)

    async def _observe(self, task_id: str, worker: WorkerInstance) -> int:
        try:
            outcome = self.adapter.observe_terminal(worker)
        except Exception:
            outcome = TerminalObservation.RETRYABLE_ERROR
        if outcome in {TerminalObservation.EXITED, TerminalObservation.FAILED}:
            await self.stop_service.record_trusted_terminal(
                worker_instance_id=worker.id,
                terminal_state=outcome.value,
                now=self.clock(),
            )
        elif outcome == TerminalObservation.RUNNING:
            await self._set_verifying(task_id)
        elif outcome in {
            TerminalObservation.UNKNOWN,
            TerminalObservation.RETRYABLE_ERROR,
        }:
            await self._set_verifying(
                task_id,
                error_code="TERMINAL_OBSERVE_" + outcome.value,
            )
        else:
            await self._set_blocked(task_id, "TERMINAL_OBSERVE_" + outcome.value)
        return 1

    def _retry_delay(self, attempt_count: int) -> timedelta:
        return timedelta(seconds=min(60, 2 ** min(attempt_count, 5)))

    def _set_error(self, task: WorkerStopTask, error_code: str, now: datetime) -> None:
        task.last_error_code = error_code
        task.last_error_at = now

    def _to_blocked(
        self, session: Session, task: WorkerStopTask, error_code: str, now: datetime
    ) -> None:
        if task.state == "PENDING":
            task.state = "STOP_REQUESTED"
            session.flush()
        if task.state != "BLOCKED":
            task.state = "BLOCKED"
        self._set_error(task, error_code, now)
        task.next_attempt_at = now + timedelta(seconds=self.blocked_recheck_seconds)
        task.updated_at = now

    def _to_converged(self, session: Session, task: WorkerStopTask, now: datetime) -> None:
        if task.state == "PENDING":
            task.state = "STOP_REQUESTED"
            session.flush()
        if task.state != "CONVERGED":
            task.state = "CONVERGED"
        task.last_error_code = None
        task.last_error_at = None
        task.next_attempt_at = now
        task.updated_at = now

    async def _set_verifying(self, task_id: str, error_code: str | None = None) -> None:
        now = self.clock()
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                task = session.get(WorkerStopTask, task_id)
                if task is not None and task.state != "CONVERGED":
                    if task.state == "STOP_REQUESTED":
                        task.state = "VERIFYING"
                    self._set_error(task, error_code, now) if error_code else None
                    task.next_attempt_at = now + timedelta(seconds=self.verification_seconds)
                    task.updated_at = now
                session.commit()
            except Exception:
                session.rollback()
                raise

    async def _set_retryable(self, task_id: str, error_code: str) -> None:
        now = self.clock()
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                task = session.get(WorkerStopTask, task_id)
                if task is not None and task.state != "CONVERGED":
                    if task.state == "STOP_REQUESTED":
                        task.state = "PENDING"
                    self._set_error(task, error_code, now)
                    task.next_attempt_at = now + self._retry_delay(task.attempt_count)
                    task.updated_at = now
                session.commit()
            except Exception:
                session.rollback()
                raise

    async def _set_blocked(self, task_id: str, error_code: str) -> None:
        now = self.clock()
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                task = session.get(WorkerStopTask, task_id)
                if task is not None and task.state != "CONVERGED":
                    self._to_blocked(session, task, error_code, now)
                session.commit()
            except Exception:
                session.rollback()
                raise
