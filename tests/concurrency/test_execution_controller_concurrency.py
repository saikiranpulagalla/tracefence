from __future__ import annotations

import asyncio
import threading
from datetime import datetime

from sqlalchemy import select

from tests.helpers import create_v2_run
from tracefence.db.models import RuntimeStopIntent, WorkerInstance, WorkerStopTask
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.schemas import CommandCreate, Principal
from tracefence.runtime.adapter import StopRequestOutcome, TerminalObservation
from tracefence.services.control_service import ControlService
from tracefence.services.execution_controller import ExecutionController
from tracefence.services.runtime_stop_service import RuntimeStopService


class _Adapter:
    def __init__(self) -> None:
        self.requests: list[str] = []

    def request_stop(self, worker: WorkerInstance) -> StopRequestOutcome:
        self.requests.append(worker.id)
        return StopRequestOutcome.ACCEPTED

    def observe_terminal(self, worker: WorkerInstance) -> TerminalObservation:
        return TerminalObservation.RUNNING


def _cancel(node_id: str, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_RUN,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="controller concurrency",
    )


async def _prepared_task(session_factory, key: str) -> tuple[str, str]:
    run = await create_v2_run(session_factory, key)
    command = await ControlService(session_factory).issue_command(
        _cancel(run.root_node_id, key),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        intent = session.scalar(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        )
        worker = session.scalar(
            select(WorkerInstance).where(WorkerInstance.node_id == run.root_node_id)
        )
        assert intent is not None and worker is not None
    planner = RuntimeStopService(session_factory)
    await planner.materialize_targets(intent_id=intent.id, batch_size=10)
    return intent.id, worker.id


async def test_two_materializers_create_one_task(session_factory):
    intent_id, worker_id = await _prepared_task(session_factory, "task-materializer-race")
    barrier = threading.Barrier(2)

    def materialize() -> int:
        barrier.wait()
        return asyncio.run(
            RuntimeStopService(session_factory).materialize_tasks(
                batch_size=10,
                now=datetime(2026, 1, 1),
            )
        ).inserted

    first = asyncio.to_thread(materialize)
    second = asyncio.to_thread(materialize)
    results = await asyncio.gather(first, second)
    assert sorted(results) == [0, 1]
    with session_factory() as session:
        tasks = list(
            session.execute(
                select(WorkerStopTask).where(
                    WorkerStopTask.worker_instance_id == worker_id
                )
            ).scalars()
        )
        assert len(tasks) == 1
        assert tasks[0].attempt_count == 0
    assert intent_id


async def test_two_controllers_reserve_one_due_task(session_factory):
    _intent_id, worker_id = await _prepared_task(session_factory, "controller-reservation-race")
    await RuntimeStopService(session_factory).materialize_tasks(
        batch_size=10, now=datetime(2026, 1, 1)
    )
    barrier = threading.Barrier(2)

    def reserve() -> str | None:
        controller = ExecutionController(session_factory, _Adapter(), clock=lambda: datetime(2026, 1, 1))
        barrier.wait()
        work = asyncio.run(controller._reserve_next_due())
        return work.task_id if work is not None else None

    first = asyncio.to_thread(reserve)
    second = asyncio.to_thread(reserve)
    reservations = await asyncio.gather(first, second)
    assert sum(item is not None for item in reservations) == 1
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(
                WorkerStopTask.worker_instance_id == worker_id
            )
        )
        assert task is not None
        assert task.state == "STOP_REQUESTED"
        assert task.attempt_count == 1
