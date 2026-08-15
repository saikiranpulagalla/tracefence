from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from tests.helpers import create_v2_run
from tracefence.db.engine import (
    ALEMBIC_HEAD,
    SCHEMA_VERSION,
    _validate_required_triggers,
    build_engine,
    init_db,
)
from tracefence.db.models import (
    RuntimeStopIntent,
    RuntimeStopTarget,
    WorkerInstance,
    WorkerStopTask,
)
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.schemas import CommandCreate, Principal
from tracefence.runtime.adapter import StopRequestOutcome, TerminalObservation
from tracefence.services.control_service import ControlService
from tracefence.services.execution_controller import ExecutionController
from tracefence.services.runtime_stop_service import (
    CAUSE_LEASE_EXPIRED,
    DOMAIN_NODE,
    RuntimeStopService,
)


@dataclass
class FakeClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


class FakeRuntimeAdapter:
    """Test-only deterministic adapter; it never resolves or uses process IDs."""

    def __init__(
        self,
        *,
        requests: list[StopRequestOutcome] | None = None,
        observations: list[TerminalObservation] | None = None,
    ) -> None:
        self.requests = deque(requests or [StopRequestOutcome.ACCEPTED])
        self.observations = deque(observations or [TerminalObservation.RUNNING])
        self.request_calls: list[str] = []
        self.observe_calls: list[str] = []

    def request_stop(self, worker_instance: WorkerInstance) -> StopRequestOutcome:
        self.request_calls.append(worker_instance.id)
        return self.requests.popleft() if self.requests else StopRequestOutcome.ACCEPTED

    def observe_terminal(self, worker_instance: WorkerInstance) -> TerminalObservation:
        self.observe_calls.append(worker_instance.id)
        return (
            self.observations.popleft()
            if self.observations
            else TerminalObservation.RUNNING
        )


def _cancel(root_node_id: str, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_RUN,
        target_node_id=root_node_id,
        reason_code="TEST",
        reason_text="execution controller test",
    )


def _alembic_config(database_path: Path):
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")
    return config


async def _intent_and_worker(session_factory, key: str):
    run = await create_v2_run(session_factory, f"controller-{key}")
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
        assert intent is not None
        assert worker is not None
        return run, intent.id, worker.id


def test_v23_migration_lifecycle_and_schema_guard(tmp_path):
    from alembic import command

    path = tmp_path / "worker-stop-v23.db"
    config = _alembic_config(path)
    command.upgrade(config, "006_schema_v22_runtime_stop_causality")
    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        names = set(connection.exec_driver_sql("SELECT name FROM sqlite_master").scalars())
    assert "worker_stop_tasks" in names
    assert "trg_worker_stop_tasks_state_transition" not in names
    engine.dispose()

    command.upgrade(config, "head")
    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        assert connection.execute(text("SELECT version FROM schema_metadata")).scalar_one() == SCHEMA_VERSION
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == ALEMBIC_HEAD
    _validate_required_triggers(engine)
    engine.dispose()

    fresh = build_engine(f"sqlite+pysqlite:///{tmp_path / 'fresh-v23.db'}")
    init_db(fresh)
    _validate_required_triggers(fresh)
    fresh.dispose()


async def test_task_materialization_is_unique_proof_neutral_and_delete_rejected(session_factory):
    run, intent_id, worker_id = await _intent_and_worker(session_factory, "task-unique")
    planner = RuntimeStopService(session_factory)
    before = None
    with session_factory() as session:
        before = session.scalar(
            select(RuntimeStopIntent.source_revision).where(RuntimeStopIntent.id == intent_id)
        )
    await planner.materialize_targets(intent_id=intent_id, batch_size=10)
    first = await planner.materialize_tasks(batch_size=10)
    second = await planner.materialize_tasks(batch_size=10)
    assert first.inserted == 1
    assert second.inserted == 0
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        assert task is not None
        assert task.state == "PENDING"
        assert session.scalar(
            select(RuntimeStopIntent.source_revision).where(RuntimeStopIntent.id == intent_id)
        ) == before
        with pytest.raises(IntegrityError, match="WORKER_STOP_TASK_DELETE_PROHIBITED"):
            session.execute(text("DELETE FROM worker_stop_tasks WHERE id = :id"), {"id": task.id})
            session.commit()
        session.rollback()


async def test_controller_accepts_then_stamps_trusted_terminal_once(session_factory):
    run, _intent_id, worker_id = await _intent_and_worker(session_factory, "terminal-once")
    clock = FakeClock(datetime(2026, 1, 1))
    adapter = FakeRuntimeAdapter(
        requests=[StopRequestOutcome.ACCEPTED],
        observations=[TerminalObservation.EXITED],
    )
    controller = ExecutionController(
        session_factory,
        adapter,
        clock=clock,
        reservation_seconds=10,
        verification_seconds=1,
    )
    first = await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert first.adapter_calls == 1
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        worker = session.get(WorkerInstance, worker_id)
        assert task is not None and task.state == "VERIFYING"
        assert worker is not None and worker.terminal_revision is None
        before = session.get(type(session.get(WorkerInstance, worker_id)), worker_id)
        assert before is not None
        revision_before_terminal = session.get(
            __import__("tracefence.db.models", fromlist=["Run"]).Run, run.run_id
        ).proof_revision
    clock.advance(1)
    second = await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert second.adapter_calls == 1
    assert adapter.request_calls == [worker_id]
    assert adapter.observe_calls == [worker_id]
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        worker = session.get(WorkerInstance, worker_id)
        current_run = session.get(__import__("tracefence.db.models", fromlist=["Run"]).Run, run.run_id)
        assert task is not None and task.state == "CONVERGED"
        assert worker is not None and worker.observed_state == "EXITED"
        assert worker.terminal_revision == revision_before_terminal + 1
        first_terminal_revision = worker.terminal_revision
    changed = await RuntimeStopService(session_factory).record_trusted_terminal(
        worker_instance_id=worker_id,
        terminal_state="FAILED",
        now=clock(),
    )
    assert changed is False
    with session_factory() as session:
        worker = session.get(WorkerInstance, worker_id)
        current_run = session.get(__import__("tracefence.db.models", fromlist=["Run"]).Run, run.run_id)
        assert worker is not None and worker.terminal_revision == first_terminal_revision
        assert current_run is not None and current_run.proof_revision == first_terminal_revision


async def test_currently_authoritative_target_blocks_without_adapter(session_factory):
    run = await create_v2_run(session_factory, "controller-authority")
    clock = FakeClock(datetime(2026, 1, 1))
    with session_factory() as session:
        worker = session.scalar(
            select(WorkerInstance).where(WorkerInstance.node_id == run.root_node_id)
        )
        assert worker is not None
        node = session.get(__import__("tracefence.db.models", fromlist=["Node"]).Node, run.root_node_id)
        current_run = session.get(__import__("tracefence.db.models", fromlist=["Run"]).Run, run.run_id)
        assert node is not None and current_run is not None
        session.execute(text("BEGIN IMMEDIATE"))
        intent = RuntimeStopService.ensure_intent(
            session,
            run=current_run,
            cause_type=CAUSE_LEASE_EXPIRED,
            target_domain=DOMAIN_NODE,
            source_node_id=node.id,
        )
        session.commit()
    planner = RuntimeStopService(session_factory)
    await planner.materialize_targets(intent_id=intent.id, batch_size=10)
    adapter = FakeRuntimeAdapter()
    controller = ExecutionController(session_factory, adapter, clock=clock)
    await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert adapter.request_calls == []
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker.id)
        )
        assert task is not None and task.state == "BLOCKED"
        assert task.last_error_code == "CURRENT_AUTHORITY_VALID"


async def test_terminal_before_source_excludes_future_target(session_factory):
    run = await create_v2_run(session_factory, "terminal-before-source")
    with session_factory() as session:
        worker = session.scalar(
            select(WorkerInstance).where(WorkerInstance.node_id == run.root_node_id)
        )
        assert worker is not None
        worker_id = worker.id
    assert await RuntimeStopService(session_factory).record_trusted_terminal(
        worker_instance_id=worker_id,
        terminal_state="EXITED",
        now=datetime(2026, 1, 1),
    )
    command = await ControlService(session_factory).issue_command(
        _cancel(run.root_node_id, "terminal-before-source-command"),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        intent = session.scalar(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        )
        worker = session.get(WorkerInstance, worker_id)
        assert intent is not None and worker is not None
        assert worker.terminal_revision is not None
        assert worker.terminal_revision < intent.source_revision
    result = await RuntimeStopService(session_factory).materialize_targets(
        intent_id=intent.id, batch_size=10
    )
    assert result.inserted == 0


async def test_source_before_terminal_retains_historical_target(session_factory):
    run, intent_id, worker_id = await _intent_and_worker(session_factory, "source-before-terminal")
    with session_factory() as session:
        intent = session.get(RuntimeStopIntent, intent_id)
        assert intent is not None
        source_revision = intent.source_revision
    assert await RuntimeStopService(session_factory).record_trusted_terminal(
        worker_instance_id=worker_id,
        terminal_state="EXITED",
        now=datetime(2026, 1, 1),
    )
    with session_factory() as session:
        worker = session.get(WorkerInstance, worker_id)
        assert worker is not None and worker.terminal_revision is not None
        assert source_revision < worker.terminal_revision
    result = await RuntimeStopService(session_factory).materialize_targets(
        intent_id=intent_id, batch_size=10
    )
    assert result.inserted == 1
    with session_factory() as session:
        assert session.scalar(
            select(RuntimeStopTarget).where(
                RuntimeStopTarget.stop_intent_id == intent_id,
                RuntimeStopTarget.worker_instance_id == worker_id,
            )
        ) is not None


async def test_existing_target_gets_converged_task_without_stop_request(session_factory):
    _run, intent_id, worker_id = await _intent_and_worker(session_factory, "target-already-terminal")
    planner = RuntimeStopService(session_factory)
    assert (await planner.materialize_targets(intent_id=intent_id, batch_size=10)).inserted == 1
    assert await planner.record_trusted_terminal(
        worker_instance_id=worker_id,
        terminal_state="EXITED",
        now=datetime(2026, 1, 1),
    )
    created = await planner.materialize_tasks(
        batch_size=10, now=datetime(2026, 1, 2)
    )
    assert created.inserted == 1
    adapter = FakeRuntimeAdapter()
    controller = ExecutionController(session_factory, adapter, clock=FakeClock(datetime(2026, 1, 2)))
    await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert adapter.request_calls == []
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        assert task is not None and task.state == "CONVERGED"


async def test_reservation_survives_crash_and_is_retried_after_expiry(session_factory):
    _run, intent_id, worker_id = await _intent_and_worker(session_factory, "reservation-crash")
    clock = FakeClock(datetime(2026, 1, 1))
    planner = RuntimeStopService(session_factory)
    await planner.materialize_targets(intent_id=intent_id, batch_size=10)
    await planner.materialize_tasks(batch_size=10, now=clock())
    first = ExecutionController(
        session_factory,
        FakeRuntimeAdapter(),
        clock=clock,
        reservation_seconds=10,
    )
    reserved = await first._reserve_next_due()
    assert reserved is not None
    second_adapter = FakeRuntimeAdapter(requests=[StopRequestOutcome.ACCEPTED])
    second = ExecutionController(
        session_factory,
        second_adapter,
        clock=clock,
        reservation_seconds=10,
    )
    await second.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert second_adapter.request_calls == []
    clock.advance(10)
    await second.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert second_adapter.request_calls == [worker_id]


@pytest.mark.parametrize(
    ("outcome", "expected_state"),
    [
        (StopRequestOutcome.RETRYABLE_ERROR, "PENDING"),
        (StopRequestOutcome.UNKNOWN, "PENDING"),
        (StopRequestOutcome.UNSUPPORTED, "BLOCKED"),
        (StopRequestOutcome.PERMANENT_ERROR, "BLOCKED"),
    ],
)
async def test_stop_request_outcomes_never_claim_terminal(
    session_factory, outcome, expected_state
):
    _run, _intent_id, worker_id = await _intent_and_worker(
        session_factory, f"outcome-{outcome.value}"
    )
    clock = FakeClock(datetime(2026, 1, 1))
    controller = ExecutionController(
        session_factory,
        FakeRuntimeAdapter(requests=[outcome]),
        clock=clock,
    )
    await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        worker = session.get(WorkerInstance, worker_id)
        assert task is not None and task.state == expected_state
        assert worker is not None and worker.terminal_revision is None



@pytest.mark.parametrize(
    ("observation", "expected_state", "error_prefix"),
    [
        (TerminalObservation.RUNNING, "VERIFYING", None),
        (TerminalObservation.UNKNOWN, "VERIFYING", "TERMINAL_OBSERVE_UNKNOWN"),
        (
            TerminalObservation.RETRYABLE_ERROR,
            "VERIFYING",
            "TERMINAL_OBSERVE_RETRYABLE_ERROR",
        ),
        (
            TerminalObservation.PERMANENT_ERROR,
            "BLOCKED",
            "TERMINAL_OBSERVE_PERMANENT_ERROR",
        ),
    ],
)
async def test_terminal_observation_outcomes_are_nonterminal_until_trusted(
    session_factory, observation, expected_state, error_prefix
):
    _run, _intent_id, worker_id = await _intent_and_worker(
        session_factory, f"observe-{observation.value}"
    )
    clock = FakeClock(datetime(2026, 1, 1))
    controller = ExecutionController(
        session_factory,
        FakeRuntimeAdapter(
            requests=[StopRequestOutcome.ACCEPTED],
            observations=[observation],
        ),
        clock=clock,
        reservation_seconds=1,
        verification_seconds=1,
    )
    await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    clock.advance(1)
    await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        worker = session.get(WorkerInstance, worker_id)
        assert task is not None and task.state == expected_state
        assert task.last_error_code == error_prefix
        assert worker is not None and worker.terminal_revision is None


async def test_already_terminal_requires_trusted_observation_before_convergence(session_factory):
    _run, _intent_id, worker_id = await _intent_and_worker(
        session_factory, "already-terminal-observation"
    )
    controller = ExecutionController(
        session_factory,
        FakeRuntimeAdapter(
            requests=[StopRequestOutcome.ALREADY_TERMINAL],
            observations=[TerminalObservation.FAILED],
        ),
        clock=FakeClock(datetime(2026, 1, 1)),
    )
    tick = await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert tick.adapter_calls == 1
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        worker = session.get(WorkerInstance, worker_id)
        assert task is not None and task.state == "CONVERGED"
        assert worker is not None and worker.observed_state == "FAILED"
        assert worker.terminal_revision is not None


async def test_adapter_result_crash_retries_at_least_once_after_reservation(session_factory, monkeypatch):
    _run, _intent_id, worker_id = await _intent_and_worker(
        session_factory, "adapter-result-crash"
    )
    clock = FakeClock(datetime(2026, 1, 1))
    first_adapter = FakeRuntimeAdapter(requests=[StopRequestOutcome.ACCEPTED])
    first = ExecutionController(
        session_factory,
        first_adapter,
        clock=clock,
        reservation_seconds=10,
    )

    async def crash_after_adapter(_task_id: str, error_code: str | None = None) -> None:
        assert error_code is None
        raise RuntimeError("simulated crash after external adapter result")

    monkeypatch.setattr(first, "_set_verifying", crash_after_adapter)
    with pytest.raises(RuntimeError, match="simulated crash"):
        await first.tick(
            target_materialization_limit=10,
            target_batch_size=10,
            task_materialization_limit=10,
            task_execution_limit=10,
        )
    assert first_adapter.request_calls == [worker_id]
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        assert task is not None and task.state == "STOP_REQUESTED"

    clock.advance(10)
    resumed_adapter = FakeRuntimeAdapter(requests=[StopRequestOutcome.ACCEPTED])
    resumed = ExecutionController(
        session_factory,
        resumed_adapter,
        clock=clock,
        reservation_seconds=10,
    )
    await resumed.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert resumed_adapter.request_calls == [worker_id]
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        assert task is not None and task.state == "VERIFYING"


async def test_controller_tick_is_bounded_and_rescans_remaining_tasks(session_factory):
    first_run, _first_intent, first_worker = await _intent_and_worker(
        session_factory, "bounded-first"
    )
    second_run, _second_intent, second_worker = await _intent_and_worker(
        session_factory, "bounded-second"
    )
    assert first_run.run_id != second_run.run_id
    adapter = FakeRuntimeAdapter(
        requests=[StopRequestOutcome.ACCEPTED, StopRequestOutcome.ACCEPTED]
    )
    clock = FakeClock(datetime(2026, 1, 1))
    controller = ExecutionController(session_factory, adapter, clock=clock)

    first = await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=1,
    )
    assert first.adapter_calls == 1
    assert len(adapter.request_calls) == 1
    with session_factory() as session:
        tasks = list(session.execute(select(WorkerStopTask)).scalars())
        assert {task.worker_instance_id for task in tasks} == {
            first_worker,
            second_worker,
        }

    second = await controller.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=1,
    )
    assert second.adapter_calls == 1
    assert set(adapter.request_calls) == {first_worker, second_worker}


async def test_converged_task_is_not_reexecuted_after_controller_restart(session_factory):
    _run, _intent_id, worker_id = await _intent_and_worker(
        session_factory, "restart-after-terminal"
    )
    clock = FakeClock(datetime(2026, 1, 1))
    initial = ExecutionController(
        session_factory,
        FakeRuntimeAdapter(
            requests=[StopRequestOutcome.ACCEPTED],
            observations=[TerminalObservation.EXITED],
        ),
        clock=clock,
        verification_seconds=1,
    )
    await initial.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    clock.advance(1)
    await initial.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )

    restarted_adapter = FakeRuntimeAdapter()
    restarted = ExecutionController(session_factory, restarted_adapter, clock=clock)
    await restarted.tick(
        target_materialization_limit=10,
        target_batch_size=10,
        task_materialization_limit=10,
        task_execution_limit=10,
    )
    assert restarted_adapter.request_calls == []
    assert restarted_adapter.observe_calls == []
    with session_factory() as session:
        task = session.scalar(
            select(WorkerStopTask).where(WorkerStopTask.worker_instance_id == worker_id)
        )
        assert task is not None and task.state == "CONVERGED"
