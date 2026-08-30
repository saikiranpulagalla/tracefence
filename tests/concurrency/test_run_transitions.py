from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import func, select

import tracefence.services.spawn_service as spawn_module
from tests.helpers import create_seeded_run, create_v2_run
from tracefence.db.models import ActionAttempt, ControlCommand, Node, Run
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus, RunStatus
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.lease_service import LeaseService
from tracefence.services.operation_lifecycle import OperationLifecycleService
from tracefence.services.spawn_service import SpawnService


def _cancel_request(run, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_RUN,
        target_node_id=run.root_node_id,
        reason_code="CANCEL",
        reason_text="cancel run",
    )


async def test_late_cancel_against_completed_run_preserves_terminal_state(
    session_factory,
):
    run = await create_seeded_run(session_factory, "late-cancel-completed")
    await SpawnService(session_factory).complete(run.root_node_id, run.root_token)
    with session_factory() as session:
        completed = session.get(Run, run.run_id)
        assert completed is not None
        original_finished_at = completed.finished_at

    with pytest.raises(ConflictError) as captured:
        await ControlService(session_factory).issue_command(
            _cancel_request(run, "late-cancel-command"),
            Principal(issuer_type=IssuerType.HUMAN),
        )

    assert captured.value.code == "RUN_TERMINAL_STATE"
    with session_factory() as session:
        stored = session.get(Run, run.run_id)
        command_count = session.scalar(
            select(func.count(ControlCommand.id)).where(
                ControlCommand.run_id == run.run_id
            )
        )
        assert stored is not None
        assert stored.status == RunStatus.COMPLETED
        assert stored.finished_at == original_finished_at
        assert command_count == 0


async def test_concurrent_completion_and_cancellation_have_one_terminal_winner(
    session_factory,
):
    run = await create_seeded_run(session_factory, "complete-cancel-race")
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)

    def complete():
        return asyncio.run(spawns.complete(run.root_node_id, run.root_token))

    def cancel():
        return asyncio.run(
            controls.issue_command(
                _cancel_request(run, "concurrent-cancel-command"),
                Principal(issuer_type=IssuerType.HUMAN),
            )
        )

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = await asyncio.gather(
            loop.run_in_executor(pool, complete),
            loop.run_in_executor(pool, cancel),
            return_exceptions=True,
        )

    assert sum(not isinstance(outcome, Exception) for outcome in outcomes) == 1
    loser = next(outcome for outcome in outcomes if isinstance(outcome, Exception))
    assert isinstance(loser, ConflictError)
    assert loser.code in {"RUN_NOT_ACTIVE", "RUN_TERMINAL_STATE"}
    with session_factory() as session:
        stored = session.get(Run, run.run_id)
        assert stored is not None
        assert stored.status in {RunStatus.COMPLETED, RunStatus.CANCELLED}
        assert stored.finished_at is not None


async def test_root_lease_expiry_terminalizes_running_run(session_factory):
    run = await create_seeded_run(session_factory, "root-lease-expiry")
    with session_factory() as session, session.begin():
        root = session.get(Node, run.root_node_id)
        assert root is not None
        root.lease_expires_at = utcnow() - timedelta(seconds=1)

    expired = await LeaseService(session_factory).expire_stale_nodes(run.run_id)

    assert expired == 1
    with session_factory() as session:
        stored_run = session.get(Run, run.run_id)
        root = session.get(Node, run.root_node_id)
        assert stored_run is not None
        assert root is not None
        assert stored_run.status == RunStatus.FAILED
        assert stored_run.finished_at is not None
        assert root.status == NodeStatus.LEASE_EXPIRED


def _action_request(key: str) -> ActionExecute:
    return ActionExecute(
        tool_name="restart_postgres",
        arguments={},
        idempotency_key=key,
    )


async def test_root_completion_serializes_before_later_v2_reservation(
    session_factory,
    monkeypatch,
):
    """A completion that holds the writer first prevents later authorization."""
    original_predicate = spawn_module._has_unresolved_v2_actions

    for iteration in range(25):
        run = await create_v2_run(session_factory, f"complete-first-{iteration}")
        entered = threading.Event()
        release = threading.Event()

        def ordered_predicate(
            session,
            *,
            run_id,
            worker_instance_id=None,
            expected_run_id=run.run_id,
            entered=entered,
            release=release,
        ):
            if run_id == expected_run_id and worker_instance_id is None:
                entered.set()
                assert release.wait(timeout=5)
            return original_predicate(
                session,
                run_id=run_id,
                worker_instance_id=worker_instance_id,
            )

        monkeypatch.setattr(
            spawn_module, "_has_unresolved_v2_actions", ordered_predicate
        )
        spawns = SpawnService(session_factory)
        lifecycle = OperationLifecycleService(session_factory)

        def complete(
            spawns=spawns, node_id=run.root_node_id, node_token=run.root_token
        ):
            return asyncio.run(spawns.complete(node_id, node_token))

        def reserve(
            lifecycle=lifecycle,
            node_id=run.root_node_id,
            node_token=run.root_token,
            request_key=f"complete-first-{iteration}",
        ):
            return asyncio.run(
                lifecycle.reserve(
                    node_id=node_id,
                    credential=node_token,
                    request=_action_request(request_key),
                )
            )

        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=2) as pool:
            completion = loop.run_in_executor(pool, complete)
            assert entered.wait(timeout=5)
            reservation = loop.run_in_executor(pool, reserve)
            release.set()
            outcomes = await asyncio.gather(completion, reservation, return_exceptions=True)

        assert outcomes[0] is None
        assert isinstance(outcomes[1], ConflictError)
        assert outcomes[1].code in {"NODE_NOT_ACTIVE", "RUN_NOT_ACTIVE"}
        with session_factory() as session:
            stored_run = session.get(Run, run.run_id)
            assert stored_run is not None and stored_run.status == RunStatus.COMPLETED
            assert session.scalar(
                select(ActionAttempt.id).where(ActionAttempt.run_id == run.run_id)
            ) is None


async def test_v2_reservation_serializes_before_root_completion(session_factory):
    """A committed reservation remains a Run-level completion obligation."""
    for iteration in range(25):
        run = await create_v2_run(session_factory, f"reserve-first-{iteration}")
        await OperationLifecycleService(session_factory).reserve(
            node_id=run.root_node_id,
            credential=run.root_token,
            request=_action_request(f"reserve-first-{iteration}"),
        )

        with pytest.raises(ConflictError) as captured:
            await SpawnService(session_factory).complete(run.root_node_id, run.root_token)
        assert captured.value.code == "WORKER_HAS_UNRESOLVED_ACTIONS"
        with session_factory() as session:
            stored_run = session.get(Run, run.run_id)
            assert stored_run is not None and stored_run.status == RunStatus.RUNNING
