from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from tests.helpers import create_seeded_run
from tracefence.db.models import ControlCommand, Node, Run
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus, RunStatus
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import CommandCreate, Principal
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.lease_service import LeaseService
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
