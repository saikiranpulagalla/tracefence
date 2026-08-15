from __future__ import annotations

import pytest
from sqlalchemy import func, select

from tests.helpers import activate, create_seeded_run
from tests.unit.test_execution_principal_auth import (
    _install_synthetic_v2,
    _switch_current_worker,
)
from tracefence.db.models import (
    ControlCommand,
    ControlScope,
    CorrectionProposal,
    Node,
    SpawnIntent,
    WorkerInstance,
)
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus, ProposalType
from tracefence.domain.errors import AuthenticationError
from tracefence.domain.schemas import CommandCreate, Principal, ProposalCreate, SpawnCreate
from tracefence.services.control_service import ControlService
from tracefence.services.proposal_service import ProposalService
from tracefence.services.spawn_service import SpawnService


async def _v2_root(session_factory, name: str):
    run = await create_seeded_run(session_factory, name)
    first, second, _first_id = await _install_synthetic_v2(session_factory, run)
    second_id = await _switch_current_worker(
        session_factory, run.run_id, run.root_node_id, second
    )
    return run, first, second, second_id


def _run_counts(session_factory, run_id: str) -> tuple[int, int, int, int]:
    with session_factory() as session:
        return (
            session.scalar(select(func.count(Node.id)).where(Node.run_id == run_id))
            or 0,
            session.scalar(
                select(func.count(SpawnIntent.child_node_id)).where(
                    SpawnIntent.run_id == run_id
                )
            )
            or 0,
            session.scalar(
                select(func.count(ControlScope.id)).where(ControlScope.run_id == run_id)
            )
            or 0,
            session.scalar(
                select(func.count(ControlCommand.id)).where(ControlCommand.run_id == run_id)
            )
            or 0,
        )


async def test_v2_stale_checkpoint_has_no_write_and_current_instance_succeeds(
    session_factory,
):
    service = SpawnService(session_factory)
    run, first, second, _ = await _v2_root(session_factory, "v2-checkpoint")

    with pytest.raises(AuthenticationError):
        await service.checkpoint(run.root_node_id, first, "stale-checkpoint")
    with session_factory() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        assert node.status == NodeStatus.ACTIVE
        assert node.completed_at is None

    result = await service.checkpoint(run.root_node_id, second, "current-checkpoint")
    assert result.allowed is True
    with session_factory() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        assert node.status == NodeStatus.WAITING


async def test_v2_stale_spawn_has_no_graph_mutation_and_current_instance_succeeds(
    session_factory,
):
    service = SpawnService(session_factory)
    run, first, second, _ = await _v2_root(session_factory, "v2-spawn")
    request = SpawnCreate(role="v2-child", capabilities=[])
    before = _run_counts(session_factory, run.run_id)

    with pytest.raises(AuthenticationError):
        await service.create_spawn(run.root_node_id, first, request)
    assert _run_counts(session_factory, run.run_id) == before

    created = await service.create_spawn(run.root_node_id, second, request)
    after = _run_counts(session_factory, run.run_id)
    assert after == (before[0] + 1, before[1] + 1, before[2] + 1, before[3])
    with session_factory() as session:
        child = session.get(Node, created.child_node_id)
        assert child is not None and child.parent_id == run.root_node_id


async def test_v2_stale_proposal_has_no_row_and_current_instance_succeeds(
    session_factory,
):
    proposals = ProposalService(session_factory)
    run, first, second, _ = await _v2_root(session_factory, "v2-proposal")
    request = ProposalCreate(
        target_node_id=run.root_node_id,
        proposal_type=ProposalType.CANCEL,
        reason="current instance observed an invalid branch",
        evidence={"source": "synthetic-v2"},
    )
    with session_factory() as session:
        before = session.scalar(
            select(func.count(CorrectionProposal.id)).where(
                CorrectionProposal.run_id == run.run_id
            )
        )

    with pytest.raises(AuthenticationError):
        await proposals.create(run.root_node_id, first, request)
    with session_factory() as session:
        assert (
            session.scalar(
                select(func.count(CorrectionProposal.id)).where(
                    CorrectionProposal.run_id == run.run_id
                )
            )
            == before
        )

    proposal = await proposals.create(run.root_node_id, second, request)
    assert proposal.reporter_node_id == run.root_node_id


async def test_v2_stale_agent_command_has_no_command_and_current_instance_succeeds(
    session_factory,
):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "v2-agent-command")
    target = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="v2-command-target", capabilities=[]),
        ),
    )
    first, second, _ = await _install_synthetic_v2(session_factory, run)
    await _switch_current_worker(session_factory, run.run_id, run.root_node_id, second)
    request = CommandCreate(
        idempotency_key="v2-agent-cancel-target",
        command_type=CommandType.CANCEL_SUBTREE,
        target_node_id=target.node_id,
        reason_code="TEST",
        reason_text="the current execution principal authorizes this command",
    )
    principal = Principal(issuer_type=IssuerType.AGENT, node_id=run.root_node_id)
    before = _run_counts(session_factory, run.run_id)

    with pytest.raises(AuthenticationError):
        await controls.issue_command(request, principal, first)
    assert _run_counts(session_factory, run.run_id) == before

    issued = await controls.issue_command(request, principal, second)
    assert issued.duplicate is False
    with session_factory() as session:
        assert session.get(ControlCommand, issued.command_id) is not None


async def test_v2_stale_replacement_has_no_lineage_mutation_and_current_instance_succeeds(
    session_factory,
):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "v2-replacement")
    target = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                role="v2-replacement-target",
                instruction={"task": "old"},
                capabilities=["tool:reset_redis_pool"],
            ),
        ),
    )
    first, second, _ = await _install_synthetic_v2(session_factory, run)
    await _switch_current_worker(session_factory, run.run_id, run.root_node_id, second)
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="v2-replacement-command",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=target.node_id,
            reason_code="TEST",
            reason_text="create a valid replacement",
            replacement_instruction={"task": "reset redis"},
            replacement_expected_tool="reset_redis_pool",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    assert command.replacement_parent_id == run.root_node_id
    request = SpawnCreate(
        role="redis_recovery",
        behavior="cooperative",
        instruction={"task": "reset redis"},
        capabilities=["tool:reset_redis_pool"],
    )
    before = _run_counts(session_factory, run.run_id)
    with session_factory() as session:
        stored = session.get(ControlCommand, command.command_id)
        assert stored is not None
        assert stored.replacement_node_id is None
        status_before = stored.replacement_status

    with pytest.raises(AuthenticationError):
        await spawns.create_replacement(
            run.root_node_id, first, command.command_id, request
        )
    assert _run_counts(session_factory, run.run_id) == before
    with session_factory() as session:
        stored = session.get(ControlCommand, command.command_id)
        assert stored is not None
        assert stored.replacement_node_id is None
        assert stored.replacement_status == status_before

    created = await spawns.create_replacement(
        run.root_node_id, second, command.command_id, request
    )
    after = _run_counts(session_factory, run.run_id)
    assert after == (before[0] + 1, before[1] + 1, before[2] + 1, before[3])
    with session_factory() as session:
        stored = session.get(ControlCommand, command.command_id)
        assert stored is not None
        assert stored.replacement_node_id == created.child_node_id


async def test_v2_stale_completion_has_no_logical_or_physical_exit_and_current_succeeds(
    session_factory,
):
    service = SpawnService(session_factory)
    run, first, second, second_id = await _v2_root(session_factory, "v2-complete")

    with pytest.raises(AuthenticationError):
        await service.complete(run.root_node_id, first)
    with session_factory() as session:
        node = session.get(Node, run.root_node_id)
        instance = session.get(WorkerInstance, second_id)
        assert node is not None and node.status == NodeStatus.ACTIVE
        assert instance is not None
        assert instance.observed_state == "ACTIVE"
        assert instance.terminal_at is None
        assert instance.terminal_revision is None

    await service.complete(run.root_node_id, second)
    with session_factory() as session:
        node = session.get(Node, run.root_node_id)
        instance = session.get(WorkerInstance, second_id)
        assert node is not None and node.status == NodeStatus.COMPLETED
        assert instance is not None
        assert instance.observed_state == "ACTIVE"
        assert instance.terminal_at is None
        assert instance.terminal_revision is None
