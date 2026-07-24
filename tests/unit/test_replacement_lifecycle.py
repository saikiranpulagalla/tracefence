from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from tests.helpers import activate, create_seeded_run
from tracefence.db.models import ControlCommand, ControlScope, Node, SpawnIntent
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus, ScopeStatus
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import CommandCreate, Principal, SpawnCreate
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.lease_service import LeaseService
from tracefence.services.spawn_service import SpawnService


async def _nested_target(session_factory, key: str):
    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, key)
    parent = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                role="supervisor",
                capabilities=["tool:reset_redis_pool"],
            ),
        ),
    )
    target = await activate(
        spawns,
        await spawns.create_spawn(
            parent.node_id,
            parent.node_token,
            SpawnCreate(
                role="worker",
                instruction={"task": "old"},
                capabilities=["tool:reset_redis_pool"],
            ),
        ),
    )
    return run, parent, target


def _correction(target, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CORRECT_SUBTREE,
        target_node_id=target.node_id,
        reason_code="CORRECT",
        reason_text="create an achievable replacement",
        replacement_instruction={"task": "reset redis"},
        replacement_expected_tool="reset_redis_pool",
    )


async def test_dead_intended_parent_uses_live_root_fallback(session_factory):
    run, parent, target = await _nested_target(
        session_factory,
        "replacement-root-fallback",
    )
    with session_factory() as session, session.begin():
        stored_parent = session.get(Node, parent.node_id)
        assert stored_parent is not None
        stored_parent.status = NodeStatus.LEASE_EXPIRED

    command = await ControlService(session_factory).issue_command(
        _correction(target, "fallback-correction"),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    assert command.replacement_parent_id == run.root_node_id
    created = await SpawnService(session_factory).create_replacement(
        run.root_node_id,
        run.root_token,
        command.command_id,
        SpawnCreate(
            role="redis_recovery",
            behavior="cooperative",
            instruction={"task": "reset redis"},
            capabilities=["tool:reset_redis_pool"],
        ),
    )
    with session_factory() as session:
        replacement = session.get(Node, created.child_node_id)
        assert replacement is not None
        assert replacement.parent_id == run.root_node_id
        assert replacement.supersedes_node_id == target.node_id


async def test_correction_fails_atomically_when_parent_and_root_are_dead(
    session_factory,
):
    run, parent, target = await _nested_target(
        session_factory,
        "replacement-no-fallback",
    )
    with session_factory() as session, session.begin():
        for node_id in (parent.node_id, run.root_node_id):
            node = session.get(Node, node_id)
            assert node is not None
            node.status = NodeStatus.LEASE_EXPIRED
        target_node = session.get(Node, target.node_id)
        assert target_node is not None
        scope_id = target_node.own_scope_id

    with pytest.raises(ConflictError) as captured:
        await ControlService(session_factory).issue_command(
            _correction(target, "impossible-correction"),
            Principal(issuer_type=IssuerType.HUMAN),
        )

    assert captured.value.code == "REPLACEMENT_PARENT_UNAVAILABLE"
    with session_factory() as session:
        scope = session.get(ControlScope, scope_id)
        command_count = session.scalar(
            select(func.count(ControlCommand.id)).where(
                ControlCommand.run_id == run.run_id
            )
        )
        assert scope is not None
        assert scope.status == ScopeStatus.ACTIVE
        assert scope.version == 1
        assert command_count == 0


async def test_replacement_activation_expiry_is_durable_lifecycle_state(
    session_factory,
):
    run, parent, target = await _nested_target(
        session_factory,
        "replacement-activation-expiry",
    )
    command = await ControlService(session_factory).issue_command(
        _correction(target, "expiring-correction"),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    created = await SpawnService(session_factory).create_replacement(
        parent.node_id,
        parent.node_token,
        command.command_id,
        SpawnCreate(
            role="redis_recovery",
            behavior="cooperative",
            instruction={"task": "reset redis"},
            capabilities=["tool:reset_redis_pool"],
        ),
    )
    with session_factory() as session, session.begin():
        intent = session.execute(
            select(SpawnIntent).where(
                SpawnIntent.child_node_id == created.child_node_id
            )
        ).scalar_one()
        intent.expires_at = utcnow() - timedelta(seconds=1)

    assert await LeaseService(session_factory).expire_stale_nodes(run.run_id) == 1
    with session_factory() as session:
        stored_command = session.get(ControlCommand, command.command_id)
        replacement = session.get(Node, created.child_node_id)
        assert stored_command is not None
        assert replacement is not None
        assert stored_command.replacement_status == "ACTIVATION_EXPIRED"
        assert replacement.status == NodeStatus.LEASE_EXPIRED
