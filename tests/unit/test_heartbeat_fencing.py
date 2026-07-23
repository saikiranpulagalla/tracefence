from __future__ import annotations

import pytest

from tests.helpers import activate, create_seeded_run
from tracefence.db.models import CommandAcknowledgement, ControlScope, Node
from tracefence.domain.enums import (
    AckType,
    CommandType,
    IssuerType,
    NodeStatus,
)
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import CommandCreate, Principal, SpawnCreate
from tracefence.services.control_service import ControlService
from tracefence.services.spawn_service import SpawnService


async def _active_child(session_factory, key: str):
    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, key)
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="heartbeat-worker", capabilities=["tool:read_metrics"]),
        ),
    )
    with session_factory() as session:
        stored = session.get(Node, child.node_id)
        assert stored is not None
        lease_before = stored.lease_expires_at
    return run, child, lease_before


async def _assert_denied_without_renewal(
    session_factory,
    child,
    lease_before,
    expected_code: str,
    expected_status: NodeStatus,
):
    with pytest.raises(ConflictError) as captured:
        await SpawnService(session_factory).heartbeat(
            child.node_id,
            child.node_token,
        )
    assert captured.value.code == expected_code
    with session_factory() as session:
        stored = session.get(Node, child.node_id)
        assert stored is not None
        assert stored.lease_expires_at == lease_before
        assert stored.status == expected_status


async def test_heartbeat_after_subtree_cancellation_does_not_renew(session_factory):
    _run, child, lease_before = await _active_child(
        session_factory, "heartbeat-cancelled"
    )
    command = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="heartbeat-cancel-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=child.node_id,
            reason_code="CANCEL",
            reason_text="cancel before heartbeat",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    await _assert_denied_without_renewal(
        session_factory,
        child,
        lease_before,
        "SCOPE_CANCELLED",
        NodeStatus.CANCELLED,
    )
    with session_factory() as session:
        ack = session.query(CommandAcknowledgement).filter_by(
            command_id=command.command_id,
            node_id=child.node_id,
            ack_type=AckType.COOPERATIVE,
        ).one_or_none()
        assert ack is not None


async def test_heartbeat_after_scope_supersession_does_not_renew(session_factory):
    _run, child, lease_before = await _active_child(
        session_factory, "heartbeat-superseded"
    )
    command = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="heartbeat-supersede-command",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=child.node_id,
            reason_code="CORRECT",
            reason_text="supersede before heartbeat",
            replacement_instruction={"task": "replacement"},
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    await _assert_denied_without_renewal(
        session_factory,
        child,
        lease_before,
        "SCOPE_SUPERSEDED",
        NodeStatus.SUPERSEDED,
    )
    with session_factory() as session:
        ack = session.query(CommandAcknowledgement).filter_by(
            command_id=command.command_id,
            node_id=child.node_id,
            ack_type=AckType.COOPERATIVE,
        ).one_or_none()
        assert ack is not None


async def test_heartbeat_after_scope_version_mismatch_does_not_renew(
    session_factory,
):
    _run, child, lease_before = await _active_child(
        session_factory, "heartbeat-version-mismatch"
    )
    with session_factory() as session, session.begin():
        node = session.get(Node, child.node_id)
        assert node is not None
        own_scope = session.get(ControlScope, node.own_scope_id)
        assert own_scope is not None
        own_scope.version += 1

    await _assert_denied_without_renewal(
        session_factory,
        child,
        lease_before,
        "SCOPE_VERSION_MISMATCH",
        NodeStatus.SUPERSEDED,
    )
