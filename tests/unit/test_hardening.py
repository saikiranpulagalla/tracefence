from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from tests.helpers import activate, create_seeded_run
from tracefence.db.models import ControlCommand, Node
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import ConflictError, TraceFenceError
from tracefence.domain.schemas import CommandCreate, Principal, SpawnCreate
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService


async def test_expired_lease_cannot_be_revived(session_factory):
    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, "lease")
    active = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="worker", capabilities=[]),
        ),
    )
    with session_factory() as session, session.begin():
        node = session.get(Node, active.node_id)
        node.lease_expires_at = utcnow() - timedelta(seconds=1)

    with pytest.raises(ConflictError) as exc:
        await spawns.heartbeat(active.node_id, active.node_token)
    assert exc.value.code == "LEASE_EXPIRED"
    with session_factory() as session:
        assert session.get(Node, active.node_id).status == "LEASE_EXPIRED"


async def test_replacement_requires_real_correction_and_leaves_no_orphan(session_factory):
    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, "replacement-integrity")
    old = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="old", capabilities=[]),
        ),
    )

    with pytest.raises(TraceFenceError):
        await spawns.create_replacement(
            run.root_node_id,
            run.root_token,
            "missing-command",
            SpawnCreate(role="replacement", instruction={}, capabilities=[]),
        )
    with session_factory() as session:
        replacements = session.execute(
            select(Node).where(Node.supersedes_node_id == old.node_id)
        ).scalars().all()
        assert replacements == []


async def test_service_state_is_isolated_per_run(session_factory):
    states = StateService(session_factory)
    run_a = await create_seeded_run(session_factory, "run-a")
    run_b = await create_seeded_run(session_factory, "run-b")
    rows_a = {row["service_name"]: row for row in await states.list_states(run_a.run_id)}
    rows_b = {row["service_name"]: row for row in await states.list_states(run_b.run_id)}
    assert rows_a["redis"]["status"] == "connection_pool_exhausted"
    assert rows_b["redis"]["status"] == "connection_pool_exhausted"
    assert all(row["run_id"] == run_a.run_id for row in rows_a.values())
    assert all(row["run_id"] == run_b.run_id for row in rows_b.values())


async def test_cancel_run_by_delegated_parent_is_denied_in_service(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "cancel-run-authority")
    parent = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="parent", capabilities=["control:descendants"]),
        ),
    )
    child = await activate(
        spawns,
        await spawns.create_spawn(
            parent.node_id,
            parent.node_token,
            SpawnCreate(role="child", capabilities=[]),
        ),
    )
    with pytest.raises(TraceFenceError):
        await controls.issue_command(
            CommandCreate(
                idempotency_key="bad-cancel-run",
                command_type=CommandType.CANCEL_RUN,
                target_node_id=child.node_id,
                reason_code="BAD",
                reason_text="bad",
            ),
            Principal(issuer_type=IssuerType.AGENT, node_id=parent.node_id),
            parent.node_token,
        )
    with session_factory() as session:
        assert session.execute(select(ControlCommand)).scalars().all() == []


async def test_expired_checkpoint_persists_expiry_and_reports_effective_status(session_factory):
    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, "checkpoint-expiry")
    active = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="worker", capabilities=[]),
        ),
    )
    with session_factory() as session, session.begin():
        node = session.get(Node, active.node_id)
        node.lease_expires_at = utcnow() - timedelta(seconds=1)

    response = await spawns.checkpoint(active.node_id, active.node_token, "before_tool")
    assert response.allowed is False
    assert response.reason_code == "LEASE_EXPIRED"
    assert response.effective_status == "LEASE_EXPIRED"
    with session_factory() as session:
        assert session.get(Node, active.node_id).status == "LEASE_EXPIRED"


async def test_human_cancel_run_targeting_child_is_denied(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "human-cancel-target")
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="child", capabilities=[]),
        ),
    )
    with pytest.raises(TraceFenceError):
        await controls.issue_command(
            CommandCreate(
                idempotency_key="human-bad-target",
                command_type=CommandType.CANCEL_RUN,
                target_node_id=child.node_id,
                reason_code="BAD_TARGET",
                reason_text="must target root",
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )


async def test_root_completion_expires_stale_active_descendant(session_factory):
    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, "complete-expired-active")
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="child", capabilities=[]),
        ),
    )
    with session_factory() as session, session.begin():
        session.get(Node, child.node_id).lease_expires_at = utcnow() - timedelta(seconds=1)

    await spawns.complete(run.root_node_id, run.root_token)
    from tracefence.db.models import Run
    with session_factory() as session:
        assert session.get(Node, child.node_id).status == "LEASE_EXPIRED"
        assert session.get(Run, run.run_id).status == "COMPLETED"


async def test_root_completion_expires_unactivated_spawn_intent(session_factory):
    from tracefence.db.models import Run, SpawnIntent

    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, "complete-expired-pending")
    pending = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="pending-child", capabilities=[]),
    )
    with session_factory() as session, session.begin():
        intent = session.execute(
            select(SpawnIntent).where(SpawnIntent.child_node_id == pending.child_node_id)
        ).scalar_one()
        intent.expires_at = utcnow() - timedelta(seconds=1)

    await spawns.complete(run.root_node_id, run.root_token)
    with session_factory() as session:
        assert session.get(Node, pending.child_node_id).status == "LEASE_EXPIRED"
        assert session.get(Run, run.run_id).status == "COMPLETED"


async def test_parent_chain_not_lineage_cache_controls_authority(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "parent-chain-authority")
    parent = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="parent", capabilities=["control:descendants"]),
        ),
    )
    child = await activate(
        spawns,
        await spawns.create_spawn(
            parent.node_id,
            parent.node_token,
            SpawnCreate(role="child", capabilities=[]),
        ),
    )
    sibling = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="sibling", capabilities=[]),
        ),
    )
    with session_factory() as session, session.begin():
        session.get(Node, child.node_id).lineage_path = "/corrupted/cache/"
        session.get(Node, sibling.node_id).lineage_path = f"/forged/{parent.node_id}/"

    allowed = await controls.issue_command(
        CommandCreate(
            idempotency_key="real-parent-link",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=child.node_id,
            reason_code="TEST",
            reason_text="authoritative parent chain",
        ),
        Principal(issuer_type=IssuerType.AGENT, node_id=parent.node_id),
        parent.node_token,
    )
    assert allowed.command_id

    with pytest.raises(TraceFenceError):
        await controls.issue_command(
            CommandCreate(
                idempotency_key="forged-lineage",
                command_type=CommandType.CANCEL_SUBTREE,
                target_node_id=sibling.node_id,
                reason_code="TEST",
                reason_text="forged cache must not grant authority",
            ),
            Principal(issuer_type=IssuerType.AGENT, node_id=parent.node_id),
            parent.node_token,
        )
