from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from tests.helpers import create_v2_run
from tracefence.db.models import (
    V22_SCHEMA_INTEGRITY_TRIGGER_DDL,
    Node,
    Run,
    RuntimeStopIntent,
    RuntimeStopTarget,
    WorkerInstance,
)
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import CommandCreate, NodeActivate, Principal, SpawnCreate
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.lease_service import LeaseService
from tracefence.services.runtime_stop_service import (
    CAUSE_COMMAND_CANCEL_RUN,
    DOMAIN_RUN,
    RuntimeStopService,
)
from tracefence.services.spawn_service import SpawnService


def _command(node_id: str, *, command_type: CommandType, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=command_type,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="runtime stop causal persistence",
    )


async def _root_with_second_worker(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    with session_factory.begin() as session:
        row = session.get(Run, run.run_id)
        node = session.get(Node, run.root_node_id)
        assert row is not None and node is not None
        second = WorkerInstance(
            id=str(uuid4()),
            node_id=node.id,
            incarnation=2,
            observed_state="ACTIVE",
            activated_at=utcnow(),
            credential_hash="f" * 64,
            activated_revision=None,
        )
        session.add(second)
        session.flush()
        node.current_worker_instance_id = second.id
        session.flush()
        session.refresh(row, attribute_names=["proof_revision"])
        second.activated_revision = row.proof_revision
    return run, second.id


async def test_cancel_run_creates_one_revision_neutral_intent_and_replay_is_stable(
    session_factory,
):
    run = await create_v2_run(session_factory, "runtime-stop-command")
    controls = ControlService(session_factory)
    request = _command(
        run.root_node_id,
        command_type=CommandType.CANCEL_RUN,
        key="runtime-stop-command",
    )

    issued = await controls.issue_command(
        request,
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == issued.command_id
            )
        ).scalar_one()
        row = session.get(Run, run.run_id)
        assert row is not None
        assert intent.cause_type == CAUSE_COMMAND_CANCEL_RUN
        assert intent.target_domain == DOMAIN_RUN
        assert intent.source_revision == row.proof_revision

    replay = await controls.issue_command(
        request,
        Principal(issuer_type=IssuerType.HUMAN),
    )
    assert replay.duplicate is True
    with session_factory() as session:
        assert session.scalar(
            select(func.count(RuntimeStopIntent.id)).where(
                RuntimeStopIntent.run_id == run.run_id
            )
        ) == 1


async def test_scope_target_materialization_is_bounded_idempotent_and_excludes_root(
    session_factory,
):
    run = await create_v2_run(session_factory, "runtime-stop-scope")
    spawns = SpawnService(session_factory)
    child = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="runtime-stop-child", capabilities=[]),
    )
    activated = await spawns.activate(
        child.child_node_id,
        NodeActivate(activation_token=child.activation_token),
    )
    command = await ControlService(session_factory).issue_command(
        _command(
            activated.node_id,
            command_type=CommandType.CANCEL_SUBTREE,
            key="runtime-stop-scope",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        ).scalar_one()
        before = session.get(Run, run.run_id).proof_revision

    planner = RuntimeStopService(session_factory)
    first = await planner.materialize_targets(intent_id=intent.id, batch_size=1)
    second = await planner.materialize_targets(intent_id=intent.id, batch_size=1)
    assert first.inserted == 1
    assert second.inserted == 0
    with session_factory() as session:
        targets = session.execute(
            select(RuntimeStopTarget.worker_instance_id).where(
                RuntimeStopTarget.stop_intent_id == intent.id
            )
        ).scalars().all()
        row = session.get(Run, run.run_id)
        assert targets
        assert len(targets) == 1
        assert row is not None and row.proof_revision == before


async def test_run_target_includes_old_current_and_legacy_exited_candidates(
    session_factory,
):
    run, second_id = await _root_with_second_worker(session_factory, "runtime-stop-run")
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        legacy = WorkerInstance(
            id=str(uuid4()),
            node_id=node.id,
            incarnation=3,
            observed_state="EXITED",
            activated_at=utcnow() - timedelta(seconds=1),
            terminal_at=utcnow(),
            activated_revision=None,
        )
        session.add(legacy)

    command = await ControlService(session_factory).issue_command(
        _command(
            run.root_node_id,
            command_type=CommandType.CANCEL_RUN,
            key="runtime-stop-run",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        ).scalar_one()
        expected = set(
            session.execute(
                select(WorkerInstance.id).where(
                    WorkerInstance.node_id == run.root_node_id,
                    WorkerInstance.activated_at.is_not(None),
                )
            ).scalars()
        )

    planner = RuntimeStopService(session_factory)
    while (await planner.materialize_targets(intent_id=intent.id, batch_size=1)).inserted:
        pass
    with session_factory() as session:
        actual = set(
            session.execute(
                select(RuntimeStopTarget.worker_instance_id).where(
                    RuntimeStopTarget.stop_intent_id == intent.id
                )
            ).scalars()
        )
    assert second_id in actual
    assert actual == expected


async def test_post_source_activation_is_excluded_without_current_state_filters(
    session_factory,
):
    run = await create_v2_run(session_factory, "runtime-stop-post-source")
    command = await ControlService(session_factory).issue_command(
        _command(
            run.root_node_id,
            command_type=CommandType.CANCEL_RUN,
            key="runtime-stop-post-source",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory.begin() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        ).scalar_one()
        node = session.get(Node, run.root_node_id)
        assert node is not None
        later = WorkerInstance(
            id=str(uuid4()),
            node_id=node.id,
            incarnation=2,
            observed_state="FAILED",
            activated_at=utcnow(),
            terminal_at=utcnow(),
            activated_revision=intent.source_revision + 1,
        )
        session.add(later)

    await RuntimeStopService(session_factory).materialize_targets(
        intent_id=intent.id,
        batch_size=10,
    )
    with session_factory() as session:
        targets = set(
            session.execute(
                select(RuntimeStopTarget.worker_instance_id).where(
                    RuntimeStopTarget.stop_intent_id == intent.id
                )
            ).scalars()
        )
    assert later.id not in targets


async def test_stop_schema_rejects_cross_run_and_selector_identity_rewrites(session_factory):
    first = await create_v2_run(session_factory, "runtime-stop-first")
    second = await create_v2_run(session_factory, "runtime-stop-second")
    with session_factory() as session:
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO runtime_stop_intents "
                    "(id, run_id, cause_type, target_domain, source_revision, "
                    "source_node_id, created_at) VALUES "
                    "(:id, :run, 'LEASE_EXPIRED', 'NODE', 1, :node, CURRENT_TIMESTAMP)"
                ),
                {"id": str(uuid4()), "run": first.run_id, "node": second.root_node_id},
            )
            session.commit()
        session.rollback()

    command = await ControlService(session_factory).issue_command(
        _command(
            first.root_node_id,
            command_type=CommandType.CANCEL_RUN,
            key="runtime-stop-immutable",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        ).scalar_one()
        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE runtime_stop_intents SET cause_type = 'LEASE_EXPIRED' WHERE id = :id"),
                {"id": intent.id},
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE nodes SET scope_snapshot_json = '[]' WHERE id = :id"),
                {"id": first.root_node_id},
            )
            session.commit()



async def test_lease_expiry_intents_preserve_node_and_root_run_domains(session_factory):
    node_run = await create_v2_run(session_factory, "runtime-stop-heartbeat-lease")
    with session_factory.begin() as session:
        node = session.get(Node, node_run.root_node_id)
        assert node is not None
        node.lease_expires_at = utcnow() - timedelta(seconds=1)

    with pytest.raises(ConflictError):
        await SpawnService(session_factory).heartbeat(
            node_run.root_node_id,
            node_run.root_token,
        )
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.run_id == node_run.run_id
            )
        ).scalar_one()
        assert intent.cause_type == "LEASE_EXPIRED"
        assert intent.target_domain == "NODE"

    root_run = await create_v2_run(session_factory, "runtime-stop-root-lease")
    with session_factory.begin() as session:
        node = session.get(Node, root_run.root_node_id)
        assert node is not None
        node.lease_expires_at = utcnow() - timedelta(seconds=1)
    from tracefence.services.lease_service import LeaseService

    assert await LeaseService(session_factory).expire_stale_nodes(root_run.run_id) == 1
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.run_id == root_run.run_id
            )
        ).scalar_one()
        assert intent.target_domain == "RUN"


async def test_logical_completion_creates_conservative_node_and_run_intents(session_factory):
    run = await create_v2_run(session_factory, "runtime-stop-nonroot-complete")
    spawns = SpawnService(session_factory)
    child = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="runtime-stop-complete-child", capabilities=[]),
    )
    activated = await spawns.activate(
        child.child_node_id,
        NodeActivate(activation_token=child.activation_token),
    )
    await spawns.complete(activated.node_id, activated.node_token)
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.run_id == run.run_id,
                RuntimeStopIntent.cause_type == "LOGICAL_COMPLETION",
            )
        ).scalar_one()
        worker = session.execute(
            select(WorkerInstance).where(WorkerInstance.node_id == activated.node_id)
        ).scalar_one()
        assert intent.target_domain == "NODE"
        assert worker.observed_state == "ACTIVE"
        assert worker.terminal_at is None
        assert worker.terminal_revision is None

    root = await create_v2_run(session_factory, "runtime-stop-root-complete")
    await SpawnService(session_factory).complete(root.root_node_id, root.root_token)
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.run_id == root.run_id,
                RuntimeStopIntent.cause_type == "LOGICAL_COMPLETION",
            )
        ).scalar_one()
        assert intent.target_domain == "RUN"


async def test_command_domains_freeze_cancelled_or_corrected_scope_identity(
    session_factory,
):
    spawns = SpawnService(session_factory)
    cancelled_run = await create_v2_run(session_factory, "runtime-stop-command-scope")
    cancelled_child = await spawns.create_spawn(
        cancelled_run.root_node_id,
        cancelled_run.root_token,
        SpawnCreate(role="runtime-stop-cancel-scope", capabilities=[]),
    )
    activated_cancelled = await spawns.activate(
        cancelled_child.child_node_id,
        NodeActivate(activation_token=cancelled_child.activation_token),
    )
    cancelled = await ControlService(session_factory).issue_command(
        _command(
            activated_cancelled.node_id,
            command_type=CommandType.CANCEL_SUBTREE,
            key="runtime-stop-cancel-scope",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    corrected_run = await create_v2_run(session_factory, "runtime-stop-command-correct")
    corrected_child = await spawns.create_spawn(
        corrected_run.root_node_id,
        corrected_run.root_token,
        SpawnCreate(role="runtime-stop-correct-scope", capabilities=[]),
    )
    activated_corrected = await spawns.activate(
        corrected_child.child_node_id,
        NodeActivate(activation_token=corrected_child.activation_token),
    )
    corrected = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="runtime-stop-correct-scope",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=activated_corrected.node_id,
            reason_code="TEST",
            reason_text="freeze old corrected scope",
            replacement_instruction={"task": "replace"},
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    with session_factory() as session:
        cancelled_intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == cancelled.command_id
            )
        ).scalar_one()
        corrected_intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == corrected.command_id
            )
        ).scalar_one()
        cancelled_node = session.get(Node, activated_cancelled.node_id)
        corrected_node = session.get(Node, activated_corrected.node_id)
        assert cancelled_node is not None and corrected_node is not None
        assert cancelled_intent.cause_type == "COMMAND_CANCEL_SUBTREE"
        assert cancelled_intent.target_domain == "SCOPE"
        assert cancelled_intent.source_scope_id == cancelled_node.own_scope_id
        assert corrected_intent.cause_type == "COMMAND_CORRECT_SUBTREE"
        assert corrected_intent.target_domain == "SCOPE"
        assert corrected_intent.source_scope_id == corrected_node.own_scope_id


async def test_pending_expiry_has_no_physical_intent_and_checkpoint_expiry_is_node_local(
    session_factory,
):
    pending = await create_v2_run(session_factory, "runtime-stop-pending-expiry")
    spawns = SpawnService(session_factory)
    created = await spawns.create_spawn(
        pending.root_node_id,
        pending.root_token,
        SpawnCreate(role="runtime-stop-pending", capabilities=[]),
    )
    with session_factory.begin() as session:
        session.execute(
            text("UPDATE spawn_intents SET expires_at = :expiry WHERE child_node_id = :node"),
            {"expiry": utcnow() - timedelta(seconds=1), "node": created.child_node_id},
        )
    assert await LeaseService(session_factory).expire_stale_nodes(pending.run_id) == 1
    with session_factory() as session:
        node = session.get(Node, created.child_node_id)
        assert node is not None and node.status == NodeStatus.LEASE_EXPIRED
        assert session.scalar(
            select(func.count(RuntimeStopIntent.id)).where(
                RuntimeStopIntent.run_id == pending.run_id
            )
        ) == 0

    checkpoint_run = await create_v2_run(session_factory, "runtime-stop-checkpoint-expiry")
    with session_factory.begin() as session:
        node = session.get(Node, checkpoint_run.root_node_id)
        assert node is not None
        node.lease_expires_at = utcnow() - timedelta(seconds=1)
    response = await spawns.checkpoint(
        checkpoint_run.root_node_id, checkpoint_run.root_token, "expired"
    )
    assert response.allowed is False
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.run_id == checkpoint_run.run_id
            )
        ).scalar_one()
        run = session.get(Run, checkpoint_run.run_id)
        assert run is not None
        assert intent.cause_type == "LEASE_EXPIRED"
        assert intent.target_domain == "NODE"
        assert run.status == "RUNNING"


async def test_completed_logical_node_remains_targetable_by_later_run_stop(session_factory):
    run = await create_v2_run(session_factory, "runtime-stop-completed-node-target")
    spawns = SpawnService(session_factory)
    child = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="runtime-stop-completed-child", capabilities=[]),
    )
    activated = await spawns.activate(
        child.child_node_id,
        NodeActivate(activation_token=child.activation_token),
    )
    await spawns.complete(activated.node_id, activated.node_token)
    command = await ControlService(session_factory).issue_command(
        _command(
            run.root_node_id,
            command_type=CommandType.CANCEL_RUN,
            key="runtime-stop-completed-node-run-cancel",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        worker_id = session.scalar(
            select(WorkerInstance.id).where(WorkerInstance.node_id == activated.node_id)
        )
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        ).scalar_one()
        assert worker_id is not None
    await RuntimeStopService(session_factory).materialize_targets(
        intent_id=intent.id, batch_size=10
    )
    with session_factory() as session:
        target_ids = set(
            session.execute(
                select(RuntimeStopTarget.worker_instance_id).where(
                    RuntimeStopTarget.stop_intent_id == intent.id
                )
            ).scalars()
        )
    assert worker_id in target_ids


async def test_pending_discovery_skips_completed_intents_without_cursor_state(session_factory):
    first = await create_v2_run(session_factory, "runtime-stop-discovery-first")
    second = await create_v2_run(session_factory, "runtime-stop-discovery-second")
    controls = ControlService(session_factory)
    first_command = await controls.issue_command(
        _command(first.root_node_id, command_type=CommandType.CANCEL_RUN, key="runtime-stop-discovery-first"),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    second_command = await controls.issue_command(
        _command(second.root_node_id, command_type=CommandType.CANCEL_RUN, key="runtime-stop-discovery-second"),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        first_intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == first_command.command_id
            )
        ).scalar_one()
        second_intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == second_command.command_id
            )
        ).scalar_one()
    planner = RuntimeStopService(session_factory)
    await planner.materialize_targets(intent_id=first_intent.id, batch_size=10)
    assert await planner.pending_intent_ids(limit=1) == [second_intent.id]


async def test_historical_command_replay_never_invents_a_current_stop_intent(
    session_factory,
):
    run = await create_v2_run(session_factory, "runtime-stop-historical-replay")
    request = _command(
        run.root_node_id,
        command_type=CommandType.CANCEL_RUN,
        key="runtime-stop-historical-replay",
    )
    controls = ControlService(session_factory)
    issued = await controls.issue_command(request, Principal(issuer_type=IssuerType.HUMAN))
    with session_factory.begin() as session:
        intent_id = session.scalar(
            select(RuntimeStopIntent.id).where(
                RuntimeStopIntent.source_command_id == issued.command_id
            )
        )
        assert intent_id is not None
        session.execute(text("DROP TRIGGER trg_runtime_stop_intents_delete_prohibited"))
        session.execute(
            text("DELETE FROM runtime_stop_intents WHERE id = :id"), {"id": intent_id}
        )
        session.execute(
            text(V22_SCHEMA_INTEGRITY_TRIGGER_DDL["trg_runtime_stop_intents_delete_prohibited"])
        )

    with pytest.raises(ConflictError) as exc_info:
        await controls.issue_command(request, Principal(issuer_type=IssuerType.HUMAN))
    assert exc_info.value.code == "RUNTIME_STOP_INTENT_HISTORICAL_MISSING"
    with session_factory() as session:
        assert session.scalar(
            select(func.count(RuntimeStopIntent.id)).where(
                RuntimeStopIntent.source_command_id == issued.command_id
            )
        ) == 0
