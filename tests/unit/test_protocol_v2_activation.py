from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from tests.helpers import FULL_ROOT_CAPABILITIES, create_v2_run
from tracefence.db.models import (
    CredentialRecoveryEnvelope,
    Node,
    Run,
    SpawnIntent,
    WorkerInstance,
)
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus, ProposalType
from tracefence.domain.errors import AuthenticationError, ConflictError
from tracefence.domain.schemas import (
    ActionExecute,
    CommandCreate,
    NodeActivate,
    Principal,
    ProposalCreate,
    RunCreate,
    SpawnCreate,
)
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.proposal_service import ProposalService
from tracefence.services.run_service import RunService
from tracefence.services.spawn_service import SpawnService


async def test_explicit_v2_root_has_only_worker_instance_credential(session_factory):
    created = await RunService(session_factory).create_run(
        RunCreate(name="real-v2-root", root_capabilities=FULL_ROOT_CAPABILITIES),
        execution_protocol_version=2,
    )

    with session_factory() as session:
        run = session.get(Run, created.run_id)
        node = session.get(Node, created.root_node_id)
        workers = session.execute(
            select(WorkerInstance).where(WorkerInstance.node_id == created.root_node_id)
        ).scalars().all()
        assert run is not None and run.execution_protocol_version == 2
        assert node is not None and node.token_hash is None
        assert len(workers) == 1
        worker = workers[0]
        assert worker.incarnation == 1
        assert worker.observed_state == "ACTIVE"
        assert worker.credential_hash is not None
        assert worker.credential_confirmed_at is None
        assert worker.activation_intent_id is None
        assert worker.terminal_revision is None
        assert worker.activated_revision == run.proof_revision
        assert node.current_worker_instance_id == worker.id

    service = SpawnService(session_factory)
    assert (await service.heartbeat(created.root_node_id, created.root_token)).id == created.root_node_id
    with pytest.raises(AuthenticationError):
        await service.heartbeat(created.root_node_id, "not-a-v2-worker-credential")


async def test_v2_child_activation_uses_spawn_intent_once_and_ignores_retry_pid(
    session_factory,
):
    run = await create_v2_run(session_factory, "real-v2-child")
    service = SpawnService(session_factory)
    spawned = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="v2-child", capabilities=[]),
    )

    with session_factory() as session:
        child = session.get(Node, spawned.child_node_id)
        assert child is not None and child.token_hash is None
        assert session.scalar(
            select(func.count(WorkerInstance.id)).where(
                WorkerInstance.node_id == spawned.child_node_id
            )
        ) == 0

    first = await service.activate(
        spawned.child_node_id,
        NodeActivate(activation_token=spawned.activation_token, process_id=4101),
    )
    retried = await service.activate(
        spawned.child_node_id,
        NodeActivate(activation_token=spawned.activation_token, process_id=4102),
    )
    assert retried == first

    with session_factory() as session:
        child = session.get(Node, spawned.child_node_id)
        intent = session.execute(
            select(SpawnIntent).where(
                SpawnIntent.child_node_id == spawned.child_node_id
            )
        ).scalar_one()
        workers = session.execute(
            select(WorkerInstance).where(WorkerInstance.node_id == spawned.child_node_id)
        ).scalars().all()
        run_row = session.get(Run, run.run_id)
        envelope = session.execute(
            select(CredentialRecoveryEnvelope).where(
                CredentialRecoveryEnvelope.binding_version == 2,
                CredentialRecoveryEnvelope.subject_node_id == spawned.child_node_id,
            )
        ).scalar_one()
        assert child is not None and child.token_hash is None
        assert len(workers) == 1
        worker = workers[0]
        assert worker.incarnation == 1
        assert worker.observed_state == "ACTIVE"
        assert worker.activation_intent_id == envelope.spawn_intent_id
        assert worker.reported_process_id == 4101
        assert worker.credential_hash is not None
        assert worker.activated_revision == run_row.proof_revision
        assert worker.terminal_revision is None
        assert child.current_worker_instance_id == worker.id
        assert envelope.binding_kind == "V2_CHILD_ACTIVATION"
        assert envelope.subject_worker_instance_id == worker.id
        assert envelope.spawn_intent_id == intent.id
        assert intent.consumed_at is not None

    assert (await service.heartbeat(first.node_id, first.node_token)).id == first.node_id


async def test_v2_expired_unconfirmed_recovery_rotates_same_worker_only(session_factory):
    run = await create_v2_run(session_factory, "v2-expired-unconfirmed")
    service = SpawnService(session_factory)
    spawned = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="v2-recovery-child", capabilities=[]),
    )
    first = await service.activate(
        spawned.child_node_id,
        NodeActivate(activation_token=spawned.activation_token, process_id=4201),
    )
    with session_factory.begin() as session:
        envelope = session.execute(
            select(CredentialRecoveryEnvelope).where(
                CredentialRecoveryEnvelope.subject_node_id == first.node_id,
                CredentialRecoveryEnvelope.binding_version == 2,
            )
        ).scalar_one()
        worker_id = envelope.subject_worker_instance_id
        envelope.expires_at = utcnow() - timedelta(seconds=1)

    rotated = await service.activate(
        spawned.child_node_id,
        NodeActivate(activation_token=spawned.activation_token, process_id=4202),
    )
    assert rotated.node_token != first.node_token
    with pytest.raises(AuthenticationError):
        await service.heartbeat(first.node_id, first.node_token)
    assert (await service.heartbeat(rotated.node_id, rotated.node_token)).id == first.node_id
    with session_factory() as session:
        workers = session.execute(
            select(WorkerInstance).where(WorkerInstance.node_id == first.node_id)
        ).scalars().all()
        assert len(workers) == 1
        assert workers[0].id == worker_id
        assert workers[0].incarnation == 1


async def test_v2_expired_confirmed_recovery_is_rejected(session_factory):
    run = await create_v2_run(session_factory, "v2-expired-confirmed")
    service = SpawnService(session_factory)
    spawned = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="v2-confirmed-child", capabilities=[]),
    )
    first = await service.activate(
        spawned.child_node_id,
        NodeActivate(activation_token=spawned.activation_token),
    )
    await service.heartbeat(first.node_id, first.node_token)
    with session_factory.begin() as session:
        envelope = session.execute(
            select(CredentialRecoveryEnvelope).where(
                CredentialRecoveryEnvelope.subject_node_id == first.node_id,
                CredentialRecoveryEnvelope.binding_version == 2,
            )
        ).scalar_one()
        envelope.expires_at = utcnow() - timedelta(seconds=1)

    with pytest.raises(ConflictError) as captured:
        await service.activate(
            spawned.child_node_id,
            NodeActivate(activation_token=spawned.activation_token),
        )
    assert captured.value.code == "CREDENTIAL_RECOVERY_CONFIRMED"


async def test_v2_activated_revision_precedes_later_cancellation(session_factory):
    run = await create_v2_run(session_factory, "v2-activated-revision")
    service = SpawnService(session_factory)
    spawned = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="v2-revision-child", capabilities=[]),
    )
    activated = await service.activate(
        spawned.child_node_id,
        NodeActivate(activation_token=spawned.activation_token),
    )
    with session_factory() as session:
        worker = session.execute(
            select(WorkerInstance).where(WorkerInstance.node_id == activated.node_id)
        ).scalar_one()
        activated_revision = worker.activated_revision

    command = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="v2-activation-revision-cancel",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=activated.node_id,
            reason_code="TEST",
            reason_text="advance proof revision after activation",
        ),
        Principal(issuer_type="HUMAN"),
        None,
    )
    assert command.duplicate is False
    with session_factory() as session:
        run_row = session.get(Run, run.run_id)
        assert run_row is not None
        assert activated_revision is not None
        assert run_row.proof_revision > activated_revision


async def test_v2_real_root_action_replay_and_logical_completion(session_factory):
    run = await create_v2_run(session_factory, "v2-real-root-mutations")
    gateway = ActionGateway(session_factory)
    first = await gateway.execute(
        run.root_node_id,
        run.root_token,
        request=ActionExecute(
            tool_name="read_metrics",
            arguments={},
            idempotency_key="v2-real-root-action",
        ),
    )
    replay = await gateway.execute(
        run.root_node_id,
        run.root_token,
        request=ActionExecute(
            tool_name="read_metrics",
            arguments={},
            idempotency_key="v2-real-root-action",
        ),
    )
    assert first.committed is True
    assert replay.duplicate is True
    await SpawnService(session_factory).complete(run.root_node_id, run.root_token)
    with session_factory() as session:
        worker = session.execute(
            select(WorkerInstance).where(WorkerInstance.node_id == run.root_node_id)
        ).scalar_one()
        node = session.get(Node, run.root_node_id)
        assert node is not None and node.status == NodeStatus.COMPLETED
        assert worker.observed_state == "ACTIVE"
        assert worker.terminal_at is None
        assert worker.terminal_revision is None


async def test_real_v2_root_checkpoint_and_proposal_use_returned_credential(session_factory):
    run = await create_v2_run(session_factory, "v2-real-root-checkpoint-proposal")
    spawn = SpawnService(session_factory)

    checkpoint = await spawn.checkpoint(run.root_node_id, run.root_token, "real-v2-checkpoint")
    assert checkpoint.allowed is True
    proposal = await ProposalService(session_factory).create(
        run.root_node_id,
        run.root_token,
        ProposalCreate(
            target_node_id=run.root_node_id,
            proposal_type=ProposalType.CANCEL,
            reason="real v2 credential can submit a proposal",
            evidence={"protocol": 2},
        ),
    )
    assert proposal.reporter_node_id == run.root_node_id


async def test_real_v2_root_credential_issues_agent_command(session_factory):
    run = await create_v2_run(session_factory, "v2-real-root-command")
    spawn = SpawnService(session_factory)
    child = await spawn.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="v2-command-child", capabilities=[]),
    )
    activated = await spawn.activate(
        child.child_node_id,
        NodeActivate(activation_token=child.activation_token),
    )

    issued = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="real-v2-agent-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=activated.node_id,
            reason_code="TEST",
            reason_text="real v2 root credential authorizes an agent command",
        ),
        Principal(issuer_type=IssuerType.AGENT, node_id=run.root_node_id),
        run.root_token,
    )
    assert issued.duplicate is False


async def test_real_v2_root_credential_creates_authorized_replacement(session_factory):
    run = await create_v2_run(session_factory, "v2-real-root-replacement")
    spawn = SpawnService(session_factory)
    child = await spawn.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(
            role="v2-replacement-target",
            instruction={"task": "old"},
            capabilities=["tool:reset_redis_pool"],
        ),
    )
    activated = await spawn.activate(
        child.child_node_id,
        NodeActivate(activation_token=child.activation_token),
    )
    command = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="real-v2-replacement-command",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=activated.node_id,
            reason_code="TEST",
            reason_text="authorize a real v2 replacement",
            replacement_instruction={"task": "reset redis"},
            replacement_expected_tool="reset_redis_pool",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    replacement = await spawn.create_replacement(
        run.root_node_id,
        run.root_token,
        command.command_id,
        SpawnCreate(
            role="redis_recovery",
            instruction={"task": "reset redis"},
            capabilities=["tool:reset_redis_pool"],
        ),
    )
    assert replacement.child_node_id != activated.node_id


async def test_v2_recovery_rejects_cancelled_activation_subject(session_factory):
    run = await create_v2_run(session_factory, "v2-recovery-cancelled")
    spawn = SpawnService(session_factory)
    child = await spawn.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="v2-cancelled-recovery-child", capabilities=[]),
    )
    activated = await spawn.activate(
        child.child_node_id,
        NodeActivate(activation_token=child.activation_token),
    )
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="v2-recovery-cancel-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=activated.node_id,
            reason_code="TEST",
            reason_text="revoke v2 activation recovery authority",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    with pytest.raises(ConflictError) as captured:
        await spawn.activate(
            child.child_node_id,
            NodeActivate(activation_token=child.activation_token, process_id=4301),
        )
    assert captured.value.code in {"SCOPE_CANCELLED", "ACTIVATION_RECOVERY_DENIED"}
