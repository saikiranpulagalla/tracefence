from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

import tracefence.services.control_service as control_module
import tracefence.services.run_service as run_module
import tracefence.services.spawn_service as spawn_module
from tests.helpers import activate, create_seeded_run
from tests.unit.test_proof_contract import _corrected_recovery
from tracefence.config import _bool_env, settings
from tracefence.db.models import (
    ActionAttempt,
    ControlCommand,
    CorrectionProposal,
    InvariantViolation,
    ServiceState,
    TelemetryOutbox,
)
from tracefence.domain.enums import (
    ActionDecision,
    CommandType,
    IssuerType,
    ProofVerdict,
    ProposalStatus,
    ProposalType,
)
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import (
    ActionExecute,
    CommandCreate,
    Principal,
    ProposalCommandAuthorization,
    ProposalCreate,
    ProposalReview,
    SpawnCreate,
)
from tracefence.evidence import EvidenceIntegrityError, resolve_evidence_path, write_evidence_bundle
from tracefence.security import payload_digest
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.invariant_service import InvariantService
from tracefence.services.proof_service import ProofService
from tracefence.services.proposal_service import ProposalService
from tracefence.services.spawn_service import SpawnService


async def test_recovery_proof_requires_stability_and_valid_result_digest(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    proof_service = ProofService(session_factory)
    run = await create_seeded_run(session_factory, "stability")
    old = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="database_investigator", capabilities=[]),
        ),
    )
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="stability-command",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=old.node_id,
            reason_code="TEST",
            reason_text="verify stability",
            replacement_instruction={"task": "reset redis pool"},
            replacement_expected_tool="reset_redis_pool",
            recovery_stability_seconds=5,
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    replacement = await activate(
        spawns,
        await spawns.create_replacement(
            run.root_node_id,
            run.root_token,
            command.command_id,
            SpawnCreate(
                role="redis_recovery",
                instruction={"task": "reset redis pool"},
                capabilities=["tool:reset_redis_pool"],
            ),
        ),
    )
    action = await gateway.execute(
        replacement.node_id,
        replacement.node_token,
        ActionExecute(
            idempotency_key="stability-action",
            tool_name="reset_redis_pool",
            arguments={},
        ),
    )
    await spawns.complete(replacement.node_id, replacement.node_token)

    early = await proof_service.build(command.command_id)
    assert early.recovery_action_verdict == ProofVerdict.VERIFIED
    assert early.recovery_postcondition_verdict == ProofVerdict.VERIFIED
    assert early.recovery_stability_verdict == ProofVerdict.INCOMPLETE

    with session_factory() as session, session.begin():
        for service_name in ("redis", "checkout"):
            state = session.get(ServiceState, (run.run_id, service_name))
            state.updated_at = utcnow() - timedelta(seconds=10)
        row = session.get(ActionAttempt, action.action_id)
        row.result_digest = "0" * 64

    corrupted = await proof_service.build(command.command_id)
    assert corrupted.recovery_action_verdict == ProofVerdict.INCONSISTENT
    assert corrupted.runtime_verdict == ProofVerdict.INCONSISTENT


async def test_recovery_postconditions_require_authorized_action_causality(session_factory):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="causal-postcondition"
    )
    with session_factory() as session, session.begin():
        redis = session.get(ServiceState, (run.run_id, "redis"))
        assert redis is not None
        redis.last_action_id = None
    proof = await ProofService(session_factory).build(command.command_id)
    assert proof.recovery_action_verdict == ProofVerdict.VERIFIED
    assert proof.recovery_postcondition_verdict == ProofVerdict.INCONSISTENT
    assert proof.runtime_verdict == ProofVerdict.INCONSISTENT


async def test_accepted_proposal_is_digest_bound_and_linked_to_one_command(session_factory):
    spawns = SpawnService(session_factory)
    proposals = ProposalService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "proposal-link")
    target = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="target", capabilities=[]),
        ),
    )
    proposal = await proposals.create(
        run.root_node_id,
        run.root_token,
        ProposalCreate(
            target_node_id=target.node_id,
            proposal_type=ProposalType.CANCEL,
            reason="stop the invalid branch",
            evidence={"trace_id": "abc"},
        ),
    )
    authorized = ProposalCommandAuthorization(
        command_type=CommandType.CANCEL_SUBTREE,
        target_node_id=target.node_id,
        reason_code="ACCEPTED_PROPOSAL",
        reason_text="operator accepted proposal",
    )
    await proposals.review(
        proposal.id,
        ProposalReview(
            status=ProposalStatus.ACCEPTED,
            authorized_command=authorized,
        ),
        reviewer_principal="human:operator",
    )
    with pytest.raises(ConflictError) as mismatch:
        await controls.issue_command(
            CommandCreate(
                idempotency_key="proposal-command-mismatch",
                source_proposal_id=proposal.id,
                command_type=CommandType.CANCEL_SUBTREE,
                target_node_id=target.node_id,
                reason_code="DIFFERENT_REASON",
                reason_text="not the reviewed command",
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
    assert mismatch.value.code == "SOURCE_PROPOSAL_COMMAND_MISMATCH"

    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="proposal-command",
            source_proposal_id=proposal.id,
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=target.node_id,
            reason_code="ACCEPTED_PROPOSAL",
            reason_text="operator accepted proposal",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        stored_proposal = session.get(CorrectionProposal, proposal.id)
        stored_command = session.get(ControlCommand, command.command_id)
        assert stored_proposal.resulting_command_id == command.command_id
        assert stored_command.source_proposal_id == proposal.id
        assert stored_proposal.reviewed_by_principal == "human:operator"

    with pytest.raises(ConflictError) as exc:
        await controls.issue_command(
            CommandCreate(
                idempotency_key="proposal-command-two",
                source_proposal_id=proposal.id,
                command_type=CommandType.CANCEL_SUBTREE,
                target_node_id=target.node_id,
                reason_code="REUSE",
                reason_text="reuse accepted proposal",
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
    assert exc.value.code == "SOURCE_PROPOSAL_ALREADY_USED"


async def test_accepted_proposal_tampering_is_detected(session_factory):
    spawns = SpawnService(session_factory)
    proposals = ProposalService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "proposal-tamper")
    target = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="target", capabilities=[]),
        ),
    )
    proposal = await proposals.create(
        run.root_node_id,
        run.root_token,
        ProposalCreate(
            target_node_id=target.node_id,
            proposal_type=ProposalType.CANCEL,
            reason="original",
            evidence={},
        ),
    )
    authorized = ProposalCommandAuthorization(
        command_type=CommandType.CANCEL_SUBTREE,
        target_node_id=target.node_id,
        reason_code="TEST",
        reason_text="test",
    )
    await proposals.review(
        proposal.id,
        ProposalReview(
            status=ProposalStatus.ACCEPTED,
            authorized_command=authorized,
        ),
        reviewer_principal="human:operator",
    )
    with session_factory() as session, session.begin():
        session.get(CorrectionProposal, proposal.id).reason = "tampered"
    with pytest.raises(ConflictError) as exc:
        await controls.issue_command(
            CommandCreate(
                idempotency_key="tampered-proposal-command",
                source_proposal_id=proposal.id,
                command_type=CommandType.CANCEL_SUBTREE,
                target_node_id=target.node_id,
                reason_code="TEST",
                reason_text="test",
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
    assert exc.value.code == "SOURCE_PROPOSAL_DIGEST_MISMATCH"


async def test_graph_and_command_quotas_fail_closed(session_factory, monkeypatch):
    limited = replace(
        settings,
        max_nodes_per_run=2,
        max_children_per_node=1,
        max_graph_depth=1,
        max_commands_per_run=1,
    )
    monkeypatch.setattr(spawn_module, "settings", limited)
    monkeypatch.setattr(control_module, "settings", limited)
    monkeypatch.setattr(run_module, "settings", limited)
    run = await create_seeded_run(session_factory, "quotas")
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="child", capabilities=[]),
        ),
    )
    with pytest.raises(ConflictError) as exc:
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="second-child", capabilities=[]),
        )
    assert exc.value.code in {"RUN_NODE_QUOTA_EXCEEDED", "NODE_CHILD_QUOTA_EXCEEDED"}

    await controls.issue_command(
        CommandCreate(
            idempotency_key="quota-command-one",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=child.node_id,
            reason_code="TEST",
            reason_text="first",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    # A second command targets another fresh run node because the first scope is no longer active.
    with pytest.raises(ConflictError) as exc:
        await controls.issue_command(
            CommandCreate(
                idempotency_key="quota-command-two",
                command_type=CommandType.CANCEL_RUN,
                target_node_id=run.root_node_id,
                reason_code="TEST",
                reason_text="second",
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
    assert exc.value.code == "RUN_COMMAND_QUOTA_EXCEEDED"


async def test_invariant_auditor_persists_stale_commit_once(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "invariant-outbox")
    node = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="stale", capabilities=["tool:restart_postgres"]),
        ),
    )
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="invariant-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=node.node_id,
            reason_code="TEST",
            reason_text="cancel",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    now = utcnow()
    with session_factory() as session, session.begin():
        session.add(
            ActionAttempt(
                id="00000000-0000-0000-0000-000000000123",
                run_id=run.run_id,
                node_id=node.node_id,
                tool_name="restart_postgres",
                side_effecting=True,
                idempotency_key="corrupt-stale-commit",
                decision=ActionDecision.ALLOW,
                denial_reason=None,
                scope_evaluation_json={"allowed": True},
                request_payload_digest=payload_digest(
                    {
                        "idempotency_key": "corrupt-stale-commit",
                        "tool_name": "restart_postgres",
                        "arguments": {},
                    }
                ),
                arguments_json={},
                arguments_digest=payload_digest({}),
                result_json={"service": "postgres", "restart_count": 1},
                result_digest=payload_digest({"service": "postgres", "restart_count": 1}),
                attempted_at=now,
                committed_at=now,
            )
        )
    auditor = InvariantService(session_factory)
    assert await auditor.scan(run.run_id) == 1
    assert await auditor.scan(run.run_id) == 0
    with session_factory() as session:
        assert session.scalar(select(func.count(InvariantViolation.id))) == 1
        outbox = session.execute(select(TelemetryOutbox)).scalar_one()
        assert outbox.event_key == f"stale-commit:{command.command_id}:00000000-0000-0000-0000-000000000123"
        assert outbox.delivered_at is None


def test_evidence_manifest_detects_tampering(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "tracefence.evidence._git_metadata",
        lambda _repo: {"commit": "a" * 40, "dirty": False},
    )
    command_id = "command-1"
    bundle = {
        "run": {"run_id": "run-1", "root_node_id": "root"},
        "command": {"command_id": command_id},
        "recovery": {},
        "sibling_check": {},
        "worker_output": "ok",
        "proof": {"command_id": command_id},
        "graph": {"run_id": "run-1"},
        "actions": [],
        "services": [],
    }
    pointer = write_evidence_bundle(tmp_path, bundle, repo_dir=tmp_path, signing_key="s" * 32)
    resolved, manifest = resolve_evidence_path(pointer, signing_key="s" * 32)
    assert resolved.name == "bundle.json"
    assert manifest["run_id"] == "run-1"
    resolved.write_text("{}")
    with pytest.raises(EvidenceIntegrityError, match="digest mismatch"):
        resolve_evidence_path(pointer, signing_key="s" * 32)


def test_boolean_environment_parser_rejects_typos(monkeypatch):
    monkeypatch.setenv("TRACEFENCE_TEST_BOOLEAN", "treu")
    with pytest.raises(RuntimeError, match="must be one of"):
        _bool_env("TRACEFENCE_TEST_BOOLEAN")


async def test_action_quota_rejects_new_actions_but_allows_exact_replay(
    session_factory, monkeypatch
):
    import tracefence.services.action_gateway as action_module

    limited = replace(settings, max_actions_per_run=1)
    monkeypatch.setattr(action_module, "settings", limited)
    run = await create_seeded_run(session_factory, "action-quota")
    gateway = ActionGateway(session_factory)

    first_request = ActionExecute(
        idempotency_key="metrics-once",
        tool_name="read_metrics",
        arguments={},
    )
    first = await gateway.execute(run.root_node_id, run.root_token, first_request)
    replay = await gateway.execute(run.root_node_id, run.root_token, first_request)
    assert replay.duplicate is True
    assert replay.action_id == first.action_id

    with pytest.raises(ConflictError) as exc:
        await gateway.execute(
            run.root_node_id,
            run.root_token,
            ActionExecute(
                idempotency_key="metrics-twice",
                tool_name="read_metrics",
                arguments={},
            ),
        )
    assert exc.value.code == "RUN_ACTION_QUOTA_EXCEEDED"


async def test_outbox_is_acknowledged_only_after_successful_telemetry_flush(
    session_factory, monkeypatch
):
    import tracefence.services.invariant_service as invariant_module

    run = await create_seeded_run(session_factory, "outbox-flush")
    with session_factory() as session, session.begin():
        session.add(
            TelemetryOutbox(
                id="00000000-0000-0000-0000-000000000777",
                event_key="stale-commit:test:test",
                run_id=run.run_id,
                event_type="tracefence.stale_action_committed",
                payload_json={
                    "command_id": "test-command",
                    "action_id": "test-action",
                    "node_id": run.root_node_id,
                    "tool_name": "restart_postgres",
                },
                created_at=utcnow(),
            )
        )

    monkeypatch.setattr(invariant_module, "telemetry_health", lambda: {"status": "READY"})
    monkeypatch.setattr(invariant_module, "force_flush_telemetry", lambda: False)
    service = InvariantService(session_factory)
    assert await service.deliver_pending() == 0
    with session_factory() as session:
        row = session.get(TelemetryOutbox, "00000000-0000-0000-0000-000000000777")
        assert row.delivered_at is None
        assert row.attempts == 1
        assert "did not flush" in row.last_error

    monkeypatch.setattr(invariant_module, "force_flush_telemetry", lambda: True)
    with session_factory() as session, session.begin():
        row = session.get(
            TelemetryOutbox,
            "00000000-0000-0000-0000-000000000777",
        )
        row.next_attempt_at = utcnow()
    assert await service.deliver_pending() == 1
    with session_factory() as session:
        row = session.get(TelemetryOutbox, "00000000-0000-0000-0000-000000000777")
        assert row.delivered_at is not None
        assert row.attempts == 2
        assert row.last_error is None


def test_integer_environment_parser_and_placeholder_secrets_fail_closed(monkeypatch):
    from tracefence.config import _int_env

    monkeypatch.setenv("TRACEFENCE_TEST_INTEGER", "not-a-number")
    with pytest.raises(RuntimeError, match="must be an integer"):
        _int_env("TRACEFENCE_TEST_INTEGER", 1)

    insecure = replace(
        settings,
        environment="development",
        operator_key="generate-a-unique-operator-key-at-least-24-characters",
        token_hash_secret="x" * 48,
    )
    with pytest.raises(RuntimeError, match="placeholder"):
        insecure.validate_security()
