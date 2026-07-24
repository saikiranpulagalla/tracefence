from __future__ import annotations

import pytest

from tests.helpers import activate, create_seeded_run
from tracefence.db.models import ServiceState
from tracefence.domain.enums import CommandType, IssuerType, ProofVerdict
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal, SpawnCreate
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.proof_service import ProofService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService


async def _corrected_recovery(session_factory, *, key: str = "proof-contract"):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    run = await create_seeded_run(session_factory, key)
    old = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                role="database_investigator",
                instruction={"task": "investigate postgres"},
                capabilities=["tool:restart_postgres", "tool:read_metrics"],
            ),
        ),
    )
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key=f"{key}-correct",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=old.node_id,
            reason_code="WRONG_ROOT_CAUSE",
            reason_text="Redis is causal",
            replacement_instruction={"task": "reset redis pool"},
            replacement_expected_tool="reset_redis_pool",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    await spawns.checkpoint(old.node_id, old.node_token, "after_evidence")
    replacement_spawn = await spawns.create_replacement(
        run.root_node_id,
        run.root_token,
        command.command_id,
        SpawnCreate(
            role="redis_recovery",
            behavior="cooperative",
            instruction={"task": "reset redis pool"},
            capabilities=["tool:reset_redis_pool"],
        ),
    )
    replacement = await activate(spawns, replacement_spawn)
    action = await gateway.execute(
        replacement.node_id,
        replacement.node_token,
        ActionExecute(
            idempotency_key=f"{key}-recover",
            tool_name="reset_redis_pool",
            arguments={},
        ),
    )
    await spawns.complete(replacement.node_id, replacement.node_token)
    return run, old, command, replacement, action


async def test_recovery_proof_rechecks_current_authoritative_postconditions(session_factory):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="false-recovery"
    )
    proofs = ProofService(session_factory)

    first = await proofs.build(command.command_id)
    assert first.recovery_action_verdict == ProofVerdict.VERIFIED
    assert first.recovery_postcondition_verdict == ProofVerdict.VERIFIED
    assert first.recovery_outcome_verdict == ProofVerdict.VERIFIED

    with session_factory() as session, session.begin():
        redis = session.get(ServiceState, (run.run_id, "redis"))
        checkout = session.get(ServiceState, (run.run_id, "checkout"))
        assert redis is not None and checkout is not None
        redis.status = "connection_pool_exhausted"
        redis.last_action_id = None
        redis.updated_at = utcnow()
        checkout.status = "degraded"
        checkout.last_action_id = None
        checkout.updated_at = utcnow()

    second = await proofs.build(command.command_id)
    assert second.recovery_action_verdict == ProofVerdict.VERIFIED
    assert second.recovery_postcondition_verdict == ProofVerdict.INCONSISTENT
    assert second.recovery_outcome_verdict == ProofVerdict.INCONSISTENT
    assert second.runtime_verdict == ProofVerdict.INCONSISTENT
    assert any("Recovery postcondition failed" in item for item in second.discrepancies)


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        (
            {"replacement_role": "arbitrary_root_agent"},
            "REPLACEMENT_ROLE_POLICY_VIOLATION",
        ),
        (
            {"replacement_behavior": "non_compliant"},
            "REPLACEMENT_BEHAVIOR_POLICY_VIOLATION",
        ),
        (
            {
                "replacement_capabilities": [
                    "tool:reset_redis_pool",
                    "tool:restart_postgres",
                ]
            },
            "REPLACEMENT_CAPABILITY_POLICY_VIOLATION",
        ),
        (
            {"replacement_max_children": 1},
            "REPLACEMENT_CHILD_BUDGET_POLICY_VIOLATION",
        ),
    ],
)
async def test_correction_rejects_overprivileged_replacement_manifest(
    session_factory, overrides, code
):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, f"manifest-{code}")
    old = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="database_investigator", capabilities=[]),
        ),
    )
    with pytest.raises(ConflictError) as exc:
        await controls.issue_command(
            CommandCreate(
                idempotency_key=f"manifest-{code}",
                command_type=CommandType.CORRECT_SUBTREE,
                target_node_id=old.node_id,
                reason_code="TEST",
                reason_text="test policy",
                replacement_instruction={"task": "reset redis pool"},
                replacement_expected_tool="reset_redis_pool",
                **overrides,
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
    assert exc.value.code == code


async def test_replacement_creation_requires_exact_frozen_manifest(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "manifest-spawn")
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
            idempotency_key="manifest-spawn-command",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=old.node_id,
            reason_code="TEST",
            reason_text="test",
            replacement_instruction={"task": "reset redis pool"},
            replacement_expected_tool="reset_redis_pool",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    with pytest.raises(ConflictError) as exc:
        await spawns.create_replacement(
            run.root_node_id,
            run.root_token,
            command.command_id,
            SpawnCreate(
                role="evil_replacement",
                behavior="non_compliant",
                instruction={"task": "reset redis pool"},
                capabilities=["tool:reset_redis_pool", "tool:restart_postgres"],
            ),
        )
    assert exc.value.code == "REPLACEMENT_MANIFEST_MISMATCH"


async def test_replacement_child_budget_is_enforced(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "replacement-budget")
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
            idempotency_key="replacement-budget-command",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=old.node_id,
            reason_code="TEST",
            reason_text="test",
            replacement_instruction={"task": "reset redis pool"},
            replacement_expected_tool="reset_redis_pool",
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
                behavior="cooperative",
                instruction={"task": "reset redis pool"},
                capabilities=["tool:reset_redis_pool"],
            ),
        ),
    )
    with pytest.raises(ConflictError) as exc:
        await spawns.create_spawn(
            replacement.node_id,
            replacement.node_token,
            SpawnCreate(role="unexpected-child", capabilities=[]),
        )
    assert exc.value.code == "REPLACEMENT_CHILD_BUDGET_EXCEEDED"


async def test_overlapping_commands_acknowledge_every_applicable_scope(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    proofs = ProofService(session_factory)
    run = await create_seeded_run(session_factory, "overlapping-commands")
    parent = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                role="parent",
                capabilities=["tool:restart_postgres"],
            ),
        ),
    )
    child = await activate(
        spawns,
        await spawns.create_spawn(
            parent.node_id,
            parent.node_token,
            SpawnCreate(
                role="child",
                behavior="non_compliant",
                capabilities=["tool:restart_postgres"],
            ),
        ),
    )
    narrow = await controls.issue_command(
        CommandCreate(
            idempotency_key="cancel-child",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=child.node_id,
            reason_code="NARROW",
            reason_text="cancel child",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    broad = await controls.issue_command(
        CommandCreate(
            idempotency_key="cancel-parent",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=parent.node_id,
            reason_code="BROAD",
            reason_text="cancel parent",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    denied = await gateway.execute(
        child.node_id,
        child.node_token,
        ActionExecute(
            idempotency_key="child-stale-action",
            tool_name="restart_postgres",
            arguments={},
        ),
    )
    assert denied.committed is False
    await spawns.checkpoint(parent.node_id, parent.node_token, "observe_broad_cancel")

    narrow_proof = await proofs.build(narrow.command_id)
    broad_proof = await proofs.build(broad.command_id)
    assert narrow_proof.control_convergence_verdict == ProofVerdict.VERIFIED
    assert broad_proof.control_convergence_verdict == ProofVerdict.VERIFIED
    assert narrow_proof.stale_action_attempts == 1
    assert broad_proof.stale_action_attempts == 1


async def test_scenario_fixture_is_one_shot_and_cannot_erase_history(session_factory):
    states = StateService(session_factory)
    run = await create_seeded_run(session_factory, "one-shot-seed")
    with pytest.raises(ConflictError) as exc:
        await states.seed_scenario(run.run_id)
    assert exc.value.code == "SCENARIO_ALREADY_INITIALIZED"
