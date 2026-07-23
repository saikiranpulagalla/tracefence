from __future__ import annotations

from tracefence.domain.enums import ActionDecision, CommandType, IssuerType, ProofVerdict
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal, SpawnCreate
from tracefence.db.models import ActionAttempt
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.graph_service import GraphService
from tracefence.services.proof_service import ProofService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService
from tracefence.signoz.mcp_client import TelemetryProof
from tests.helpers import activate, create_seeded_run


async def test_hierarchical_scope_blocks_stale_descendant_and_preserves_sibling(
    session_factory,
):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    states = StateService(session_factory)
    graph_service = GraphService(session_factory)
    run = await create_seeded_run(session_factory, "checkout-incident")

    database_spawn = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(
            role="database_investigator",
            instruction={"task": "investigate postgres"},
            capabilities=["tool:restart_postgres", "tool:read_metrics"],
        ),
    )
    database = await activate(spawns, database_spawn)
    child_spawn = await spawns.create_spawn(
        database.node_id,
        database.node_token,
        SpawnCreate(
            role="non_compliant_child",
            instruction={"task": "restart postgres"},
            capabilities=["tool:restart_postgres"],
            behavior="non_compliant",
        ),
    )
    child = await activate(spawns, child_spawn)
    sibling_spawn = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(
            role="metrics_investigator",
            instruction={"task": "read metrics"},
            capabilities=["tool:read_metrics"],
        ),
    )
    sibling = await activate(spawns, sibling_spawn)

    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="correct-db-001",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=database.node_id,
            reason_code="WRONG_ROOT_CAUSE",
            reason_text="Redis, not PostgreSQL, is failing",
            replacement_instruction={"task": "investigate redis"},
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    cooperative = await spawns.checkpoint(
        database.node_id, database.node_token, "before_action"
    )
    assert cooperative.allowed is False
    assert cooperative.effective_status.value == "SUPERSEDED"

    stale = await gateway.execute(
        child.node_id,
        child.node_token,
        ActionExecute(
            idempotency_key="restart-postgres-001",
            tool_name="restart_postgres",
            arguments={},
        ),
    )
    assert stale.decision == ActionDecision.DENY
    assert stale.denial_reason == "SCOPE_SUPERSEDED"
    assert stale.committed is False

    sibling_result = await gateway.execute(
        sibling.node_id,
        sibling.node_token,
        ActionExecute(
            idempotency_key="read-metrics-001",
            tool_name="read_metrics",
            arguments={},
        ),
    )
    assert sibling_result.decision == ActionDecision.ALLOW
    assert sibling_result.committed is True

    graph = await graph_service.get_graph(run.run_id)
    by_id = {node.id: node for node in graph.nodes}
    assert by_id[database.node_id].effective_status.value == "SUPERSEDED"
    assert by_id[child.node_id].effective_status.value == "SUPERSEDED"
    assert by_id[sibling.node_id].effective_status.value == "ACTIVE"

    service_states = {
        row["service_name"]: row for row in await states.list_states(run.run_id)
    }
    assert service_states["postgres"]["restart_count"] == 0
    assert command.status == "SUPERSEDED"


async def test_correction_replacement_and_recovery_are_proven(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    states = StateService(session_factory)
    proofs = ProofService(session_factory)
    run = await create_seeded_run(session_factory, "replacement-test")

    old_spawn = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(
            role="database_investigator",
            capabilities=["tool:restart_postgres", "tool:read_metrics"],
        ),
    )
    old = await activate(spawns, old_spawn)
    child_spawn = await spawns.create_spawn(
        old.node_id,
        old.node_token,
        SpawnCreate(
            role="non_compliant_child",
            capabilities=["tool:restart_postgres"],
            behavior="non_compliant",
        ),
    )
    child = await activate(spawns, child_spawn)

    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="correct-db-002",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=old.node_id,
            reason_code="WRONG_ROOT_CAUSE",
            reason_text="Use Redis evidence",
            replacement_instruction={"task": "reset redis pool"},
            replacement_expected_tool="reset_redis_pool",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    await spawns.checkpoint(old.node_id, old.node_token, "after_evidence")
    denied = await gateway.execute(
        child.node_id,
        child.node_token,
        ActionExecute(
            idempotency_key="stale-restart-002",
            tool_name="restart_postgres",
            arguments={},
        ),
    )
    assert denied.decision == ActionDecision.DENY

    replacement_spawn = await spawns.create_replacement(
        run.root_node_id,
        run.root_token,
        command.command_id,
        SpawnCreate(
            role="redis_recovery",
            instruction={"task": "reset redis pool"},
            capabilities=["tool:reset_redis_pool"],
        ),
    )
    replacement = await activate(spawns, replacement_spawn)
    allowed = await gateway.execute(
        replacement.node_id,
        replacement.node_token,
        ActionExecute(
            idempotency_key="reset-redis-002",
            tool_name="reset_redis_pool",
            arguments={},
        ),
    )
    assert allowed.decision == ActionDecision.ALLOW
    await spawns.complete(replacement.node_id, replacement.node_token)

    proof = await proofs.build(command.command_id)
    assert proof.control_convergence_verdict == ProofVerdict.VERIFIED
    assert proof.replacement_lineage_verdict == ProofVerdict.VERIFIED
    assert proof.recovery_outcome_verdict == ProofVerdict.VERIFIED
    assert proof.runtime_verdict == ProofVerdict.VERIFIED
    assert proof.telemetry_verdict == ProofVerdict.UNAVAILABLE
    assert proof.overall_verdict == ProofVerdict.UNAVAILABLE
    assert proof.affected_registered_nodes == 2
    assert proof.classifications["ACKNOWLEDGED"] == 1
    assert proof.classifications["BLOCKED_AT_GATEWAY"] == 1
    assert proof.stale_action_attempts == 1
    assert proof.stale_actions_committed == 0
    assert proof.unrelated_branches_interrupted == 0

    service_states = {
        row["service_name"]: row for row in await states.list_states(run.run_id)
    }
    assert service_states["postgres"]["restart_count"] == 0
    assert service_states["redis"]["pool_reset_count"] == 1
    assert service_states["checkout"]["status"] == "healthy"


class _CountingMCPClient:
    def __init__(self):
        self.calls = 0

    async def verify_command(self, **_kwargs):
        import asyncio

        self.calls += 1
        await asyncio.sleep(0.05)
        return TelemetryProof(
            verdict=ProofVerdict.UNAVAILABLE,
            trace_ids=[],
            discrepancies=["test MCP unavailable"],
            evidence={},
        )


async def test_concurrent_proof_requests_are_single_flight(session_factory):
    import asyncio

    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    run = await create_seeded_run(session_factory, "proof-single-flight")

    parent_spawn = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(
            role="database_investigator",
            capabilities=["tool:restart_postgres"],
        ),
    )
    parent = await activate(spawns, parent_spawn)
    child_spawn = await spawns.create_spawn(
        parent.node_id,
        parent.node_token,
        SpawnCreate(
            role="non_compliant_child",
            capabilities=["tool:restart_postgres"],
            behavior="non_compliant",
        ),
    )
    child = await activate(spawns, child_spawn)

    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="proof-single-flight-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=parent.node_id,
            reason_code="TEST_CANCEL",
            reason_text="Verify single-flight proof generation",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    await spawns.checkpoint(parent.node_id, parent.node_token, "after_cancel")
    await gateway.execute(
        child.node_id,
        child.node_token,
        ActionExecute(
            idempotency_key="proof-single-flight-action",
            tool_name="restart_postgres",
            arguments={},
        ),
    )

    mcp = _CountingMCPClient()
    proofs = ProofService(session_factory, mcp_client=mcp)
    first, second = await asyncio.gather(
        proofs.build(command.command_id),
        proofs.build(command.command_id),
    )

    assert mcp.calls == 1
    assert first == second
    assert first.runtime_verdict == ProofVerdict.VERIFIED


async def test_stale_action_attribution_pairs_command_with_its_exact_scope_mismatch(
    session_factory,
):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    run = await create_seeded_run(session_factory, "nested-command-attribution")

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
                capabilities=["tool:restart_postgres"],
            ),
        ),
    )

    await controls.issue_command(
        CommandCreate(
            idempotency_key="supersede-child-first",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=child.node_id,
            reason_code="CHILD_WRONG",
            reason_text="Supersede the child first",
            replacement_instruction={"task": "replacement"},
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    parent_cancel = await controls.issue_command(
        CommandCreate(
            idempotency_key="cancel-parent-second",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=parent.node_id,
            reason_code="PARENT_CANCELLED",
            reason_text="Cancel the ancestor after child correction",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    result = await gateway.execute(
        child.node_id,
        child.node_token,
        ActionExecute(
            idempotency_key="nested-stale-action",
            tool_name="restart_postgres",
            arguments={},
        ),
    )
    assert result.decision == ActionDecision.DENY

    with session_factory() as session:
        attempt = session.get(ActionAttempt, result.action_id)
        assert attempt.matched_command_id == parent_cancel.command_id
        assert attempt.matched_scope_id == parent_cancel.target_scope_id
        assert attempt.matched_live_status == "CANCELLED"


async def test_proof_fails_closed_if_affected_scope_is_corrupted_back_to_active(session_factory):
    from tracefence.db.models import ControlScope, Node

    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "proof-corruption")
    target = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="target", capabilities=[]),
        ),
    )
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="proof-corruption-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=target.node_id,
            reason_code="TEST",
            reason_text="create affected branch",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session, session.begin():
        node = session.get(Node, target.node_id)
        scope = session.get(ControlScope, node.own_scope_id)
        scope.version = 1
        scope.status = "ACTIVE"

    proof = await ProofService(session_factory).build(command.command_id)
    assert proof.control_convergence_verdict != ProofVerdict.VERIFIED
    assert proof.runtime_verdict != ProofVerdict.VERIFIED
    assert any("remained scope-valid" in item for item in proof.discrepancies)
