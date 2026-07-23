import pytest

from tracefence.domain.enums import ActionDecision, CommandType, IssuerType
from tracefence.domain.errors import AuthenticationError, ConflictError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal, SpawnCreate
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService
from tests.helpers import activate, create_seeded_run


async def test_action_idempotency_prevents_duplicate_side_effect(session_factory):
    spawns = SpawnService(session_factory)
    gateway = ActionGateway(session_factory)
    states = StateService(session_factory)
    run = await create_seeded_run(session_factory, "idempotency")
    spawned = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="recovery", capabilities=["tool:reset_redis_pool"]),
    )
    active = await activate(spawns, spawned)
    request = ActionExecute(
        idempotency_key="same-action", tool_name="reset_redis_pool", arguments={}
    )
    first = await gateway.execute(active.node_id, active.node_token, request)
    second = await gateway.execute(active.node_id, active.node_token, request)
    assert first.decision == ActionDecision.ALLOW
    assert second.duplicate is True
    service_states = {
        row["service_name"]: row for row in await states.list_states(run.run_id)
    }
    assert service_states["redis"]["pool_reset_count"] == 1


async def test_action_replay_authenticates_and_binds_payload(session_factory):
    spawns = SpawnService(session_factory)
    gateway = ActionGateway(session_factory)
    run = await create_seeded_run(session_factory, "action-replay")
    spawned = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(
            role="reader",
            capabilities=["tool:read_metrics", "tool:restart_postgres"],
        ),
    )
    active = await activate(spawns, spawned)
    original = ActionExecute(
        idempotency_key="replay-key", tool_name="read_metrics", arguments={}
    )
    await gateway.execute(active.node_id, active.node_token, original)

    with pytest.raises(AuthenticationError):
        await gateway.execute(active.node_id, "invalid-token", original)
    with pytest.raises(ConflictError) as exc:
        await gateway.execute(
            active.node_id,
            active.node_token,
            ActionExecute(
                idempotency_key="replay-key",
                tool_name="restart_postgres",
                arguments={},
            ),
        )
    assert exc.value.code == "IDEMPOTENCY_PAYLOAD_MISMATCH"


async def test_command_replay_authenticates_and_binds_payload(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, "command-replay")
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="worker", capabilities=[]),
        ),
    )
    request = CommandCreate(
        idempotency_key="command-key",
        command_type=CommandType.CANCEL_SUBTREE,
        target_node_id=child.node_id,
        reason_code="TEST",
        reason_text="test",
    )
    first = await controls.issue_command(
        request, Principal(issuer_type=IssuerType.HUMAN)
    )
    replay = await controls.issue_command(
        request, Principal(issuer_type=IssuerType.HUMAN)
    )
    assert replay.command_id == first.command_id
    assert replay.duplicate is True

    with pytest.raises(ConflictError) as exc:
        await controls.issue_command(
            request.model_copy(update={"reason_text": "different"}),
            Principal(issuer_type=IssuerType.HUMAN),
        )
    assert exc.value.code == "IDEMPOTENCY_PAYLOAD_MISMATCH"


async def test_unauthenticated_caller_cannot_probe_tool_registry(session_factory):
    from tracefence.domain.errors import AuthenticationError
    from tracefence.domain.schemas import ActionExecute
    from tracefence.services.action_gateway import ActionGateway

    run = await create_seeded_run(session_factory, "tool-oracle")
    gateway = ActionGateway(session_factory)
    with pytest.raises(AuthenticationError):
        await gateway.execute(
            run.root_node_id,
            "invalid-token",
            ActionExecute(
                idempotency_key="probe",
                tool_name="nonexistent_sensitive_tool",
                arguments={},
            ),
        )
