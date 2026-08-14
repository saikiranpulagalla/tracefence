from __future__ import annotations

from tests.helpers import activate, create_seeded_run
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.schemas import (
    ActionExecute,
    CommandCreate,
    Principal,
    SpawnCreate,
)
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService


async def test_checkpoint_wait_state_and_timeline_are_authoritative(session_factory):
    run = await create_seeded_run(session_factory, "inspector-waiting")
    spawns = SpawnService(session_factory)
    worker = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                role="postgres-worker",
                capabilities=["tool:restart_postgres"],
                behavior="non_compliant",
            ),
        ),
    )

    checkpoint = await spawns.checkpoint(
        worker.node_id, worker.node_token, "before_protected_action"
    )
    assert checkpoint.allowed is True

    state = StateService(session_factory)
    events = await state.list_events(run.run_id, after=0, limit=100)
    waiting = [event for event in events if event["event_type"] == "NODE_WAITING"]
    assert len(waiting) == 1
    assert waiting[0]["node_id"] == worker.node_id
    assert waiting[0]["metadata"] == {"stage": "before_protected_action"}
    assert [event["sequence"] for event in events] == sorted(
        event["sequence"] for event in events
    )


async def test_action_detail_is_the_persisted_gateway_explanation(session_factory):
    run = await create_seeded_run(session_factory, "inspector-action-detail")
    spawns = SpawnService(session_factory)
    worker = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                role="postgres-worker",
                capabilities=["tool:restart_postgres"],
            ),
        ),
    )
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="inspector-detail-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=worker.node_id,
            reason_code="DEMO_CANCEL",
            reason_text="exercise cancellation",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    denied = await ActionGateway(session_factory).execute(
        worker.node_id,
        worker.node_token,
        ActionExecute(
            idempotency_key="inspector-detail-action",
            tool_name="restart_postgres",
            arguments={},
        ),
    )

    detail = await StateService(session_factory).get_action(
        run.run_id, denied.action_id
    )
    assert detail["id"] == denied.action_id
    assert detail["decision"] == "DENY"
    assert detail["decision_explanation"]["final_reason"] == "SCOPE_CANCELLED"
    assert detail["scope_evaluation"]["allowed"] is False
