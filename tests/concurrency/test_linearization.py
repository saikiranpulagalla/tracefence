from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from tracefence.domain.enums import ActionDecision, CommandType, IssuerType
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal, SpawnCreate
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService
from tests.helpers import activate, create_seeded_run


async def test_command_action_race_has_only_two_linearizable_outcomes(session_factory):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    states = StateService(session_factory)
    run = await create_seeded_run(session_factory, "race")
    spawned = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="database", capabilities=["tool:restart_postgres"]),
    )
    active = await activate(spawns, spawned)

    barrier = Barrier(2)

    def issue_command():
        barrier.wait()
        return asyncio.run(
            controls.issue_command(
                CommandCreate(
                    idempotency_key="race-command",
                    command_type=CommandType.CORRECT_SUBTREE,
                    target_node_id=active.node_id,
                    reason_code="CORRECTION",
                    reason_text="new evidence",
                    replacement_instruction={"task": "use redis"},
                ),
                Principal(issuer_type=IssuerType.HUMAN),
            )
        )

    def issue_action():
        barrier.wait()
        return asyncio.run(
            gateway.execute(
                active.node_id,
                active.node_token,
                ActionExecute(
                    idempotency_key="race-action",
                    tool_name="restart_postgres",
                    arguments={},
                ),
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        command_future = pool.submit(issue_command)
        action_future = pool.submit(issue_action)
        command_future.result(timeout=10)
        action = action_future.result(timeout=10)

    service_states = {
        row["service_name"]: row for row in await states.list_states(run.run_id)
    }
    restart_count = service_states["postgres"]["restart_count"]
    if action.decision == ActionDecision.ALLOW:
        assert action.committed is True
        assert restart_count == 1
    else:
        assert action.denial_reason == "SCOPE_SUPERSEDED"
        assert action.committed is False
        assert restart_count == 0
