from __future__ import annotations

from dataclasses import replace

import pytest
from sqlalchemy import func, select

from tracefence.db.models import ActionAttempt, ServiceState
from tracefence.domain.enums import ActionDecision
from tracefence.domain.schemas import ActionExecute, RunCreate
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.run_service import RunService
from tracefence.services.tool_registry import TOOL_REGISTRY


async def _unseeded_run(session_factory, name: str):
    return await RunService(session_factory).create_run(
        RunCreate(
            name=name,
            root_capabilities=[
                "tool:restart_postgres",
                "tool:reset_redis_pool",
            ],
        )
    )


@pytest.mark.parametrize(
    ("tool_name", "service_name", "counter_name"),
    [
        ("restart_postgres", "postgres", "restart_count"),
        ("reset_redis_pool", "redis", "pool_reset_count"),
    ],
)
async def test_first_mutating_action_on_unseeded_run_commits_atomically(
    session_factory,
    tool_name,
    service_name,
    counter_name,
):
    run = await _unseeded_run(session_factory, f"unseeded-{tool_name}")

    result = await ActionGateway(session_factory).execute(
        run.root_node_id,
        run.root_token,
        ActionExecute(
            idempotency_key=f"first-{tool_name}",
            tool_name=tool_name,
            arguments={},
        ),
    )

    assert result.decision == ActionDecision.ALLOW
    assert result.committed is True
    with session_factory() as session:
        action = session.get(ActionAttempt, result.action_id)
        state = session.get(ServiceState, (run.run_id, service_name))
        assert action is not None
        assert state is not None
        assert state.last_action_id == action.id
        assert getattr(state, counter_name) == 1


async def test_executor_failure_rolls_back_action_and_service_state_together(
    session_factory,
    monkeypatch,
):
    run = await _unseeded_run(session_factory, "atomic-executor-rollback")
    original = TOOL_REGISTRY["restart_postgres"]

    def mutate_then_fail(session, run_id, action_id, _arguments):
        session.add(
            ServiceState(
                run_id=run_id,
                service_name="postgres",
                status="mutated-before-failure",
                restart_count=1,
                pool_reset_count=0,
                last_action_id=action_id,
            )
        )
        raise RuntimeError("simulated executor failure")

    monkeypatch.setitem(
        TOOL_REGISTRY,
        "restart_postgres",
        replace(original, executor=mutate_then_fail),
    )

    with pytest.raises(RuntimeError, match="simulated executor failure"):
        await ActionGateway(session_factory).execute(
            run.root_node_id,
            run.root_token,
            ActionExecute(
                idempotency_key="atomic-failing-action",
                tool_name="restart_postgres",
                arguments={},
            ),
        )

    with session_factory() as session:
        action_count = session.scalar(
            select(func.count(ActionAttempt.id)).where(
                ActionAttempt.run_id == run.run_id
            )
        )
        state = session.get(ServiceState, (run.run_id, "postgres"))
        assert action_count == 0
        assert state is None
