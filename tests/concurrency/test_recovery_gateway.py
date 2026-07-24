from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select

from tests.helpers import activate, create_seeded_run
from tracefence.db.models import ActionAttempt, ServiceState
from tracefence.domain.enums import ActionDecision, CommandType, IssuerType
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal, SpawnCreate
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.spawn_service import SpawnService


async def _active_recovery_node(session_factory, key: str):
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run = await create_seeded_run(session_factory, key)
    old = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                role="investigator",
                instruction={"task": "investigate redis"},
                capabilities=["tool:reset_redis_pool"],
            ),
        ),
    )
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key=f"{key}-correct",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=old.node_id,
            reason_code="RECOVER",
            reason_text="replace with constrained recovery worker",
            replacement_instruction={"task": "reset redis"},
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
                instruction={"task": "reset redis"},
                capabilities=["tool:reset_redis_pool"],
            ),
        ),
    )
    return run, command, replacement


async def test_wrong_recovery_tool_is_denied_before_execution(session_factory):
    run, _command, replacement = await _active_recovery_node(
        session_factory, "wrong-recovery-tool"
    )
    gateway = ActionGateway(session_factory)

    result = await gateway.execute(
        replacement.node_id,
        replacement.node_token,
        ActionExecute(
            idempotency_key="wrong-recovery-tool-action",
            tool_name="restart_postgres",
            arguments={},
        ),
    )

    assert result.decision == ActionDecision.DENY
    assert result.denial_reason == "RECOVERY_TOOL_MISMATCH"
    with session_factory() as session:
        postgres = session.get(ServiceState, (run.run_id, "postgres"))
        assert postgres is not None
        assert postgres.restart_count == 0


async def test_wrong_recovery_arguments_are_denied_before_execution(session_factory):
    run, _command, replacement = await _active_recovery_node(
        session_factory, "wrong-recovery-arguments"
    )
    gateway = ActionGateway(session_factory)

    result = await gateway.execute(
        replacement.node_id,
        replacement.node_token,
        ActionExecute(
            idempotency_key="wrong-recovery-arguments-action",
            tool_name="reset_redis_pool",
            arguments={"resource": "another-redis"},
        ),
    )

    assert result.decision == ActionDecision.DENY
    assert result.denial_reason == "RECOVERY_ARGUMENTS_MISMATCH"
    with session_factory() as session:
        redis = session.get(ServiceState, (run.run_id, "redis"))
        assert redis is not None
        assert redis.pool_reset_count == 0


async def test_recovery_invocation_limit_is_checked_before_second_side_effect(
    session_factory,
):
    run, _command, replacement = await _active_recovery_node(
        session_factory, "recovery-invocation-limit"
    )
    gateway = ActionGateway(session_factory)
    def request(key: str) -> ActionExecute:
        return ActionExecute(
            idempotency_key=key,
            tool_name="reset_redis_pool",
            arguments={},
        )

    first = await gateway.execute(
        replacement.node_id,
        replacement.node_token,
        request("recovery-limit-first"),
    )
    second = await gateway.execute(
        replacement.node_id,
        replacement.node_token,
        request("recovery-limit-second"),
    )

    assert first.decision == ActionDecision.ALLOW
    assert second.decision == ActionDecision.DENY
    assert second.denial_reason == "RECOVERY_INVOCATION_LIMIT_EXCEEDED"
    with session_factory() as session:
        redis = session.get(ServiceState, (run.run_id, "redis"))
        assert redis is not None
        assert redis.pool_reset_count == 1


async def test_concurrent_recovery_invocations_commit_exactly_one_side_effect(
    session_factory,
):
    run, _command, replacement = await _active_recovery_node(
        session_factory, "concurrent-recovery-limit"
    )
    gateway = ActionGateway(session_factory)

    def invoke(key: str):
        return asyncio.run(
            gateway.execute(
                replacement.node_id,
                replacement.node_token,
                ActionExecute(
                    idempotency_key=key,
                    tool_name="reset_redis_pool",
                    arguments={},
                ),
            )
        )

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = await asyncio.gather(
            loop.run_in_executor(pool, invoke, "concurrent-recovery-a"),
            loop.run_in_executor(pool, invoke, "concurrent-recovery-b"),
        )

    assert sorted([first.decision, second.decision]) == [
        ActionDecision.ALLOW,
        ActionDecision.DENY,
    ]
    denied = first if first.decision == ActionDecision.DENY else second
    assert denied.denial_reason == "RECOVERY_INVOCATION_LIMIT_EXCEEDED"
    with session_factory() as session:
        redis = session.get(ServiceState, (run.run_id, "redis"))
        attempts = session.execute(
            select(ActionAttempt).where(
                ActionAttempt.node_id == replacement.node_id,
                ActionAttempt.decision == ActionDecision.ALLOW,
            )
        ).scalars().all()
        assert redis is not None
        assert redis.pool_reset_count == 1
        assert len(attempts) == 1
