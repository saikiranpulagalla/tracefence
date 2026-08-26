from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

import tracefence.services.operation_lifecycle as lifecycle_module
from tests.helpers import create_v2_run
from tracefence.db.models import ActionAttempt, Node, WorkerInstance
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal
from tracefence.security import hash_token
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.operation_lifecycle import DispatchClaimStatus, OperationLifecycleService
from tracefence.services.tool_registry import TOOL_REGISTRY, ToolSpec

REPETITIONS = range(25)
TOOL_NAME = "test_b2_ordering_tool"
CAPABILITY = "tool:test_b2_ordering_tool"
CASES = (
    "cancel-before-dispatch",
    "dispatch-before-cancel-before-first-effect",
    "cancel-between-effects",
    "final-check-before-cancel-before-result",
    "uncertain-before-first-effect",
    "uncertain-between-effects",
    "w2-before-w1-checkpoint",
    "concurrent-authorized-duplicate",
    "sequential-already-dispatched-duplicate",
)


@dataclass
class Counts:
    executor: int = 0
    effect_1: int = 0
    effect_2: int = 0
    returned: int = 0


def _request(key: str) -> ActionExecute:
    return ActionExecute(idempotency_key=key, tool_name=TOOL_NAME, arguments={})


async def _run(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        node.capabilities_json = [*(node.capabilities_json or []), CAPABILITY]
    return run


async def _cancel(session_factory, run, key: str) -> None:
    await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key=key,
            command_type=CommandType.CANCEL_RUN,
            target_node_id=run.root_node_id,
            reason_code="TEST",
            reason_text="B2 deterministic ordering",
        ),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="b2-race"),
    )


def _replace_worker(session_factory, node_id: str) -> None:
    with session_factory.begin() as session:
        node = session.get(Node, node_id)
        assert node is not None and node.current_worker_instance_id is not None
        old = session.get(WorkerInstance, node.current_worker_instance_id)
        assert old is not None
        replacement = WorkerInstance(
            id=str(uuid4()),
            node_id=node.id,
            incarnation=old.incarnation + 1,
            observed_state="ACTIVE",
            activated_at=old.activated_at,
            credential_hash=hash_token("b2-race-w2"),
        )
        session.add(replacement)
        session.flush()
        node.current_worker_instance_id = replacement.id


def _action(session_factory, run_id: str) -> ActionAttempt:
    with session_factory() as session:
        action = session.scalar(select(ActionAttempt).where(ActionAttempt.run_id == run_id))
        assert action is not None
        return action


def _install(monkeypatch, counts: Counts, executor) -> None:
    monkeypatch.setitem(
        TOOL_REGISTRY,
        TOOL_NAME,
        ToolSpec(
            name=TOOL_NAME,
            capability=CAPABILITY,
            side_effecting=True,
            allowed_argument_keys=frozenset(),
            resources=frozenset({"test"}),
            execution_mode="cooperative",
            cooperative_executor=executor,
        ),
    )


@pytest.mark.parametrize("iteration", REPETITIONS)
@pytest.mark.parametrize("case", CASES)
async def test_cooperative_ordering_matrix(session_factory, monkeypatch, iteration, case):
    counts = Counts()
    run = await _run(session_factory, f"b2-race-{case}-{iteration}")
    gateway = ActionGateway(session_factory)
    lifecycle = OperationLifecycleService(session_factory)
    request = _request(f"{case}-{iteration}")

    async def success(context, _arguments):
        counts.executor += 1
        await context.checkpoint()
        counts.effect_1 += 1
        await context.checkpoint()
        counts.effect_2 += 1
        counts.returned += 1
        return {"effects": 2}

    if case == "uncertain-between-effects":
        async def uncertain_between(context, _arguments):
            counts.executor += 1
            await context.checkpoint()
            counts.effect_1 += 1
            async def unavailable(*_args, **_kwargs):
                raise OperationalError("SELECT", {}, Exception("busy"))
            monkeypatch.setattr(lifecycle_module, "_evaluate_live_bound_action_authority", unavailable)
            await context.checkpoint()
            return {"unreachable": True}
        _install(monkeypatch, counts, uncertain_between)
        with pytest.raises(ConflictError) as error:
            await gateway.execute(run.root_node_id, run.root_token, request)
        assert error.value.code == "OPERATION_AUTHORITY_UNCERTAIN"
        assert _action(session_factory, run.run_id).execution_state == "DISPATCHED"
        assert counts.effect_1 == 1
        assert counts.effect_2 == counts.returned == 0
        return

    if case == "concurrent-authorized-duplicate":
        executor_started = asyncio.Event()
        release_executor = asyncio.Event()
        first_at_claim = asyncio.Event()
        second_at_claim = asyncio.Event()
        release_claims = asyncio.Event()
        claim_statuses = []
        claim_calls = 0
        original_claim = OperationLifecycleService.mark_dispatched
        async def executor(_context, _arguments):
            counts.executor += 1
            executor_started.set()
            await release_executor.wait()
            counts.returned += 1
            return {"effects": 0}
        async def delayed_claim(self, **kwargs):
            nonlocal claim_calls
            claim_calls += 1
            (first_at_claim if claim_calls == 1 else second_at_claim).set()
            await release_claims.wait()
            claim = await original_claim(self, **kwargs)
            claim_statuses.append(claim.status)
            return claim
        _install(monkeypatch, counts, executor)
        monkeypatch.setattr(OperationLifecycleService, "mark_dispatched", delayed_claim)
        first = asyncio.create_task(gateway.execute(run.root_node_id, run.root_token, request))
        await first_at_claim.wait()
        second = asyncio.create_task(gateway.execute(run.root_node_id, run.root_token, request))
        await second_at_claim.wait()
        release_claims.set()
        await executor_started.wait()
        release_executor.set()
        first_result, second_result = await asyncio.gather(first, second)
        assert first_result.action_id == second_result.action_id
        assert claim_statuses.count(DispatchClaimStatus.CLAIMED) == 1
        assert claim_statuses.count(DispatchClaimStatus.ALREADY_DISPATCHED) == 1
        assert counts.executor == counts.returned == 1
        return

    if case == "cancel-before-dispatch":
        _install(monkeypatch, counts, success)
        reserved = await lifecycle.reserve(
            node_id=run.root_node_id,
            credential=run.root_token,
            request=request,
            required_capability=CAPABILITY,
        )
        await _cancel(session_factory, run, f"{case}-cancel-{iteration}")
        result = await gateway.execute(run.root_node_id, run.root_token, request)
        assert result.duplicate is True
        assert _action(session_factory, run.run_id).id == reserved.id
        assert _action(session_factory, run.run_id).execution_state == "STALE"
        assert counts.executor == counts.effect_1 == counts.effect_2 == 0
        return

    if case == "dispatch-before-cancel-before-first-effect":
        async def cancel_then_check(context, _arguments):
            counts.executor += 1
            await _cancel(session_factory, run, f"{case}-cancel-{iteration}")
            await context.checkpoint()
            return {"unreachable": True}

        _install(monkeypatch, counts, cancel_then_check)
        result = await gateway.execute(run.root_node_id, run.root_token, request)
        assert _action(session_factory, run.run_id).execution_state == "STALE"
        assert counts.executor == 1
        assert counts.effect_1 == counts.effect_2 == 0
        return

    if case == "cancel-between-effects":
        async def between(context, _arguments):
            counts.executor += 1
            await context.checkpoint()
            counts.effect_1 += 1
            await _cancel(session_factory, run, f"{case}-cancel-{iteration}")
            await context.checkpoint()
            return {"unreachable": True}

        _install(monkeypatch, counts, between)
        result = await gateway.execute(run.root_node_id, run.root_token, request)
        assert _action(session_factory, run.run_id).execution_state == "STALE"
        assert counts.effect_1 == 1
        assert counts.effect_2 == 0
        return

    if case == "final-check-before-cancel-before-result":
        async def final_check(context, _arguments):
            counts.executor += 1
            await context.checkpoint()
            counts.effect_1 += 1
            await context.checkpoint()
            counts.effect_2 += 1
            await _cancel(session_factory, run, f"{case}-cancel-{iteration}")
            counts.returned += 1
            return {"effects": 2}

        _install(monkeypatch, counts, final_check)
        result = await gateway.execute(run.root_node_id, run.root_token, request)
        assert _action(session_factory, run.run_id).execution_state == "STALE"
        assert result.committed is False
        assert counts.returned == 1
        return

    if case == "uncertain-before-first-effect":
        async def uncertain(context, _arguments):
            counts.executor += 1

            async def unavailable(*_args, **_kwargs):
                raise OperationalError("SELECT", {}, Exception("busy"))

            monkeypatch.setattr(lifecycle_module, "_evaluate_live_bound_action_authority", unavailable)
            await context.checkpoint()
            return {"unreachable": True}

        _install(monkeypatch, counts, uncertain)
        with pytest.raises(ConflictError) as error:
            await gateway.execute(run.root_node_id, run.root_token, request)
        assert error.value.code == "OPERATION_AUTHORITY_UNCERTAIN"
        assert _action(session_factory, run.run_id).execution_state == "DISPATCHED"
        assert counts.effect_1 == counts.effect_2 == 0
        return

    if case == "sequential-already-dispatched-duplicate":
        _install(monkeypatch, counts, success)
        action = await lifecycle.reserve(
            node_id=run.root_node_id,
            credential=run.root_token,
            request=request,
            required_capability=CAPABILITY,
        )
        assert action.worker_instance_id is not None and action.worker_incarnation is not None
        await lifecycle.mark_dispatched(
            action_id=action.id,
            worker_instance_id=action.worker_instance_id,
            worker_incarnation=action.worker_incarnation,
        )
        result = await gateway.execute(run.root_node_id, run.root_token, request)
        assert result.duplicate is True
        assert counts.executor == 0
        return

    async def replace_before_checkpoint(context, _arguments):
        counts.executor += 1
        await context.checkpoint()
        counts.effect_1 += 1
        _replace_worker(session_factory, run.root_node_id)
        await context.checkpoint()
        return {"unreachable": True}

    _install(monkeypatch, counts, replace_before_checkpoint)
    result = await gateway.execute(run.root_node_id, run.root_token, request)
    assert _action(session_factory, run.run_id).execution_state == "STALE"
    assert counts.effect_1 == 1
    assert counts.effect_2 == 0
