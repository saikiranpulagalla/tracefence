from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

import tracefence.services.action_gateway as action_gateway_module
import tracefence.services.operation_lifecycle as lifecycle_module
from tests.helpers import create_v2_run
from tracefence.config import settings
from tracefence.db.models import ActionAttempt, Node, Run
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal
from tracefence.rate_limits import authenticated_rate_limiter
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.operation_lifecycle import (
    DispatchClaimStatus,
    OperationLifecycleService,
)
from tracefence.services.tool_registry import TOOL_REGISTRY, ToolSpec

TOOL_NAME = "test_cooperative_checkpoint"
CAPABILITY = "tool:test_cooperative_checkpoint"


@dataclass
class Counts:
    executor: int = 0
    effect_1: int = 0
    effect_2: int = 0
    returned: int = 0


def _request(key: str) -> ActionExecute:
    return ActionExecute(idempotency_key=key, tool_name=TOOL_NAME, arguments={})


async def _run_with_cooperative_capability(session_factory, name: str):
    run = await create_v2_run(session_factory, name)
    with session_factory.begin() as session:
        node = session.get(Node, run.root_node_id)
        assert node is not None
        node.capabilities_json = [*(node.capabilities_json or []), CAPABILITY]
    return run


def _cancel(run_id: str, node_id: str, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_RUN,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="cooperative checkpoint test",
    )


async def _cancel_run(session_factory, run, key: str) -> None:
    await ControlService(session_factory).issue_command(
        _cancel(run.run_id, run.root_node_id, key),
        Principal(issuer_type=IssuerType.HUMAN, principal_id="b2-test"),
    )


def _install_tool(monkeypatch, counts: Counts, *, after_effect_1=None):
    async def executor(context, _arguments):
        counts.executor += 1
        await context.checkpoint()
        counts.effect_1 += 1
        if after_effect_1 is not None:
            await after_effect_1(context)
        await context.checkpoint()
        counts.effect_2 += 1
        counts.returned += 1
        return {"effects": counts.effect_2}

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


def _install_cooperative_executor(monkeypatch, executor) -> None:
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


def _action(session_factory, action_id: str) -> ActionAttempt:
    with session_factory() as session:
        row = session.get(ActionAttempt, action_id)
        assert row is not None
        return row


async def test_cooperative_cancel_before_dispatch_does_not_invoke_executor(
    session_factory, monkeypatch
):
    counts = Counts()
    _install_tool(monkeypatch, counts)
    run = await _run_with_cooperative_capability(session_factory, "b2-before-dispatch")
    lifecycle = OperationLifecycleService(session_factory)
    reserved = await lifecycle.reserve(
        node_id=run.root_node_id,
        credential=run.root_token,
        request=_request("before-dispatch"),
        required_capability=CAPABILITY,
    )
    await _cancel_run(session_factory, run, "before-dispatch-cancel")

    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("before-dispatch")
    )
    row = _action(session_factory, reserved.id)
    assert result.duplicate is True
    assert row.execution_state == "STALE"
    assert counts.executor == counts.effect_1 == counts.effect_2 == 0


async def test_cooperative_cancel_between_effects_stops_later_effect(
    session_factory, monkeypatch
):
    counts = Counts()
    run = await _run_with_cooperative_capability(session_factory, "b2-between-effects")

    async def cancel_after_first(_context):
        await _cancel_run(session_factory, run, "between-effects-cancel")

    _install_tool(monkeypatch, counts, after_effect_1=cancel_after_first)
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("between-effects")
    )
    row = _action(session_factory, result.action_id)
    assert row.execution_state == "STALE"
    assert result.committed is False
    assert counts.executor == 1
    assert counts.effect_1 == 1
    assert counts.effect_2 == counts.returned == 0


async def test_final_checkpoint_cannot_bypass_result_authority_fence(
    session_factory, monkeypatch
):
    counts = Counts()
    run = await _run_with_cooperative_capability(session_factory, "b2-result-fence")

    async def executor(context, _arguments):
        counts.executor += 1
        await context.checkpoint()
        counts.effect_1 += 1
        await context.checkpoint()
        counts.effect_2 += 1
        await _cancel_run(session_factory, run, "result-fence-cancel")
        counts.returned += 1
        return {"effects": 2}

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
    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("result-fence")
    )
    row = _action(session_factory, result.action_id)
    assert row.execution_state == "STALE"
    assert result.committed is False
    assert counts.effect_1 == counts.effect_2 == counts.returned == 1


async def test_cooperative_uncertainty_leaves_dispatched_operation_unresolved(
    session_factory, monkeypatch
):
    counts = Counts()
    run = await _run_with_cooperative_capability(session_factory, "b2-uncertain")

    async def make_uncertain(_context):
        async def unavailable(*_args, **_kwargs):
            raise OperationalError("SELECT", {}, Exception("busy"))

        monkeypatch.setattr(lifecycle_module, "_evaluate_live_bound_action_authority", unavailable)

    _install_tool(monkeypatch, counts, after_effect_1=make_uncertain)
    with pytest.raises(ConflictError) as error:
        await ActionGateway(session_factory).execute(
            run.root_node_id, run.root_token, _request("uncertain")
        )
    assert error.value.code == "OPERATION_AUTHORITY_UNCERTAIN"
    with session_factory() as session:
        row = session.scalar(select(ActionAttempt).where(ActionAttempt.run_id == run.run_id))
        proof = session.get(Run, run.run_id)
        assert row is not None and proof is not None
        assert row.execution_state == "DISPATCHED"
    assert counts.effect_1 == 1
    assert counts.effect_2 == counts.returned == 0


async def test_dispatched_duplicate_never_invokes_cooperative_executor(
    session_factory, monkeypatch
):
    counts = Counts()
    _install_tool(monkeypatch, counts)
    run = await _run_with_cooperative_capability(session_factory, "b2-dispatched-duplicate")
    lifecycle = OperationLifecycleService(session_factory)
    action = await lifecycle.reserve(
        node_id=run.root_node_id,
        credential=run.root_token,
        request=_request("dispatched-duplicate"),
        required_capability=CAPABILITY,
    )
    assert action.worker_instance_id is not None and action.worker_incarnation is not None
    await lifecycle.mark_dispatched(
        action_id=action.id,
        worker_instance_id=action.worker_instance_id,
        worker_incarnation=action.worker_incarnation,
    )

    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("dispatched-duplicate")
    )
    assert result.duplicate is True
    assert result.committed is False
    assert counts.executor == 0


async def test_concurrent_authorized_duplicates_claim_once(session_factory, monkeypatch):
    counts = Counts()
    executor_started = asyncio.Event()
    release_executor = asyncio.Event()

    async def executor(_context, _arguments):
        counts.executor += 1
        executor_started.set()
        await release_executor.wait()
        counts.returned += 1
        return {"effects": 0}

    _install_cooperative_executor(monkeypatch, executor)
    run = await _run_with_cooperative_capability(session_factory, "b2-concurrent-duplicate")
    gateway = ActionGateway(session_factory)
    first_at_claim = asyncio.Event()
    second_at_claim = asyncio.Event()
    release_claims = asyncio.Event()
    claim_statuses = []
    original_claim = OperationLifecycleService.mark_dispatched
    claim_calls = 0

    async def delayed_claim(self, **kwargs):
        nonlocal claim_calls
        claim_calls += 1
        if claim_calls == 1:
            first_at_claim.set()
        else:
            second_at_claim.set()
        await release_claims.wait()
        claim = await original_claim(self, **kwargs)
        claim_statuses.append(claim.status)
        return claim

    monkeypatch.setattr(OperationLifecycleService, "mark_dispatched", delayed_claim)
    first = asyncio.create_task(
        gateway.execute(run.root_node_id, run.root_token, _request("concurrent-duplicate"))
    )
    await first_at_claim.wait()
    with session_factory() as session:
        before = session.get(Run, run.run_id)
        assert before is not None
        proof_before = before.proof_revision

    second = asyncio.create_task(
        gateway.execute(run.root_node_id, run.root_token, _request("concurrent-duplicate"))
    )
    await second_at_claim.wait()
    release_claims.set()
    await executor_started.wait()
    with session_factory() as session:
        during = session.get(Run, run.run_id)
        action = session.scalar(select(ActionAttempt).where(ActionAttempt.run_id == run.run_id))
        assert during is not None and action is not None
        assert during.proof_revision == proof_before + 1
        assert action.execution_state == "DISPATCHED"

    release_executor.set()
    first_result, second_result = await asyncio.gather(first, second)
    assert {first_result.action_id, second_result.action_id} == {_action(session_factory, first_result.action_id).id}
    assert claim_statuses.count(DispatchClaimStatus.CLAIMED) == 1
    assert claim_statuses.count(DispatchClaimStatus.ALREADY_DISPATCHED) == 1
    assert counts.executor == counts.returned == 1
    assert _action(session_factory, first_result.action_id).execution_state == "SUCCEEDED"


async def test_claimed_dispatch_crash_window_never_redispatches(session_factory, monkeypatch):
    counts = Counts()
    executor_started = asyncio.Event()
    release_executor = asyncio.Event()

    async def executor(_context, _arguments):
        counts.executor += 1
        executor_started.set()
        await release_executor.wait()
        return {"effects": 0}

    _install_cooperative_executor(monkeypatch, executor)
    run = await _run_with_cooperative_capability(session_factory, "b2-crash-window")
    gateway = ActionGateway(session_factory)
    first = asyncio.create_task(
        gateway.execute(run.root_node_id, run.root_token, _request("crash-window"))
    )
    await executor_started.wait()
    duplicate = await gateway.execute(
        run.root_node_id, run.root_token, _request("crash-window")
    )
    assert duplicate.duplicate is True
    assert duplicate.committed is False
    assert counts.executor == 1
    assert _action(session_factory, duplicate.action_id).execution_state == "DISPATCHED"

    release_executor.set()
    await first
    assert counts.executor == 1


async def test_cooperative_request_uses_rate_limit_gate(session_factory, monkeypatch):
    counts = Counts()
    _install_tool(monkeypatch, counts)

    def rate_limited(*_args, **_kwargs):
        raise ConflictError("rate limited", code="RATE_LIMITED")

    monkeypatch.setattr(authenticated_rate_limiter, "check", rate_limited)
    run = await _run_with_cooperative_capability(session_factory, "b2-rate-limit")
    with pytest.raises(ConflictError) as error:
        await ActionGateway(session_factory).execute(
            run.root_node_id, run.root_token, _request("rate-limit")
        )
    assert error.value.code == "RATE_LIMITED"
    assert counts.executor == 0
    with session_factory() as session:
        assert session.scalar(select(ActionAttempt).where(ActionAttempt.run_id == run.run_id)) is None


async def test_cooperative_request_uses_action_quota_gate(session_factory, monkeypatch):
    counts = Counts()
    _install_tool(monkeypatch, counts)
    monkeypatch.setattr(
        action_gateway_module,
        "settings",
        replace(settings, max_actions_per_run=0),
    )
    run = await _run_with_cooperative_capability(session_factory, "b2-quota")
    with pytest.raises(ConflictError) as error:
        await ActionGateway(session_factory).execute(
            run.root_node_id, run.root_token, _request("quota")
        )
    assert error.value.code == "RUN_ACTION_QUOTA_EXCEEDED"
    assert counts.executor == 0
    with session_factory() as session:
        assert session.scalar(select(ActionAttempt).where(ActionAttempt.run_id == run.run_id)) is None


async def test_cooperative_request_uses_recovery_contract_gate(session_factory, monkeypatch):
    counts = Counts()
    _install_tool(monkeypatch, counts)
    run = await _run_with_cooperative_capability(session_factory, "b2-recovery-contract")
    monkeypatch.setattr(
        ActionGateway,
        "_recovery_contract_denial",
        staticmethod(lambda *_args: "RECOVERY_TOOL_MISMATCH"),
    )

    result = await ActionGateway(session_factory).execute(
        run.root_node_id, run.root_token, _request("recovery-contract")
    )
    row = _action(session_factory, result.action_id)
    assert result.decision.value == "DENY"
    assert row.denial_reason == "RECOVERY_TOOL_MISMATCH"
    assert counts.executor == 0
