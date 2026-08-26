from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

import tracefence.services.operation_lifecycle as lifecycle_module
from tests.helpers import create_v2_run
from tracefence.db.models import ActionAttempt, Node, Run
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.operation_lifecycle import OperationLifecycleService
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
