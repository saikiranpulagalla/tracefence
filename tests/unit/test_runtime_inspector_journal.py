from __future__ import annotations

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from tests.helpers import FULL_ROOT_CAPABILITIES, activate, create_seeded_run
from tracefence.db.models import ActionAttempt, RuntimeEvent
from tracefence.domain.enums import ActionDecision, CommandType, IssuerType
from tracefence.domain.schemas import (
    ActionExecute,
    CommandCreate,
    Principal,
    RunCreate,
    SpawnCreate,
)
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.run_service import RunService
from tracefence.services.spawn_service import SpawnService


async def test_run_creation_records_transactional_lifecycle_events(session_factory):
    created = await RunService(session_factory).create_run(
        RunCreate(
            name="runtime-journal",
            root_capabilities=FULL_ROOT_CAPABILITIES,
        )
    )

    with session_factory() as session:
        events = session.execute(
            select(RuntimeEvent)
            .where(RuntimeEvent.run_id == created.run_id)
            .order_by(RuntimeEvent.sequence)
        ).scalars().all()

    assert [event.event_type for event in events] == [
        "RUN_CREATED",
        "NODE_REGISTERED",
        "NODE_ACTIVATED",
        "LEASE_GRANTED",
    ]
    assert [event.sequence for event in events] == sorted(
        event.sequence for event in events
    )
    assert all(event.run_id == created.run_id for event in events)
    assert all("token" not in str(event.metadata_json).lower() for event in events)


async def test_gateway_persists_exact_scope_denial_explanation_and_events(
    session_factory,
):
    run = await create_seeded_run(session_factory, "runtime-decision")
    spawns = SpawnService(session_factory)
    target = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                role="stale-worker",
                behavior="non_compliant",
                capabilities=["tool:restart_postgres"],
            ),
        ),
    )
    command = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="runtime-decision-command",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=target.node_id,
            reason_code="DEMO_SUPERSEDE",
            reason_text="Exercise the real stale-action boundary",
            replacement_instruction={"task": "reset redis"},
            replacement_expected_tool="reset_redis_pool",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    result = await ActionGateway(session_factory).execute(
        target.node_id,
        target.node_token,
        ActionExecute(
            idempotency_key="runtime-decision-action",
            tool_name="restart_postgres",
            arguments={},
        ),
    )

    assert result.decision == ActionDecision.DENY
    assert result.denial_reason == "SCOPE_SUPERSEDED"
    with session_factory() as session:
        attempt = session.get(ActionAttempt, result.action_id)
        assert attempt is not None
        explanation = attempt.decision_explanation_json
        assert explanation["final_decision"] == "DENY"
        assert explanation["final_reason"] == "SCOPE_SUPERSEDED"
        assert explanation["idempotency"] == "NEW"
        checks = {item["name"]: item for item in explanation["checks"]}
        assert checks["run_active"]["outcome"] == "PASS"
        assert checks["node_active"]["outcome"] == "PASS"
        assert checks["lease_valid"]["outcome"] == "PASS"
        assert checks["scope_current"] == {
            "name": "scope_current",
            "outcome": "FAIL",
            "reason": "SCOPE_SUPERSEDED",
        }
        events = session.execute(
            select(RuntimeEvent)
            .where(RuntimeEvent.run_id == run.run_id)
            .order_by(RuntimeEvent.sequence)
        ).scalars().all()

    command_event = next(
        event for event in events if event.event_type == "COMMAND_ISSUED"
    )
    denied_event = next(
        event for event in events if event.event_type == "ACTION_DENIED"
    )
    assert command_event.command_id == command.command_id
    assert denied_event.action_id == result.action_id
    assert denied_event.reason_code == "SCOPE_SUPERSEDED"
    assert command_event.sequence < denied_event.sequence


async def test_runtime_event_journal_rejects_update_and_delete(session_factory):
    created = await RunService(session_factory).create_run(
        RunCreate(name="append-only-journal", root_capabilities=FULL_ROOT_CAPABILITIES)
    )
    with session_factory() as session:
        sequence = session.scalar(
            select(RuntimeEvent.sequence)
            .where(RuntimeEvent.run_id == created.run_id)
            .order_by(RuntimeEvent.sequence)
            .limit(1)
        )

    with pytest.raises(IntegrityError, match="RUNTIME_EVENTS_APPEND_ONLY"):
        with session_factory() as session, session.begin():
            session.execute(
                update(RuntimeEvent)
                .where(RuntimeEvent.sequence == sequence)
                .values(reason_code="rewritten")
            )

    with pytest.raises(IntegrityError, match="RUNTIME_EVENTS_APPEND_ONLY"):
        with session_factory() as session, session.begin():
            session.execute(
                delete(RuntimeEvent).where(RuntimeEvent.sequence == sequence)
            )


async def test_heartbeat_and_completion_append_transactional_events(session_factory):
    run = await create_seeded_run(session_factory, "runtime-heartbeat")
    spawns = SpawnService(session_factory)
    child = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="journal-child", capabilities=["tool:read_metrics"]),
        ),
    )

    await spawns.heartbeat(child.node_id, child.node_token)
    await spawns.complete(child.node_id, child.node_token)

    with session_factory() as session:
        events = session.execute(
            select(RuntimeEvent)
            .where(
                RuntimeEvent.run_id == run.run_id,
                RuntimeEvent.node_id == child.node_id,
            )
            .order_by(RuntimeEvent.sequence)
        ).scalars().all()

    event_types = [event.event_type for event in events]
    assert "LEASE_RENEWED" in event_types
    assert event_types[-1] == "NODE_COMPLETED"
    renewed = next(event for event in events if event.event_type == "LEASE_RENEWED")
    assert set(renewed.metadata_json) == {"lease_expires_at"}
