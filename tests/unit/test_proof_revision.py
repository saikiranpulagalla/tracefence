from __future__ import annotations

import asyncio
from datetime import timedelta

from sqlalchemy import select, text

import tracefence.services.proof_service as proof_module
from tracefence.db.models import Node, Run, ServiceState
from tracefence.domain.enums import ProofVerdict
from tracefence.services.common import utcnow
from tracefence.services.proof_service import ProofService
from tracefence.signoz.mcp_client import TelemetryProof
from tests.unit.test_proof_contract import _corrected_recovery


class _MutatingMCPClient:
    def __init__(self, session_factory, run_id: str, *, every_call: bool) -> None:
        self.session_factory = session_factory
        self.run_id = run_id
        self.every_call = every_call
        self.calls = 0

    async def verify_command(self, **_kwargs) -> TelemetryProof:
        self.calls += 1
        if self.every_call or self.calls == 1:
            with self.session_factory() as session, session.begin():
                state = session.get(ServiceState, (self.run_id, "redis"))
                assert state is not None
                state.status = (
                    "healthy"
                    if state.status == "connection_pool_exhausted"
                    else "connection_pool_exhausted"
                )
                state.last_action_id = None
                state.updated_at = utcnow()
        return TelemetryProof(
            verdict=ProofVerdict.VERIFIED,
            trace_ids=["a" * 32],
            discrepancies=[],
            evidence={},
        )


class _CountingVerifiedMCPClient:
    def __init__(self) -> None:
        self.calls = 0

    async def verify_command(self, **_kwargs) -> TelemetryProof:
        self.calls += 1
        return TelemetryProof(
            verdict=ProofVerdict.VERIFIED,
            trace_ids=["b" * 32],
            discrepancies=[],
            evidence={},
        )


def test_sqlite_installs_mandatory_proof_revision_triggers(session_factory):
    expected_tables = {
        "nodes",
        "control_scopes",
        "spawn_intents",
        "correction_proposals",
        "control_commands",
        "command_acknowledgements",
        "action_attempts",
        "action_command_matches",
        "invariant_violations",
        "telemetry_outbox",
        "service_state",
    }
    expected = {
        f"trg_{table}_{operation}_proof_revision"
        for table in expected_tables
        for operation in ("insert", "update", "delete")
    } | {"trg_runs_update_proof_revision"}

    with session_factory() as session:
        actual = set(
            session.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
            ).scalars()
        )

    assert expected <= actual


async def test_delayed_reconciliation_discards_stale_verified_and_does_not_cache_it(
    session_factory,
):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-revision-race"
    )
    mcp = _MutatingMCPClient(session_factory, run.run_id, every_call=False)
    proofs = ProofService(session_factory, mcp_client=mcp)

    first = await proofs.build(command.command_id)
    second = await proofs.build(command.command_id)

    assert first.overall_verdict != ProofVerdict.VERIFIED
    assert first.runtime_verdict != ProofVerdict.VERIFIED
    assert second.runtime_verdict == first.runtime_verdict
    assert mcp.calls >= 2


async def test_repeated_mutation_returns_bounded_fail_closed_result(session_factory):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-revision-churn"
    )
    mcp = _MutatingMCPClient(session_factory, run.run_id, every_call=True)
    proofs = ProofService(session_factory, mcp_client=mcp)

    result = await asyncio.wait_for(proofs.build(command.command_id), timeout=3)

    assert result.overall_verdict.value == "STATE_CHANGED_DURING_PROOF"
    assert "STATE_CHANGED_DURING_PROOF" in result.discrepancies
    assert mcp.calls == 3


async def test_nearest_lease_expiry_bounds_cached_proof(
    session_factory, monkeypatch
):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-lease-boundary"
    )
    with session_factory() as session, session.begin():
        root = session.scalar(
            select(Node).where(
                Node.run_id == run.run_id,
                Node.id == run.root_node_id,
            )
        )
        assert root is not None
        root.lease_expires_at = utcnow() + timedelta(milliseconds=500)

    monkeypatch.setattr(
        proof_module,
        "telemetry_export_watermark",
        lambda: "test-export-watermark",
        raising=False,
    )
    mcp = _CountingVerifiedMCPClient()
    proofs = ProofService(session_factory, mcp_client=mcp)

    await proofs.build(command.command_id)
    await asyncio.sleep(0.6)
    await proofs.build(command.command_id)

    assert mcp.calls == 2


async def test_raw_proof_relevant_mutations_increment_run_revision(session_factory):
    run, _old, _command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-trigger-behavior"
    )
    with session_factory() as session:
        before = session.get(Run, run.run_id)
        assert before is not None
        before_revision = before.proof_revision

    with session_factory() as session, session.begin():
        session.execute(
            text(
                "UPDATE service_state SET updated_at = :updated_at "
                "WHERE run_id = :run_id AND service_name = 'redis'"
            ),
            {"updated_at": utcnow(), "run_id": run.run_id},
        )

    with session_factory() as session:
        after_state = session.get(Run, run.run_id)
        assert after_state is not None
        assert after_state.proof_revision == before_revision + 1

    with session_factory() as session, session.begin():
        session.execute(
            text(
                "UPDATE nodes SET last_heartbeat_at = :heartbeat "
                "WHERE run_id = :run_id AND id = :node_id"
            ),
            {
                "heartbeat": utcnow(),
                "run_id": run.run_id,
                "node_id": run.root_node_id,
            },
        )

    with session_factory() as session:
        after_node = session.get(Run, run.run_id)
        assert after_node is not None
        assert after_node.proof_revision == before_revision + 2
