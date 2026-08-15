from __future__ import annotations

import asyncio
import threading
from datetime import timedelta

import pytest
from sqlalchemy import select, text

import tracefence.services.proof_service as proof_module
from tests.unit.test_proof_contract import _corrected_recovery
from tracefence.db.models import Node, Run, ServiceState
from tracefence.domain.enums import ProofVerdict
from tracefence.services.common import utcnow
from tracefence.services.proof_service import ProofService
from tracefence.signoz.mcp_client import ExportWatermark, TelemetryProof


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


class _BlockingVerifiedMCPClient:
    def __init__(self) -> None:
        self.calls = 0
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def verify_command(self, **_kwargs) -> TelemetryProof:
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return TelemetryProof(
            verdict=ProofVerdict.VERIFIED,
            trace_ids=["c" * 32],
            discrepancies=[],
            evidence={},
        )


class _OverlappingVerifiedMCPClient:
    def __init__(self, first_command_id: str) -> None:
        self.first_command_id = first_command_id
        self.first_started = asyncio.Event()
        self.release_first = asyncio.Event()
        self.watermarks: dict[str, ExportWatermark | None] = {}

    async def verify_command(self, *, context) -> TelemetryProof:
        self.watermarks[context.command_id] = context.export_watermark
        if context.command_id == self.first_command_id:
            self.first_started.set()
            await self.release_first.wait()
        return TelemetryProof(
            verdict=ProofVerdict.VERIFIED,
            trace_ids=["d" * 32],
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
    clock = {"now": utcnow(), "monotonic": 100.0}
    monkeypatch.setattr(proof_module, "utcnow", lambda: clock["now"])
    monkeypatch.setattr(proof_module.time, "monotonic", lambda: clock["monotonic"])

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
        root.lease_expires_at = clock["now"] + timedelta(milliseconds=500)

    watermark = ExportWatermark(
        service_name="tracefence-control-plane",
        service_instance_id="service-a",
        process_instance_id="process-a",
        build_commit="build-a",
        schema_version=1,
        run_id=run.run_id,
        command_id=command.command_id,
        exported_at_ms=1_005_000,
        sequence=1,
    )
    monkeypatch.setattr(proof_module, "force_flush_telemetry", lambda **_kwargs: True)
    monkeypatch.setattr(
        proof_module,
        "telemetry_export_context",
        lambda _run_id, _command_id: watermark,
    )
    mcp = _CountingVerifiedMCPClient()
    proofs = ProofService(session_factory, mcp_client=mcp)

    await proofs.build(command.command_id)
    clock["now"] += timedelta(milliseconds=600)
    clock["monotonic"] += 0.6
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


async def test_cancelling_follower_does_not_cancel_owner_or_shared_cache(
    session_factory,
    monkeypatch,
):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-follower-cancellation"
    )
    watermark = ExportWatermark(
        service_name="tracefence-control-plane",
        service_instance_id="service-a",
        process_instance_id="process-a",
        build_commit="build-a",
        schema_version=1,
        run_id=run.run_id,
        command_id=command.command_id,
        exported_at_ms=1_005_000,
        sequence=1,
    )
    monkeypatch.setattr(proof_module, "force_flush_telemetry", lambda **_kwargs: True)
    monkeypatch.setattr(
        proof_module,
        "telemetry_export_context",
        lambda _run_id, _command_id: watermark,
    )
    mcp = _BlockingVerifiedMCPClient()
    proofs = ProofService(session_factory, mcp_client=mcp)

    owner = asyncio.create_task(proofs.build(command.command_id))
    await asyncio.wait_for(mcp.started.wait(), timeout=1)
    follower = asyncio.create_task(proofs.build(command.command_id))
    await asyncio.sleep(0)

    follower.cancel()
    with pytest.raises(asyncio.CancelledError):
        await follower

    mcp.release.set()
    owner_result = await asyncio.wait_for(owner, timeout=1)
    cached_result = await proofs.build(command.command_id)

    assert owner_result.overall_verdict == ProofVerdict.VERIFIED
    assert cached_result == owner_result
    assert mcp.calls == 1


async def test_cache_hit_rebuilds_when_revision_changes_after_context_snapshot(
    session_factory,
    monkeypatch,
):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-cache-hit-revision-race"
    )
    watermark = ExportWatermark(
        service_name="tracefence-control-plane",
        service_instance_id="service-a",
        process_instance_id="process-a",
        build_commit="build-a",
        schema_version=1,
        run_id=run.run_id,
        command_id=command.command_id,
        exported_at_ms=1_005_000,
        sequence=1,
    )
    monkeypatch.setattr(proof_module, "force_flush_telemetry", lambda **_kwargs: True)
    monkeypatch.setattr(
        proof_module,
        "telemetry_export_context",
        lambda _run_id, _command_id: watermark,
    )
    mcp = _CountingVerifiedMCPClient()
    proofs = ProofService(session_factory, mcp_client=mcp)

    first = await proofs.build(command.command_id)
    assert first.overall_verdict == ProofVerdict.VERIFIED
    assert mcp.calls == 1

    original_context = proofs._current_context
    snapshot_taken = threading.Event()
    mutation_complete = threading.Event()
    arm_pause = threading.Event()
    mutation_errors: list[BaseException] = []

    def paused_context(command_id: str):
        context = original_context(command_id)
        if arm_pause.is_set():
            snapshot_taken.set()
            assert mutation_complete.wait(timeout=1)
        return context

    def mutate_after_snapshot() -> None:
        assert snapshot_taken.wait(timeout=1)
        try:
            with session_factory() as session, session.begin():
                state = session.get(ServiceState, (run.run_id, "redis"))
                assert state is not None
                state.status = "connection_pool_exhausted"
                state.updated_at = utcnow()
        except BaseException as exc:
            mutation_errors.append(exc)
        finally:
            arm_pause.clear()
            mutation_complete.set()

    monkeypatch.setattr(proofs, "_current_context", paused_context)
    arm_pause.set()
    mutator = threading.Thread(target=mutate_after_snapshot)
    mutator.start()
    second = await asyncio.wait_for(proofs.build(command.command_id), timeout=3)
    mutator.join(timeout=1)

    assert not mutator.is_alive()
    assert mutation_errors == []
    assert mcp.calls == 2
    assert second.overall_verdict != ProofVerdict.VERIFIED



async def test_cache_hit_rebuilds_when_node_revision_changes_during_context_read(
    session_factory,
    monkeypatch,
):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-cache-hit-node-revision-race"
    )
    watermark = ExportWatermark(
        service_name="tracefence-control-plane",
        service_instance_id="service-a",
        process_instance_id="process-a",
        build_commit="build-a",
        schema_version=1,
        run_id=run.run_id,
        command_id=command.command_id,
        exported_at_ms=1_005_000,
        sequence=1,
    )
    monkeypatch.setattr(proof_module, "force_flush_telemetry", lambda **_kwargs: True)
    monkeypatch.setattr(
        proof_module,
        "telemetry_export_context",
        lambda _run_id, _command_id: watermark,
    )
    mcp = _CountingVerifiedMCPClient()
    proofs = ProofService(session_factory, mcp_client=mcp)

    await proofs.build(command.command_id)
    assert mcp.calls == 1

    original_context = proofs._current_context
    mutated = False

    def context_with_node_mutation(command_id: str):
        nonlocal mutated
        context = original_context(command_id)
        if not mutated:
            mutated = True
            with session_factory() as session, session.begin():
                node = session.get(Node, run.root_node_id)
                assert node is not None
                node.last_heartbeat_at = utcnow()
        return context

    monkeypatch.setattr(proofs, "_current_context", context_with_node_mutation)
    await proofs.build(command.command_id)

    assert mutated
    assert mcp.calls == 2


async def test_cached_response_isolated_from_caller_mutation(
    session_factory,
    monkeypatch,
):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-cache-copy-isolation"
    )
    watermark = ExportWatermark(
        service_name="tracefence-control-plane",
        service_instance_id="service-a",
        process_instance_id="process-a",
        build_commit="build-a",
        schema_version=1,
        run_id=run.run_id,
        command_id=command.command_id,
        exported_at_ms=1_005_000,
        sequence=1,
    )
    monkeypatch.setattr(proof_module, "force_flush_telemetry", lambda **_kwargs: True)
    monkeypatch.setattr(
        proof_module,
        "telemetry_export_context",
        lambda _run_id, _command_id: watermark,
    )
    mcp = _CountingVerifiedMCPClient()
    proofs = ProofService(session_factory, mcp_client=mcp)

    first = await proofs.build(command.command_id)
    first.discrepancies.append("CALLER_MUTATION")
    cached = await proofs.build(command.command_id)

    assert "CALLER_MUTATION" not in cached.discrepancies
    assert mcp.calls == 1


async def test_cache_hit_rebuilds_when_command_export_watermark_changes(
    session_factory,
    monkeypatch,
):
    run, _old, command, _replacement, _action = await _corrected_recovery(
        session_factory, key="proof-watermark-advance"
    )
    watermarks = [
        ExportWatermark(
            service_name="tracefence-control-plane",
            service_instance_id="service-a",
            process_instance_id="process-a",
            build_commit="build-a",
            schema_version=1,
            run_id=run.run_id,
            command_id=command.command_id,
            exported_at_ms=1_005_000,
            sequence=1,
        ),
        ExportWatermark(
            service_name="tracefence-control-plane",
            service_instance_id="service-a",
            process_instance_id="process-a",
            build_commit="build-a",
            schema_version=1,
            run_id=run.run_id,
            command_id=command.command_id,
            exported_at_ms=1_006_000,
            sequence=2,
        ),
    ]
    current = {"watermark": watermarks[0]}
    monkeypatch.setattr(proof_module, "force_flush_telemetry", lambda **_kwargs: True)
    monkeypatch.setattr(
        proof_module,
        "telemetry_export_context",
        lambda _run_id, _command_id: current["watermark"],
    )
    mcp = _CountingVerifiedMCPClient()
    proofs = ProofService(session_factory, mcp_client=mcp)

    await proofs.build(command.command_id)
    current["watermark"] = watermarks[1]
    await proofs.build(command.command_id)

    assert mcp.calls == 2


async def test_overlapping_commands_cache_the_exact_reconciled_export_watermark(
    session_factory,
    monkeypatch,
):
    run_a, _old_a, command_a, _replacement_a, _action_a = await _corrected_recovery(
        session_factory, key="proof-watermark-a"
    )
    run_b, _old_b, command_b, _replacement_b, _action_b = await _corrected_recovery(
        session_factory, key="proof-watermark-b"
    )
    sequence = 0
    watermarks: dict[str, ExportWatermark] = {}
    latest_identity: str | None = None

    def fake_flush(*, run_id: str, command_id: str, **_kwargs) -> bool:
        nonlocal sequence, latest_identity
        sequence += 1
        watermark = ExportWatermark(
            service_name="tracefence-control-plane",
            service_instance_id="service-a",
            process_instance_id="process-a",
            build_commit="build-a",
            schema_version=1,
            run_id=run_id,
            command_id=command_id,
            exported_at_ms=1_000_000 + sequence,
            sequence=sequence,
        )
        watermarks[command_id] = watermark
        latest_identity = f"global:{sequence}:{command_id}"
        return True

    monkeypatch.setattr(proof_module, "force_flush_telemetry", fake_flush)
    monkeypatch.setattr(
        proof_module,
        "telemetry_export_context",
        lambda _run_id, command_id: watermarks.get(command_id),
    )
    monkeypatch.setattr(
        proof_module,
        "telemetry_export_watermark",
        lambda: latest_identity,
        raising=False,
    )
    mcp = _OverlappingVerifiedMCPClient(command_a.command_id)
    proofs = ProofService(session_factory, mcp_client=mcp)

    first = asyncio.create_task(proofs.build(command_a.command_id))
    await asyncio.wait_for(mcp.first_started.wait(), timeout=1)
    second = await asyncio.wait_for(proofs.build(command_b.command_id), timeout=2)
    mcp.release_first.set()
    first_result = await asyncio.wait_for(first, timeout=2)

    assert first_result.command_id == command_a.command_id
    assert second.command_id == command_b.command_id
    exact_identity = proof_module._export_watermark_identity
    cached_identities = {
        key.command_id: key.export_watermark for key in proofs._cache
    }
    assert cached_identities == {
        command_a.command_id: exact_identity(mcp.watermarks[command_a.command_id]),
        command_b.command_id: exact_identity(mcp.watermarks[command_b.command_id]),
    }
    assert cached_identities[command_a.command_id] != cached_identities[
        command_b.command_id
    ]
    assert run_a.run_id != run_b.run_id
