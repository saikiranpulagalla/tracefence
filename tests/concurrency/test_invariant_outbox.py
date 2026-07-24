from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import text

import tracefence.services.invariant_service as invariant_module
from tests.helpers import create_seeded_run
from tracefence.db.models import TelemetryOutbox
from tracefence.services.common import utcnow
from tracefence.services.invariant_service import InvariantService
from tracefence.telemetry.instruments import (
    gauge_snapshot,
    update_stale_violation_gauge,
)


async def test_read_heavy_invariant_discovery_does_not_hold_sqlite_writer_lock(
    session_factory,
    monkeypatch,
):
    run = await create_seeded_run(session_factory, "invariant-read-lock")
    discovery_started = threading.Event()
    release_discovery = threading.Event()

    def delayed_discovery(self, selected_run_id):
        assert selected_run_id == run.run_id
        discovery_started.set()
        release_discovery.wait(timeout=2)
        return []

    monkeypatch.setattr(
        InvariantService,
        "_discover_candidates",
        delayed_discovery,
    )
    service = InvariantService(session_factory)
    scan_task = asyncio.create_task(
        asyncio.to_thread(lambda: asyncio.run(service.scan(run.run_id)))
    )
    assert await asyncio.to_thread(discovery_started.wait, 1)

    began = time.monotonic()
    with session_factory() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        session.execute(
            text("UPDATE runs SET name = name WHERE id = :run_id"),
            {"run_id": run.run_id},
        )
        session.commit()
    elapsed = time.monotonic() - began

    release_discovery.set()
    assert await scan_task == 0
    assert elapsed < 0.25


async def test_two_outbox_workers_claim_each_row_only_once(
    session_factory,
    monkeypatch,
):
    run = await create_seeded_run(session_factory, "outbox-claim")
    with session_factory() as session, session.begin():
        session.add(
            TelemetryOutbox(
                id="00000000-0000-0000-0000-000000000888",
                event_key="stale-commit:claim:test",
                run_id=run.run_id,
                event_type="tracefence.stale_action_committed",
                payload_json={
                    "command_id": "command",
                    "action_id": "action",
                    "node_id": run.root_node_id,
                    "tool_name": "restart_postgres",
                },
                created_at=utcnow(),
            )
        )

    flush_count = 0
    flush_lock = threading.Lock()

    def successful_slow_flush() -> bool:
        nonlocal flush_count
        with flush_lock:
            flush_count += 1
        time.sleep(0.1)
        return True

    monkeypatch.setattr(invariant_module, "telemetry_health", lambda: {"status": "READY"})
    monkeypatch.setattr(
        invariant_module,
        "force_flush_telemetry",
        successful_slow_flush,
    )
    first = InvariantService(session_factory, owner_id="process-a")
    second = InvariantService(session_factory, owner_id="process-b")

    def deliver(service: InvariantService) -> int:
        return asyncio.run(service.deliver_pending())

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=2) as pool:
        delivered = await asyncio.gather(
            loop.run_in_executor(pool, deliver, first),
            loop.run_in_executor(pool, deliver, second),
        )

    assert sum(delivered) == 1
    assert flush_count == 1
    with session_factory() as session:
        row = session.get(
            TelemetryOutbox,
            "00000000-0000-0000-0000-000000000888",
        )
        assert row is not None
        assert row.delivered_at is not None
        assert row.attempts == 1
        assert row.claim_owner is None


def test_stale_violation_gauge_is_latched():
    update_stale_violation_gauge(1)
    update_stale_violation_gauge(0)

    assert gauge_snapshot().stale_violation_latched == 1
