from __future__ import annotations

import asyncio
import threading
import time

import pytest

from tracefence.api.dependencies import BoundedServiceRuntime, ControlPlaneRuntime
from tracefence.domain.errors import ServiceUnavailableError


async def test_control_plane_runtime_uses_bounded_parallel_worker_loops():
    runtime = ControlPlaneRuntime(max_workers=3)
    state_lock = threading.Lock()
    start_barrier = threading.Barrier(3)
    loop_ids: set[int] = set()
    thread_ids: set[int] = set()
    active = 0
    max_active = 0

    async def operation(value: int) -> int:
        nonlocal active, max_active
        loop_ids.add(id(asyncio.get_running_loop()))
        thread_ids.add(threading.get_ident())
        start_barrier.wait(timeout=2)
        with state_lock:
            active += 1
            max_active = max(max_active, active)
        await asyncio.sleep(0.03)
        with state_lock:
            active -= 1
        return value

    try:
        results = await asyncio.gather(
            runtime.run(operation(1)),
            runtime.run(operation(2)),
            runtime.run(operation(3)),
        )
    finally:
        await runtime.stop()

    assert results == [1, 2, 3]
    assert len(loop_ids) == 3
    assert len(thread_ids) == 3
    assert max_active == 3
    assert not runtime.is_alive()


async def test_runtime_rejects_saturated_queue_with_stable_code():
    runtime = BoundedServiceRuntime(
        name="safety",
        max_workers=1,
        max_queue=1,
        deadline_seconds=1.0,
    )
    release = threading.Event()
    started = threading.Event()

    async def blocked() -> None:
        started.set()
        release.wait(timeout=2)

    owner = asyncio.create_task(runtime.run(blocked()))
    assert await asyncio.to_thread(started.wait, 1)
    queued = asyncio.create_task(runtime.run(blocked()))
    await asyncio.sleep(0)

    rejected = blocked()
    with pytest.raises(ServiceUnavailableError) as captured:
        await runtime.run(rejected)
    assert captured.value.code == "SAFETY_EXECUTOR_OVERLOADED"

    release.set()
    await asyncio.gather(owner, queued)
    await runtime.stop()


async def test_eight_blocked_external_proofs_do_not_starve_safety_heartbeat():
    safety = BoundedServiceRuntime(
        name="safety",
        max_workers=2,
        max_queue=8,
        deadline_seconds=1.0,
    )
    external = BoundedServiceRuntime(
        name="external",
        max_workers=8,
        max_queue=8,
        deadline_seconds=2.0,
    )
    release = threading.Event()
    started = threading.Barrier(9)

    async def slow_proof() -> None:
        started.wait(timeout=2)
        release.wait(timeout=2)

    proof_tasks = [
        asyncio.create_task(external.run(slow_proof()))
        for _ in range(8)
    ]
    await asyncio.to_thread(started.wait, 2)

    began = time.monotonic()
    result = await safety.run(asyncio.sleep(0, result="heartbeat-ok"))
    elapsed = time.monotonic() - began

    assert result == "heartbeat-ok"
    assert elapsed < 0.25
    release.set()
    await asyncio.gather(*proof_tasks)
    await safety.stop()
    await external.stop()


async def test_waiter_cancellation_does_not_cancel_submitted_authoritative_work():
    runtime = BoundedServiceRuntime(
        name="external",
        max_workers=1,
        max_queue=1,
        deadline_seconds=2.0,
    )
    started = threading.Event()
    release = threading.Event()
    completed = threading.Event()

    async def authoritative_work() -> None:
        started.set()
        release.wait(timeout=2)
        completed.set()

    waiter = asyncio.create_task(runtime.run(authoritative_work()))
    assert await asyncio.to_thread(started.wait, 1)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    release.set()
    assert await asyncio.to_thread(completed.wait, 1)
    await runtime.stop()
