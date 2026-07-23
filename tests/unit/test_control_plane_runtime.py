from __future__ import annotations

import asyncio
import threading
import time

from tracefence.api.dependencies import ControlPlaneRuntime


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
        # Model the synchronous SQLAlchemy work performed by service coroutines.
        time.sleep(0.03)
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
