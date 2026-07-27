from __future__ import annotations

import asyncio
import json

import pytest

from tracefence.runtime import worker


@pytest.mark.asyncio
async def test_one_async_reader_preserves_startup_and_prebuffered_release() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(
        (json.dumps({"activation_token": "test-token"}) + "\nGO\n").encode()
    )
    reader.feed_eof()

    assert await worker._read_startup_payload(reader) == {
        "activation_token": "test-token"
    }
    assert await worker._read_release_signal(reader) == "GO\n"


@pytest.mark.asyncio
async def test_release_reader_cancels_without_a_background_thread() -> None:
    reader = asyncio.StreamReader()
    task = asyncio.create_task(worker._read_release_signal(reader))
    await asyncio.sleep(0)

    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_termination_event_cancels_worker_task_before_returning() -> None:
    worker_started = asyncio.Event()
    worker_cancelled = asyncio.Event()
    termination = asyncio.Event()

    async def blocked_worker() -> int:
        worker_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            worker_cancelled.set()

    task = asyncio.create_task(
        worker._await_worker_or_termination(blocked_worker(), termination)
    )
    await worker_started.wait()

    termination.set()

    assert await task == 143
    assert worker_cancelled.is_set()
