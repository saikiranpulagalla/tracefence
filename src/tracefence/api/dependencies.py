from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Coroutine
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, TypeVar

from fastapi import Header

from tracefence.config import settings
from tracefence.db.engine import SessionLocal
from tracefence.domain.errors import AuthenticationError
from tracefence.security import operator_key_matches
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.control_service import ControlService
from tracefence.services.graph_service import GraphService
from tracefence.services.invariant_service import InvariantService
from tracefence.services.lease_service import LeaseService
from tracefence.services.proof_service import ProofService
from tracefence.services.proposal_service import ProposalService
from tracefence.services.run_service import RunService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService

T = TypeVar("T")


class ControlPlaneRuntime:
    """Run blocking synchronous-DB service coroutines in a bounded worker pool.

    Service methods retain an async public API for MCP/network operations, but
    their SQLite work must never execute on FastAPI's event loop. Each submitted
    coroutine receives a private event loop in a worker thread. Singleton
    services therefore use only loop-independent synchronization primitives.
    SQLite still serializes conflicting ``BEGIN IMMEDIATE`` safety writes, while
    independent reads and non-conflicting work can proceed concurrently.
    """

    def __init__(self, max_workers: int | None = None) -> None:
        self._max_workers = max_workers or settings.control_plane_workers
        self._state_lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None

    def start(self) -> None:
        with self._state_lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix="tracefence-control-plane",
                )

    @staticmethod
    def _run_coroutine(coroutine: Coroutine[Any, Any, T]) -> T:
        return asyncio.run(coroutine)

    async def run(self, coroutine: Coroutine[Any, Any, T]) -> T:
        self.start()
        with self._state_lock:
            executor = self._executor
        if executor is None:
            coroutine.close()
            raise RuntimeError("Control-plane runtime is not available")
        try:
            future: Future[T] = executor.submit(self._run_coroutine, coroutine)
        except BaseException:
            coroutine.close()
            raise
        return await asyncio.wrap_future(future)

    def is_alive(self) -> bool:
        with self._state_lock:
            return self._executor is not None

    async def probe(self, timeout_seconds: float = 1.0) -> bool:
        with self._state_lock:
            executor = self._executor
        if executor is None:
            return False

        async def ping() -> bool:
            return True

        try:
            return bool(await asyncio.wait_for(self.run(ping()), timeout_seconds))
        except (TimeoutError, RuntimeError):
            return False

    async def stop(self) -> None:
        with self._state_lock:
            executor = self._executor
            self._executor = None
        if executor is not None:
            await asyncio.to_thread(executor.shutdown, True, cancel_futures=True)


control_plane_runtime = ControlPlaneRuntime()

run_service = RunService(SessionLocal)
spawn_service = SpawnService(SessionLocal)
proposal_service = ProposalService(SessionLocal)
control_service = ControlService(SessionLocal)
action_gateway = ActionGateway(SessionLocal)
graph_service = GraphService(SessionLocal)
proof_service = ProofService(SessionLocal)
invariant_service = InvariantService(SessionLocal)
lease_service = LeaseService(SessionLocal)
state_service = StateService(SessionLocal)


async def call_blocking_service(factory: Callable[[], Awaitable[T]]) -> T:
    coroutine = factory()
    if not isinstance(coroutine, Coroutine):
        raise TypeError("Service factory must return a coroutine")
    return await control_plane_runtime.run(coroutine)


def require_operator(
    x_operator_key: str | None = Header(default=None, alias="X-Operator-Key"),
) -> None:
    if not operator_key_matches(x_operator_key):
        raise AuthenticationError("Invalid or missing operator key")
