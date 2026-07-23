from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Coroutine
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

from fastapi import Header

from tracefence.config import settings
from tracefence.db.engine import SessionLocal
from tracefence.domain.errors import AuthenticationError, ServiceUnavailableError
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


class BoundedServiceRuntime:
    """Run blocking synchronous-DB service coroutines in a bounded worker pool.

    Service methods retain an async public API for MCP/network operations, but
    their SQLite work must never execute on FastAPI's event loop. Each submitted
    coroutine receives a private event loop in a worker thread. Singleton
    services therefore use only loop-independent synchronization primitives.
    SQLite still serializes conflicting ``BEGIN IMMEDIATE`` safety writes, while
    independent reads and non-conflicting work can proceed concurrently.
    """

    def __init__(
        self,
        *,
        name: str,
        max_workers: int,
        max_queue: int,
        deadline_seconds: float,
    ) -> None:
        self._name = name
        self._max_workers = max_workers
        self._deadline_seconds = deadline_seconds
        self._state_lock = threading.Lock()
        self._capacity = threading.BoundedSemaphore(max_workers + max_queue)
        self._executor: ThreadPoolExecutor | None = None

    def start(self) -> None:
        with self._state_lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix=f"tracefence-{self._name}",
                )

    @staticmethod
    def _run_coroutine[T](coroutine: Coroutine[Any, Any, T]) -> T:
        return asyncio.run(coroutine)

    def _run_and_release[T](self, coroutine: Coroutine[Any, Any, T]) -> T:
        try:
            return self._run_coroutine(coroutine)
        finally:
            self._capacity.release()

    async def run[T](self, coroutine: Coroutine[Any, Any, T]) -> T:
        self.start()
        if not self._capacity.acquire(blocking=False):
            coroutine.close()
            raise ServiceUnavailableError(
                f"{self._name.title()} executor is overloaded",
                code=f"{self._name.upper()}_EXECUTOR_OVERLOADED",
            )
        with self._state_lock:
            executor = self._executor
        if executor is None:
            self._capacity.release()
            coroutine.close()
            raise ServiceUnavailableError(
                f"{self._name.title()} executor is unavailable",
                code=f"{self._name.upper()}_EXECUTOR_UNAVAILABLE",
            )
        try:
            future: Future[T] = executor.submit(self._run_and_release, coroutine)
        except BaseException:
            self._capacity.release()
            coroutine.close()
            raise
        wrapped = asyncio.wrap_future(future)
        try:
            return await asyncio.wait_for(
                asyncio.shield(wrapped),
                timeout=self._deadline_seconds,
            )
        except TimeoutError as exc:
            raise ServiceUnavailableError(
                f"{self._name.title()} operation exceeded its deadline",
                code=f"{self._name.upper()}_EXECUTION_DEADLINE_EXCEEDED",
            ) from exc

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


class ControlPlaneRuntime(BoundedServiceRuntime):
    def __init__(self, max_workers: int | None = None) -> None:
        super().__init__(
            name="safety",
            max_workers=max_workers or settings.control_plane_workers,
            max_queue=settings.safety_queue_size,
            deadline_seconds=settings.safety_deadline_seconds,
        )


control_plane_runtime = ControlPlaneRuntime()
external_io_runtime = BoundedServiceRuntime(
    name="external",
    max_workers=settings.external_io_workers,
    max_queue=settings.external_io_queue_size,
    deadline_seconds=settings.external_io_deadline_seconds,
)

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


async def call_blocking_service[T](factory: Callable[[], Awaitable[T]]) -> T:
    coroutine = factory()
    if not isinstance(coroutine, Coroutine):
        raise TypeError("Service factory must return a coroutine")
    return await control_plane_runtime.run(coroutine)


async def call_external_service[T](factory: Callable[[], Awaitable[T]]) -> T:
    coroutine = factory()
    if not isinstance(coroutine, Coroutine):
        raise TypeError("Service factory must return a coroutine")
    return await external_io_runtime.run(coroutine)


def require_operator(
    x_operator_key: str | None = Header(default=None, alias="X-Operator-Key"),
) -> None:
    if not operator_key_matches(x_operator_key):
        raise AuthenticationError("Invalid or missing operator key")
