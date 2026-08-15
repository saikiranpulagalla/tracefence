"""Typed runtime-stop adapter boundary.

The Phase 2B controller deliberately has no production adapter: a
WorkerInstance is durable identity, not a trusted operating-system handle.
Future adapters must resolve their own trusted binding and make every method
safe for at-least-once invocation.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from tracefence.db.models import WorkerInstance


class StopRequestOutcome(StrEnum):
    ACCEPTED = "ACCEPTED"
    ALREADY_TERMINAL = "ALREADY_TERMINAL"
    UNSUPPORTED = "UNSUPPORTED"
    RETRYABLE_ERROR = "RETRYABLE_ERROR"
    PERMANENT_ERROR = "PERMANENT_ERROR"
    UNKNOWN = "UNKNOWN"


class TerminalObservation(StrEnum):
    EXITED = "EXITED"
    FAILED = "FAILED"
    RUNNING = "RUNNING"
    UNKNOWN = "UNKNOWN"
    RETRYABLE_ERROR = "RETRYABLE_ERROR"
    PERMANENT_ERROR = "PERMANENT_ERROR"


class RuntimeAdapter(Protocol):
    """Idempotent operations over adapter-owned trusted runtime bindings."""

    def request_stop(self, worker_instance: WorkerInstance) -> StopRequestOutcome: ...

    def observe_terminal(self, worker_instance: WorkerInstance) -> TerminalObservation: ...
