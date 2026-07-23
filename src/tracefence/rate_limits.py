from __future__ import annotations

import time
from collections import OrderedDict, deque
from threading import Lock

from tracefence.config import settings
from tracefence.domain.errors import RateLimitError


class AuthenticatedRateLimiter:
    """Process-local limiter keyed only by server-authenticated identities."""

    def __init__(self, *, limits: dict[str, int], max_buckets: int) -> None:
        self._limits = dict(limits)
        self._max_buckets = max_buckets
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = Lock()

    @property
    def bucket_count(self) -> int:
        with self._lock:
            return len(self._buckets)

    def check(
        self,
        category: str,
        identity: str,
        *,
        now: float | None = None,
    ) -> None:
        limit = self._limits[category]
        observed_at = time.monotonic() if now is None else now
        cutoff = observed_at - 60.0
        key = f"{category}:{identity}"
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self._max_buckets:
                    self._buckets.popitem(last=False)
                bucket = deque()
                self._buckets[key] = bucket
            else:
                self._buckets.move_to_end(key)
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                raise RateLimitError(category)
            bucket.append(observed_at)


authenticated_rate_limiter = AuthenticatedRateLimiter(
    limits={
        "heartbeat": settings.heartbeat_rate_limit_per_minute,
        "action": settings.action_rate_limit_per_minute,
        "spawn": settings.spawn_rate_limit_per_minute,
        "activation": settings.activation_rate_limit_per_minute,
        "command": settings.command_rate_limit_per_minute,
        "proof": settings.proof_rate_limit_per_minute,
        "operator_read": settings.operator_read_rate_limit_per_minute,
    },
    max_buckets=settings.rate_limit_max_buckets,
)
