from __future__ import annotations

import hashlib
import math
import time
from collections import OrderedDict, deque
from threading import Lock

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tracefence.security import operator_key_matches


class RequestSizeLimitMiddleware:
    """Enforce a real streaming request-body limit.

    Content-Length is rejected early when present, but the byte counter also wraps
    ``receive`` so chunked or misleading requests cannot bypass the limit.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {
            "POST",
            "PUT",
            "PATCH",
        }:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                declared = int(raw_length)
            except ValueError:
                await self._send_error(
                    scope,
                    receive,
                    send,
                    status_code=400,
                    code="INVALID_CONTENT_LENGTH",
                    message="Invalid Content-Length header",
                )
                return
            if declared < 0:
                await self._send_error(
                    scope,
                    receive,
                    send,
                    status_code=400,
                    code="INVALID_CONTENT_LENGTH",
                    message="Invalid Content-Length header",
                )
                return
            if declared > self.max_bytes:
                await self._send_too_large(scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _RequestBodyTooLarge
            return message

        response_started = False

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestBodyTooLarge:
            if response_started:
                # Body parsing happens before endpoint responses in FastAPI. This
                # branch is defensive: never attempt a second response once bytes
                # have already been sent.
                return
            await self._send_too_large(scope, receive, send)

    async def _send_too_large(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._send_error(
            scope,
            receive,
            send,
            status_code=413,
            code="REQUEST_TOO_LARGE",
            message="Request body exceeds the configured limit",
        )

    @staticmethod
    async def _send_error(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        code: str,
        message: str,
    ) -> None:
        response = JSONResponse(
            status_code=status_code,
            content={"error": {"code": code, "message": message}},
        )
        await response(scope, receive, send)


class _RequestBodyTooLarge(Exception):
    pass


class RateLimitMiddleware:
    """Bound authenticated API traffic without storing raw credentials.

    This process-local limiter is appropriate for the single-process hackathon
    deployment. A multi-replica deployment must replace it with a shared limiter.
    Health checks and static assets are deliberately excluded.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        requests_per_minute: int,
        proof_requests_per_minute: int,
        max_buckets: int,
    ) -> None:
        self.app = app
        self.requests_per_minute = requests_per_minute
        self.proof_requests_per_minute = proof_requests_per_minute
        self.max_buckets = max_buckets
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = Lock()

    @staticmethod
    def _principal_key(scope: Scope) -> str:
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        operator_raw = headers.get(b"x-operator-key")
        if operator_raw is not None:
            operator = operator_raw.decode("utf-8", errors="replace")
            if operator_key_matches(operator):
                digest = hashlib.sha256(operator_raw).hexdigest()[:24]
                return "operator:" + digest

        # Node credentials cannot be authenticated safely in middleware without a
        # database lookup. Keying on caller-supplied node IDs or token strings would
        # let an attacker rotate arbitrary values to evade limits and churn the LRU
        # bucket map. Unauthenticated and node traffic is therefore bounded by the
        # network principal until route-level authentication succeeds.
        client = scope.get("client")
        host = client[0] if isinstance(client, tuple) and client else "unknown"
        return "client:" + str(host)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        if not path.startswith("/v1/"):
            await self.app(scope, receive, send)
            return

        is_proof = path.startswith("/v1/commands/") and path.endswith("/proof")
        limit = (
            self.proof_requests_per_minute if is_proof else self.requests_per_minute
        )
        namespace = "proof" if is_proof else "api"
        key = f"{namespace}:{self._principal_key(scope)}"
        now = time.monotonic()
        cutoff = now - 60.0
        retry_after = 0

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self.max_buckets:
                    self._buckets.popitem(last=False)
                bucket = deque()
                self._buckets[key] = bucket
            else:
                self._buckets.move_to_end(key)
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, math.ceil(60.0 - (now - bucket[0])))
            else:
                bucket.append(now)

        if retry_after:
            response = JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "Request rate limit exceeded",
                    }
                },
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Add conservative browser security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (
                            b"content-security-policy",
                            b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
                        ),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                        (b"cross-origin-opener-policy", b"same-origin"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, secure_send)
