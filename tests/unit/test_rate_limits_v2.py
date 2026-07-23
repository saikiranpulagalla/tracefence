from __future__ import annotations

import pytest

from tests.unit.test_release_hardening import _asgi_request
from tracefence.api.middleware import RateLimitMiddleware
from tracefence.domain.errors import RateLimitError
from tracefence.rate_limits import AuthenticatedRateLimiter


def test_fifty_nodes_share_ip_without_heartbeat_self_throttling():
    limiter = AuthenticatedRateLimiter(
        limits={"heartbeat": 90},
        max_buckets=1_000,
    )

    for heartbeat_number in range(40):
        for node_number in range(50):
            limiter.check(
                "heartbeat",
                f"run-1:node-{node_number}",
                now=float(heartbeat_number),
            )

    assert limiter.bucket_count == 50


async def test_invalid_token_flood_remains_ip_limited_when_node_ids_rotate():
    calls = 0

    async def downstream(scope, receive, send):
        nonlocal calls
        calls += 1
        await send({"type": "http.response.start", "status": 401, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = RateLimitMiddleware(
        downstream,
        requests_per_minute=2,
        proof_requests_per_minute=1,
        max_buckets=20,
    )
    responses = []
    for number in range(3):
        responses.append(
            await _asgi_request(
                middleware,
                path=f"/v1/nodes/fake-{number}/heartbeat",
                headers=[
                    (b"x-node-id", f"fake-{number}".encode()),
                    (b"x-node-token", f"invalid-{number}".encode()),
                ],
            )
        )

    assert [response[0]["status"] for response in responses] == [401, 401, 429]
    assert calls == 2


def test_proof_flood_does_not_consume_heartbeat_allowance():
    limiter = AuthenticatedRateLimiter(
        limits={"proof": 1, "heartbeat": 3},
        max_buckets=20,
    )
    limiter.check("proof", "operator-1", now=1.0)
    with pytest.raises(RateLimitError):
        limiter.check("proof", "operator-1", now=2.0)

    for timestamp in (1.0, 2.0, 3.0):
        limiter.check("heartbeat", "run-1:node-1", now=timestamp)


def test_authenticated_limiter_memory_is_bounded():
    limiter = AuthenticatedRateLimiter(
        limits={"heartbeat": 2},
        max_buckets=10,
    )
    for number in range(100):
        limiter.check("heartbeat", f"run-1:node-{number}", now=1.0)
    assert limiter.bucket_count == 10


async def test_forwarded_ip_is_used_only_for_explicitly_trusted_proxy():
    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    untrusted = RateLimitMiddleware(
        downstream,
        requests_per_minute=1,
        proof_requests_per_minute=1,
        max_buckets=20,
        trusted_proxy_hosts={"10.0.0.10"},
    )
    headers_a = [(b"x-forwarded-for", b"203.0.113.1")]
    headers_b = [(b"x-forwarded-for", b"203.0.113.2")]
    first = await _asgi_request(
        untrusted,
        path="/v1/nodes/a/heartbeat",
        headers=headers_a,
        client_host="198.51.100.5",
    )
    second = await _asgi_request(
        untrusted,
        path="/v1/nodes/b/heartbeat",
        headers=headers_b,
        client_host="198.51.100.5",
    )
    assert [first[0]["status"], second[0]["status"]] == [204, 429]

    trusted = RateLimitMiddleware(
        downstream,
        requests_per_minute=1,
        proof_requests_per_minute=1,
        max_buckets=20,
        trusted_proxy_hosts={"10.0.0.10"},
    )
    forwarded_a = await _asgi_request(
        trusted,
        path="/v1/nodes/a/heartbeat",
        headers=headers_a,
        client_host="10.0.0.10",
    )
    forwarded_b = await _asgi_request(
        trusted,
        path="/v1/nodes/b/heartbeat",
        headers=headers_b,
        client_host="10.0.0.10",
    )
    assert [forwarded_a[0]["status"], forwarded_b[0]["status"]] == [204, 204]
