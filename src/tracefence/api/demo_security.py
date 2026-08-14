from __future__ import annotations

import secrets

from fastapi import Cookie, HTTPException, Request, Response

from tracefence.config import settings

_DEMO_COOKIE = "tracefence_demo_session"
_DEMO_NONCE = secrets.token_urlsafe(32)
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def demo_access_allowed(
    *,
    demo_mode: bool,
    environment: str,
    client_host: str | None,
    supplied_nonce: str | None,
    expected_nonce: str,
) -> bool:
    if not demo_mode:
        return False
    allowed_hosts = set(_LOOPBACK_HOSTS)
    if environment == "test":
        allowed_hosts.add("testclient")
    if client_host not in allowed_hosts:
        return False
    return bool(
        supplied_nonce
        and secrets.compare_digest(supplied_nonce, expected_nonce)
    )


def require_demo_bootstrap(request: Request) -> None:
    host = request.client.host if request.client is not None else None
    if not settings.demo_mode or host not in (
        _LOOPBACK_HOSTS | ({"testclient"} if settings.environment == "test" else set())
    ):
        raise HTTPException(status_code=404, detail="Not found")


def require_demo_access(
    request: Request,
    tracefence_demo_session: str | None = Cookie(
        default=None,
        alias=_DEMO_COOKIE,
    ),
) -> None:
    host = request.client.host if request.client is not None else None
    if not demo_access_allowed(
        demo_mode=settings.demo_mode,
        environment=settings.environment,
        client_host=host,
        supplied_nonce=tracefence_demo_session,
        expected_nonce=_DEMO_NONCE,
    ):
        # Demo routes deliberately disappear outside the explicit loopback
        # launcher boundary rather than becoming a second public control API.
        raise HTTPException(status_code=404, detail="Not found")


def set_demo_cookie(response: Response) -> None:
    response.set_cookie(
        key=_DEMO_COOKIE,
        value=_DEMO_NONCE,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/v1/demo",
        max_age=8 * 60 * 60,
    )
