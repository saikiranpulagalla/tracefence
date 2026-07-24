from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import Future
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from tracefence.api.dependencies import (
    control_plane_runtime,
    external_io_runtime,
    require_operator,
)
from tracefence.config import settings
from tracefence.db.engine import SessionLocal
from tracefence.signoz.mcp_client import mcp_health
from tracefence.telemetry.instruments import gauge_snapshot
from tracefence.telemetry.setup import telemetry_health

router = APIRouter(tags=["health"])

_cache_lock = threading.Lock()
_cached_key: tuple[object, ...] | None = None
_cached_until = 0.0
_cached_result: tuple[dict[str, object], bool] | None = None
_inflight: dict[tuple[object, ...], Future[tuple[dict[str, object], bool]]] = {}


class _Identity:
    __slots__ = ("value",)

    def __init__(self, value: object) -> None:
        self.value = value

    def __hash__(self) -> int:
        return id(self.value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Identity) and self.value is other.value


def _database_readable() -> bool:
    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def _database_writable() -> bool:
    try:
        with SessionLocal() as session:
            session.execute(text("PRAGMA busy_timeout=250"))
            session.execute(text("BEGIN IMMEDIATE"))
            session.execute(
                text("UPDATE schema_metadata SET version = version WHERE id = 1")
            )
            session.rollback()
        return True
    except Exception:
        return False


def _database_ready() -> bool:
    """Compatibility aggregate retained for callers that need one boolean."""

    return _database_readable() and _database_writable()


_DEFAULT_DATABASE_READY = _database_ready


def _freshness(
    value: object,
    *,
    max_age_seconds: int,
    now: datetime | None = None,
) -> tuple[bool, float | None]:
    if not isinstance(value, str) or not value:
        return False, None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False, None
    if parsed.tzinfo is None:
        return False, None
    current = now or datetime.now(UTC)
    age = (current - parsed.astimezone(UTC)).total_seconds()
    return -5 <= age <= max_age_seconds, max(age, 0.0)


def _state_value(request: Request, name: str) -> object:
    return getattr(request.app.state, name, None)


def _readiness_key(request: Request) -> tuple[object, ...]:
    safety_probe = getattr(
        control_plane_runtime.probe,
        "__func__",
        control_plane_runtime.probe,
    )
    external_probe = getattr(
        external_io_runtime.probe,
        "__func__",
        external_io_runtime.probe,
    )
    return (
        _Identity(request.app),
        _state_value(request, "lease_scanner_last_success"),
        bool(_state_value(request, "lease_scanner_error")),
        _state_value(request, "invariant_auditor_last_success"),
        bool(_state_value(request, "invariant_auditor_error")),
        _state_value(request, "invariant_outbox_pending"),
        id(_database_ready),
        id(_database_readable),
        id(_database_writable),
        id(safety_probe),
        id(external_probe),
    )


async def _compute_readiness(
    request: Request,
) -> tuple[dict[str, object], bool]:
    database_readable, database_writable = await asyncio.gather(
        asyncio.to_thread(_database_readable),
        asyncio.to_thread(_database_writable),
    )
    database_aggregate = database_readable and database_writable
    if _database_ready is not _DEFAULT_DATABASE_READY:
        database_aggregate = await asyncio.to_thread(_database_ready)
    safety_ready, external_ready = await asyncio.gather(
        control_plane_runtime.probe(),
        external_io_runtime.probe(),
    )
    scanner_last_success = _state_value(request, "lease_scanner_last_success")
    scanner_error = _state_value(request, "lease_scanner_error")
    auditor_last_success = _state_value(
        request,
        "invariant_auditor_last_success",
    )
    auditor_error = _state_value(request, "invariant_auditor_error")
    outbox_pending = _state_value(request, "invariant_outbox_pending")
    freshness_limit = max(5, settings.lease_scan_interval_seconds * 3)
    scanner_fresh, scanner_age = _freshness(
        scanner_last_success,
        max_age_seconds=freshness_limit,
    )
    auditor_fresh, auditor_age = _freshness(
        auditor_last_success,
        max_age_seconds=freshness_limit,
    )
    raw_telemetry = telemetry_health()
    telemetry_status = str(raw_telemetry.get("status", "UNKNOWN"))
    telemetry_configured = bool(raw_telemetry.get("configured"))
    flush_at = raw_telemetry.get("last_successful_flush_at")
    telemetry_fresh, telemetry_age = _freshness(
        flush_at,
        max_age_seconds=max(30, settings.lease_scan_interval_seconds * 5),
    )
    if not telemetry_configured:
        telemetry_fresh = True
    gauges = gauge_snapshot()
    delivery_timestamp = gauges.telemetry_delivery_last_success_unixtime
    delivery_age = (
        max(0.0, datetime.now(UTC).timestamp() - delivery_timestamp)
        if delivery_timestamp
        else None
    )
    outbox_healthy = isinstance(outbox_pending, int) and outbox_pending == 0
    telemetry_ready = (
        telemetry_status == "READY"
        if telemetry_configured
        else telemetry_status == "DISABLED"
    )
    database_ok = (
        database_aggregate and database_readable and database_writable
    )
    ready = (
        database_ok
        and safety_ready
        and scanner_error is None
        and scanner_fresh
        and auditor_error is None
        and auditor_fresh
        and (not telemetry_configured or outbox_healthy)
        and telemetry_ready
        and telemetry_fresh
    )
    observed_mcp_health = mcp_health()
    payload: dict[str, object] = {
        "status": "ok" if ready else "degraded",
        "service": "tracefence-control-plane",
        "database": "ready" if database_ok else "unavailable",
        "database_checks": {
            "readable": database_readable,
            "writable": database_writable,
        },
        "safety_executor": "ready" if safety_ready else "unavailable",
        "control_runtime": "ready" if safety_ready else "unavailable",
        "external_executor": "ready" if external_ready else "unavailable",
        "telemetry": {
            "status": telemetry_status,
            "configured": telemetry_configured,
            "recently_delivered": telemetry_fresh,
            "last_flush_age_seconds": telemetry_age,
            "outbox_delivery_age_seconds": delivery_age,
        },
        "mcp": observed_mcp_health,
        "lease_scanner": {
            "last_success": scanner_last_success,
            "age_seconds": scanner_age,
            "fresh": scanner_fresh,
            "error": scanner_error is not None,
        },
        "invariant_auditor": {
            "last_success": auditor_last_success,
            "age_seconds": auditor_age,
            "fresh": auditor_fresh,
            "error": auditor_error is not None,
            "outbox_pending": outbox_pending,
            "outbox_healthy": outbox_healthy,
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }
    return payload, ready


async def _readiness_payload(
    request: Request,
) -> tuple[dict[str, object], bool]:
    global _cached_key, _cached_result, _cached_until

    key = _readiness_key(request)
    now = time.monotonic()
    owner = False
    with _cache_lock:
        if (
            _cached_key == key
            and _cached_result is not None
            and now < _cached_until
        ):
            return _cached_result
        shared = _inflight.get(key)
        if shared is None:
            shared = Future()
            _inflight[key] = shared
            owner = True
    if not owner:
        return await asyncio.shield(asyncio.wrap_future(shared))

    try:
        result = await _compute_readiness(request)
    except BaseException as exc:
        with _cache_lock:
            _inflight.pop(key, None)
            if not shared.done():
                shared.set_exception(exc)
        raise
    with _cache_lock:
        _cached_key = key
        _cached_result = result
        _cached_until = time.monotonic() + settings.readiness_cache_seconds
        _inflight.pop(key, None)
        if not shared.done():
            shared.set_result(result)
    return result


@router.get("/livez")
async def livez() -> dict[str, str]:
    return {"status": "alive", "service": "tracefence-control-plane"}


@router.get("/readyz")
async def readiness(request: Request) -> JSONResponse:
    payload, ready = await _readiness_payload(request)
    public = {
        "status": payload["status"],
        "service": payload["service"],
    }
    return JSONResponse(public, status_code=200 if ready else 503)


@router.get("/health", dependencies=[Depends(require_operator)])
async def detailed_health(request: Request) -> JSONResponse:
    payload, ready = await _readiness_payload(request)
    return JSONResponse(
        payload,
        status_code=200 if ready else 503,
        headers={"Cache-Control": "no-store, private"},
    )
