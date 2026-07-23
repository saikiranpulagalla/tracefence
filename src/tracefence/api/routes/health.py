from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from tracefence.api.dependencies import control_plane_runtime
from tracefence.config import settings
from tracefence.db.engine import SessionLocal
from tracefence.telemetry.setup import telemetry_health

router = APIRouter(tags=["health"])


def _database_ready() -> bool:
    try:
        with SessionLocal() as session:
            bind = session.get_bind()
            if bind.dialect.name == "sqlite":
                # A read-only SELECT can stay green after the database becomes
                # unwritable. Acquiring and rolling back an immediate transaction
                # verifies the lock/write path without mutating application data.
                session.execute(text("PRAGMA busy_timeout=250"))
                session.execute(text("BEGIN IMMEDIATE"))
                session.execute(text("SELECT 1"))
                session.rollback()
            else:
                session.execute(text("SELECT 1"))
                session.rollback()
        return True
    except Exception:
        return False


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


async def _readiness_payload(request: Request) -> tuple[dict[str, object], bool]:
    database_ready = await asyncio.to_thread(_database_ready)
    scanner_last_success = getattr(request.app.state, "lease_scanner_last_success", None)
    scanner_error = getattr(request.app.state, "lease_scanner_error", None)
    auditor_last_success = getattr(
        request.app.state, "invariant_auditor_last_success", None
    )
    auditor_error = getattr(request.app.state, "invariant_auditor_error", None)
    outbox_pending = getattr(request.app.state, "invariant_outbox_pending", None)
    runtime_ready = await control_plane_runtime.probe()
    freshness_limit = max(5, settings.lease_scan_interval_seconds * 3)
    scanner_fresh, scanner_age = _freshness(
        scanner_last_success,
        max_age_seconds=freshness_limit,
    )
    auditor_fresh, auditor_age = _freshness(
        auditor_last_success,
        max_age_seconds=freshness_limit,
    )
    telemetry = telemetry_health()
    telemetry_ready = (
        telemetry["status"] == "READY"
        if settings.otlp_endpoint
        else telemetry["status"] == "DISABLED"
    )
    ready = (
        database_ready
        and runtime_ready
        and scanner_error is None
        and scanner_fresh
        and auditor_error is None
        and auditor_fresh
        and (not settings.otlp_endpoint or outbox_pending == 0)
        and telemetry_ready
    )
    payload: dict[str, object] = {
        "status": "ok" if ready else "degraded",
        "service": "tracefence-control-plane",
        "database": "ready" if database_ready else "unavailable",
        "control_runtime": "ready" if runtime_ready else "unavailable",
        "telemetry": telemetry,
        "lease_scanner": {
            "last_success": scanner_last_success,
            "age_seconds": scanner_age,
            "fresh": scanner_fresh,
            "error": scanner_error,
        },
        "invariant_auditor": {
            "last_success": auditor_last_success,
            "age_seconds": auditor_age,
            "fresh": auditor_fresh,
            "error": auditor_error,
            "outbox_pending": outbox_pending,
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }
    return payload, ready


@router.get("/livez")
async def livez() -> dict[str, str]:
    return {"status": "alive", "service": "tracefence-control-plane"}


@router.get("/health")
@router.get("/readyz")
async def readiness(request: Request) -> JSONResponse:
    payload, ready = await _readiness_payload(request)
    return JSONResponse(payload, status_code=200 if ready else 503)
