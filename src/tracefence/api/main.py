from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from tracefence.api.dependencies import (
    call_blocking_service,
    call_external_service,
    control_plane_runtime,
    external_io_runtime,
    invariant_service,
    lease_service,
)
from tracefence.api.exception_handlers import install_exception_handlers
from tracefence.api.middleware import (
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from tracefence.api.routes import actions, control, health, nodes, proofs, runs, scenario
from tracefence.config import settings
from tracefence.db.engine import init_db
from tracefence.logging_config import configure_logging
from tracefence.services.common import iso_utc, utcnow
from tracefence.telemetry.instruments import update_outbox_gauge
from tracefence.telemetry.setup import (
    configure_telemetry,
    force_flush_telemetry,
    instrument_app,
    register_telemetry_shutdown,
)

configure_logging()
logger = logging.getLogger(__name__)
configure_telemetry()
register_telemetry_shutdown()


async def _lease_scanner(app: FastAPI) -> None:
    while True:
        try:
            await call_blocking_service(lease_service.expire_stale_nodes)
            app.state.lease_scanner_last_success = iso_utc(utcnow())
            app.state.lease_scanner_error = None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            app.state.lease_scanner_error = f"{type(exc).__name__}: {exc}"
            logger.exception("Lease scanner iteration failed")
        await asyncio.sleep(settings.lease_scan_interval_seconds)


async def _invariant_auditor(app: FastAPI) -> None:
    while True:
        try:
            created = await call_blocking_service(invariant_service.scan)
            delivered = await call_external_service(invariant_service.deliver_pending)
            pending = await call_blocking_service(invariant_service.pending_count)
            app.state.invariant_outbox_pending = pending
            update_outbox_gauge(pending)
            app.state.invariant_auditor_last_success = iso_utc(utcnow())
            app.state.invariant_auditor_error = None
            if created or delivered:
                logger.warning(
                    "Invariant auditor processed created=%s delivered=%s",
                    created,
                    delivered,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            app.state.invariant_auditor_error = f"{type(exc).__name__}: {exc}"
            logger.exception("Invariant auditor iteration failed")
        await asyncio.sleep(settings.lease_scan_interval_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings.validate_security()
    init_db()
    control_plane_runtime.start()
    external_io_runtime.start()
    app.state.lease_scanner_last_success = None
    app.state.lease_scanner_error = None
    app.state.invariant_auditor_last_success = None
    app.state.invariant_auditor_error = None
    app.state.invariant_outbox_pending = None
    scanner = asyncio.create_task(_lease_scanner(app), name="tracefence-lease-scanner")
    auditor = asyncio.create_task(_invariant_auditor(app), name="tracefence-invariant-auditor")
    try:
        yield
    finally:
        scanner.cancel()
        auditor.cancel()
        with suppress(asyncio.CancelledError):
            await scanner
        with suppress(asyncio.CancelledError):
            await auditor
        await control_plane_runtime.stop()
        await external_io_runtime.stop()
        if not force_flush_telemetry():
            logger.error("Telemetry flush failed during application shutdown")


app = FastAPI(
    title="TraceFence",
    version="0.2.1rc2",
    description="Runtime-enforced cancellation and correction for dynamic AI-agent graphs",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin, "http://127.0.0.1:9000", "http://localhost:9000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Operator-Key", "X-Node-Id", "X-Node-Token"],
)


app.add_middleware(
    RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes
)
app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=settings.rate_limit_per_minute,
    proof_requests_per_minute=settings.proof_rate_limit_per_minute,
    max_buckets=settings.rate_limit_max_buckets,
    trusted_proxy_hosts=set(settings.trusted_proxy_hosts),
)
app.add_middleware(SecurityHeadersMiddleware)

install_exception_handlers(app)
app.include_router(health.router)
app.include_router(runs.router)
app.include_router(nodes.router)
app.include_router(control.router)
app.include_router(actions.router)
app.include_router(proofs.router)
app.include_router(scenario.router)
instrument_app(app)

_frontend_dir = Path(__file__).resolve().parents[1] / "frontend"
_frontend = _frontend_dir / "index.html"


@app.get("/", include_in_schema=False)
async def home() -> FileResponse:
    return FileResponse(_frontend)


@app.get("/assets/app.js", include_in_schema=False)
async def frontend_script() -> FileResponse:
    return FileResponse(_frontend_dir / "app.js", media_type="application/javascript")
