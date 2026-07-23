from __future__ import annotations

import atexit
import logging
import os
from datetime import UTC, datetime
from threading import Lock
from uuid import uuid4

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from tracefence.config import settings
from tracefence.logging_config import JsonFormatter
from tracefence.signoz.mcp_client import ExportWatermark

_logger = logging.getLogger(__name__)
_provider_lock = Lock()
_tracer_provider: TracerProvider | None = None
_meter_provider: MeterProvider | None = None
_logger_provider: object | None = None
_telemetry_state = "DISABLED"
_telemetry_errors: list[str] = []
_instrumentation_errors: list[str] = []
_otel_log_handler: logging.Handler | None = None
_configured_service_name: str | None = None
_shutdown_registered = False
_export_sequence = 0
_last_successful_flush_at: datetime | None = None
_last_export_watermark: ExportWatermark | None = None
_service_instance_id = os.getenv("TRACEFENCE_SERVICE_INSTANCE_ID") or str(uuid4())
_process_instance_id = str(uuid4())
_telemetry_schema_version = 1


def configure_telemetry(service_name: str = "tracefence-control-plane") -> None:
    global _tracer_provider, _meter_provider, _telemetry_state, _telemetry_errors
    global _configured_service_name
    with _provider_lock:
        if _configured_service_name is not None:
            if _configured_service_name != service_name:
                _logger.warning(
                    "Telemetry is already configured for %s; ignoring reconfiguration for %s",
                    _configured_service_name,
                    service_name,
                )
            return
        _configured_service_name = service_name
    _telemetry_errors = list(_instrumentation_errors)
    _telemetry_state = "CONFIGURED" if settings.otlp_endpoint else "DISABLED"

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.instance.id": _service_instance_id,
            "process.instance.id": _process_instance_id,
            "tracefence.build.commit": settings.build_commit or "UNSET",
            "tracefence.telemetry.schema_version": _telemetry_schema_version,
            "deployment.environment": settings.environment,
        }
    )

    tracer_provider = TracerProvider(resource=resource)
    if settings.otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            tracer_provider.add_span_processor(
                BatchSpanProcessor(
                    OTLPSpanExporter(endpoint=f"{settings.otlp_endpoint.rstrip('/')}/v1/traces")
                )
            )
        except Exception as exc:
            _telemetry_errors.append(f"trace exporter: {type(exc).__name__}: {exc}")
            _logger.exception("Failed to configure OTLP trace exporter")
    try:
        trace.set_tracer_provider(tracer_provider)
        active_tracer_provider = trace.get_tracer_provider()
        if active_tracer_provider is tracer_provider:
            with _provider_lock:
                _tracer_provider = tracer_provider
        else:
            # OpenTelemetry may reject a second provider by logging instead of
            # raising. Never retain or flush an unused candidate provider.
            tracer_provider.shutdown()
            _logger.debug("Global tracer provider is owned by the host process")
    except Exception:
        tracer_provider.shutdown()
        # A host process may already own the global provider. Do not crash the
        # control plane; the existing provider remains authoritative.
        _logger.debug("Global tracer provider was already configured", exc_info=True)

    meter_provider: MeterProvider
    if settings.otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

            metric_reader = PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=f"{settings.otlp_endpoint.rstrip('/')}/v1/metrics"),
                export_interval_millis=settings.otel_metric_export_interval_ms,
                export_timeout_millis=settings.otel_export_timeout_ms,
            )
            meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        except Exception as exc:
            _telemetry_errors.append(f"metric exporter: {type(exc).__name__}: {exc}")
            _logger.exception("Failed to configure OTLP metric exporter")
            meter_provider = MeterProvider(resource=resource)
    else:
        meter_provider = MeterProvider(resource=resource)
    try:
        metrics.set_meter_provider(meter_provider)
        active_meter_provider = metrics.get_meter_provider()
        if active_meter_provider is meter_provider:
            with _provider_lock:
                _meter_provider = meter_provider
        else:
            meter_provider.shutdown()
            _logger.debug("Global meter provider is owned by the host process")
    except Exception:
        meter_provider.shutdown()
        _logger.debug("Global meter provider was already configured", exc_info=True)

    if settings.otlp_endpoint:
        if not _configure_otlp_logs(resource):
            _telemetry_errors.append("log exporter unavailable")
        owned = (_tracer_provider, _meter_provider, _logger_provider)
        if _telemetry_errors:
            _telemetry_state = "FAILED"
        elif any(provider is None for provider in owned):
            _telemetry_state = "DEGRADED"
            _telemetry_errors.append("one or more telemetry providers are owned externally")
        else:
            _telemetry_state = "READY"


def _configure_otlp_logs(resource: Resource) -> bool:
    global _logger_provider, _otel_log_handler

    try:
        from opentelemetry._logs import get_logger_provider, set_logger_provider
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

        provider = LoggerProvider(resource=resource)
        provider.add_log_record_processor(
            BatchLogRecordProcessor(
                OTLPLogExporter(endpoint=f"{settings.otlp_endpoint.rstrip('/')}/v1/logs")
            )
        )
        set_logger_provider(provider)
        if get_logger_provider() is not provider:
            provider.shutdown()
            _logger.debug("Global logger provider is owned by the host process")
            return False
        with _provider_lock:
            _logger_provider = provider
        handler = LoggingHandler(level=logging.INFO, logger_provider=provider)
        handler.setFormatter(JsonFormatter())
        root = logging.getLogger()
        if not any(getattr(existing, "_tracefence_otel", False) for existing in root.handlers):
            telemetry_marker = "_tracefence_otel"
            setattr(handler, telemetry_marker, True)
            root.addHandler(handler)
            _otel_log_handler = handler
        return True
    except Exception:
        _logger.exception("Failed to configure OTLP log exporter")
        return False


def force_flush_telemetry(
    timeout_millis: int | None = None,
    *,
    run_id: str | None = None,
    command_id: str | None = None,
    command_created_ms: int | None = None,
) -> bool:
    """Flush spans, metrics and logs before evidence queries.

    A proof must not race the SDK's batch timers. Providers that are not owned by
    TraceFence are deliberately ignored rather than guessed at.
    """

    global _export_sequence, _last_successful_flush_at
    global _last_export_watermark

    if not settings.otlp_endpoint or _telemetry_state != "READY":
        return False
    proposed_sequence: int | None = None
    proposed_at: datetime | None = None
    if run_id is not None and command_id is not None:
        proposed_at = datetime.now(UTC)
        proposed_at_ms = int(proposed_at.timestamp() * 1000)
        if command_created_ms is not None and proposed_at_ms <= command_created_ms:
            return False
        with _provider_lock:
            _export_sequence += 1
            proposed_sequence = _export_sequence
        with trace.get_tracer("tracefence.telemetry").start_as_current_span(
            "tracefence.telemetry.export_watermark"
        ) as span:
            span.set_attribute("tracefence.run.id", run_id)
            span.set_attribute("tracefence.command.id", command_id)
            span.set_attribute("tracefence.telemetry.exported_at_ms", proposed_at_ms)
            span.set_attribute("tracefence.telemetry.export_sequence", proposed_sequence)
            span.set_attribute("tracefence.telemetry.schema_version", _telemetry_schema_version)

    timeout = timeout_millis or settings.otel_export_timeout_ms
    with _provider_lock:
        providers = (_tracer_provider, _meter_provider, _logger_provider)
    results: list[bool] = []
    for provider in providers:
        if provider is None:
            continue
        try:
            results.append(bool(provider.force_flush(timeout_millis=timeout)))  # type: ignore[attr-defined]
        except Exception:
            _logger.exception("Telemetry force-flush failed")
            results.append(False)
    if not results:
        return False
    success = all(results)
    if success:
        with _provider_lock:
            _last_successful_flush_at = datetime.now(UTC)
            if (
                run_id is not None
                and command_id is not None
                and proposed_at is not None
                and proposed_sequence is not None
            ):
                _last_export_watermark = ExportWatermark(
                    service_name=_configured_service_name
                    or "tracefence-control-plane",
                    service_instance_id=_service_instance_id,
                    process_instance_id=_process_instance_id,
                    build_commit=settings.build_commit or "UNSET",
                    schema_version=_telemetry_schema_version,
                    run_id=run_id,
                    command_id=command_id,
                    exported_at_ms=int(proposed_at.timestamp() * 1000),
                    sequence=proposed_sequence,
                )
    return success


def telemetry_export_watermark() -> str | None:
    """Return the latest successful owned-export flush identity for cache binding."""

    with _provider_lock:
        if _last_successful_flush_at is None or _configured_service_name is None:
            return None
        sequence = (
            _last_export_watermark.sequence
            if _last_export_watermark is not None
            else 0
        )
        return (
            f"{_configured_service_name}:{sequence}:"
            f"{_last_successful_flush_at.isoformat()}"
        )


def telemetry_export_context(
    run_id: str,
    command_id: str,
) -> ExportWatermark | None:
    """Return only a successful export bound to this run and command."""

    with _provider_lock:
        watermark = _last_export_watermark
        if (
            watermark is None
            or watermark.run_id != run_id
            or watermark.command_id != command_id
        ):
            return None
        return watermark


def telemetry_process_identity() -> dict[str, str | int]:
    """Return the immutable identity applied to all telemetry in this process."""

    with _provider_lock:
        return {
            "service_name": _configured_service_name
            or "tracefence-control-plane",
            "service_instance_id": _service_instance_id,
            "process_instance_id": _process_instance_id,
            "build_commit": settings.build_commit or "UNSET",
            "schema_version": _telemetry_schema_version,
        }


def telemetry_health() -> dict[str, object]:
    with _provider_lock:
        return {
            "status": _telemetry_state,
            "configured": bool(settings.otlp_endpoint),
            "errors": list(_telemetry_errors),
        }


def register_telemetry_shutdown() -> None:
    """Register one final process-level telemetry shutdown.

    ASGI lifespans can start and stop more than once in tests or embedded hosts,
    while OpenTelemetry's global providers cannot be replaced safely. The web
    application therefore flushes on lifespan shutdown and performs the actual
    provider shutdown only when the Python process exits.
    """

    global _shutdown_registered
    with _provider_lock:
        if _shutdown_registered:
            return
        _shutdown_registered = True
    atexit.register(shutdown_telemetry)


def shutdown_telemetry() -> None:
    global _tracer_provider, _meter_provider, _logger_provider, _telemetry_state
    global _otel_log_handler
    with _provider_lock:
        if _telemetry_state == "STOPPED":
            return
        providers = (_tracer_provider, _meter_provider, _logger_provider)
        _tracer_provider = None
        _meter_provider = None
        _logger_provider = None
        handler = _otel_log_handler
        _otel_log_handler = None
    if handler is not None:
        logging.getLogger().removeHandler(handler)
        try:
            handler.close()
        except Exception:
            _logger.exception("Telemetry logging handler shutdown failed")
    for provider in providers:
        if provider is None:
            continue
        try:
            provider.shutdown()  # type: ignore[attr-defined]
        except Exception:
            _logger.exception("Telemetry provider shutdown failed")
    _telemetry_state = "STOPPED"


def _record_instrumentation_error(message: str) -> None:
    global _telemetry_state
    if message not in _instrumentation_errors:
        _instrumentation_errors.append(message)
    if message not in _telemetry_errors:
        _telemetry_errors.append(message)
    if settings.otlp_endpoint:
        _telemetry_state = "FAILED"


def instrument_app(app: object) -> None:
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)  # type: ignore[arg-type]
    except ImportError:
        message = "FastAPI OpenTelemetry instrumentation package is not installed"
        _record_instrumentation_error(message)
        _logger.info(message)
    except Exception as exc:
        _record_instrumentation_error(
            f"FastAPI instrumentation: {type(exc).__name__}: {exc}"
        )
        _logger.exception("Failed to instrument FastAPI")

    instrument_httpx()


def instrument_httpx() -> None:
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().instrument()
    except ImportError:
        message = "HTTPX OpenTelemetry instrumentation package is not installed"
        _record_instrumentation_error(message)
        _logger.info(message)
    except Exception as exc:
        _record_instrumentation_error(
            f"HTTPX instrumentation: {type(exc).__name__}: {exc}"
        )
        _logger.exception("Failed to instrument HTTPX")
