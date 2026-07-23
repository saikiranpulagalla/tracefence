from __future__ import annotations

import atexit
import logging
from datetime import UTC, datetime
from threading import Lock

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from tracefence.config import settings
from tracefence.logging_config import JsonFormatter

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
_successful_flush_sequence = 0
_last_successful_flush_at: datetime | None = None


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
            setattr(handler, "_tracefence_otel", True)
            root.addHandler(handler)
            _otel_log_handler = handler
        return True
    except Exception:
        _logger.exception("Failed to configure OTLP log exporter")
        return False


def force_flush_telemetry(timeout_millis: int | None = None) -> bool:
    """Flush spans, metrics and logs before evidence queries.

    A proof must not race the SDK's batch timers. Providers that are not owned by
    TraceFence are deliberately ignored rather than guessed at.
    """

    if settings.otlp_endpoint and _telemetry_state != "READY":
        return False
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
    if settings.otlp_endpoint and not results:
        return False
    success = all(results) if results else True
    if success and settings.otlp_endpoint and _telemetry_state == "READY":
        global _successful_flush_sequence, _last_successful_flush_at
        with _provider_lock:
            _successful_flush_sequence += 1
            _last_successful_flush_at = datetime.now(UTC)
    return success


def telemetry_export_watermark() -> str | None:
    """Return the latest successful owned-export flush identity for cache binding."""

    with _provider_lock:
        if _last_successful_flush_at is None or _configured_service_name is None:
            return None
        return (
            f"{_configured_service_name}:{_successful_flush_sequence}:"
            f"{_last_successful_flush_at.isoformat()}"
        )


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
