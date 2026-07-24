from __future__ import annotations

import logging

import httpx

_logger = logging.getLogger(__name__)


def instrument_httpx_client(client: httpx.Client | httpx.AsyncClient) -> None:
    """Instrument only an HTTPX client owned by TraceFence."""

    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor.instrument_client(client)
    except ImportError:
        _logger.info(
            "HTTPX OpenTelemetry instrumentation package is not installed"
        )
    except Exception:
        _logger.exception("Failed to instrument owned HTTPX client")
