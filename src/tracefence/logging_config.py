from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from opentelemetry import trace


class JsonFormatter(logging.Formatter):
    """Render console and OTLP log bodies as valid single-line JSON."""

    _standard = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        span_context = trace.get_current_span().get_span_context()
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if span_context.is_valid:
            payload["trace_id"] = f"{span_context.trace_id:032x}"
            payload["span_id"] = f"{span_context.span_id:016x}"
        for key, value in record.__dict__.items():
            if key in self._standard or key.startswith("_"):
                continue
            if key in {
                "args",
                "exc_info",
                "exc_text",
                "stack_info",
                "pathname",
                "filename",
                "module",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "taskName",
            }:
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), default=str)


def configure_logging(level: int = logging.INFO) -> None:
    logger = logging.getLogger("tracefence")
    logger.setLevel(level)
    logger.propagate = False
    if any(
        getattr(handler, "_tracefence_console", False)
        for handler in logger.handlers
    ):
        return
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter())
    handler._tracefence_console = True
    logger.addHandler(handler)
