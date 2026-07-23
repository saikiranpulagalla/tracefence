from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tracefence.domain.errors import TraceFenceError


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(TraceFenceError)
    async def tracefence_error_handler(_request: Request, exc: TraceFenceError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )
