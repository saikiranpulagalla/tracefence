from typing import Annotated

from fastapi import APIRouter, Depends, Query

from tracefence.api.dependencies import (
    call_blocking_service,
    graph_service,
    require_operator,
    run_service,
    state_service,
)
from tracefence.domain.schemas import GraphResponse, RunCreate, RunCreated

router = APIRouter(prefix="/v1/runs", tags=["runs"])


@router.get("", dependencies=[Depends(require_operator)])
async def list_runs(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    return await call_blocking_service(
        lambda: run_service.list_runs(limit=limit, offset=offset)
    )


@router.post("", response_model=RunCreated, status_code=201, dependencies=[Depends(require_operator)])
async def create_run(request: RunCreate) -> RunCreated:
    return await call_blocking_service(lambda: run_service.create_run(request))


@router.get("/{run_id}/graph", response_model=GraphResponse, dependencies=[Depends(require_operator)])
async def get_graph(run_id: str) -> GraphResponse:
    return await call_blocking_service(lambda: graph_service.get_graph(run_id))


@router.get("/{run_id}/actions", dependencies=[Depends(require_operator)])
async def list_actions(
    run_id: str,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    return await call_blocking_service(
        lambda: state_service.list_actions(
            run_id,
            limit=limit,
            offset=offset,
        )
    )


@router.get("/{run_id}/violations", dependencies=[Depends(require_operator)])
async def list_violations(
    run_id: str,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    return await call_blocking_service(
        lambda: state_service.list_violations(
            run_id,
            limit=limit,
            offset=offset,
        )
    )
