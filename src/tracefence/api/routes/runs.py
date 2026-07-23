from fastapi import APIRouter, Depends

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
async def list_runs() -> list[dict]:
    return await call_blocking_service(run_service.list_runs)


@router.post("", response_model=RunCreated, status_code=201, dependencies=[Depends(require_operator)])
async def create_run(request: RunCreate) -> RunCreated:
    return await call_blocking_service(lambda: run_service.create_run(request))


@router.get("/{run_id}/graph", response_model=GraphResponse, dependencies=[Depends(require_operator)])
async def get_graph(run_id: str) -> GraphResponse:
    return await call_blocking_service(lambda: graph_service.get_graph(run_id))


@router.get("/{run_id}/actions", dependencies=[Depends(require_operator)])
async def list_actions(run_id: str) -> list[dict]:
    return await call_blocking_service(lambda: state_service.list_actions(run_id))


@router.get("/{run_id}/violations", dependencies=[Depends(require_operator)])
async def list_violations(run_id: str) -> list[dict]:
    return await call_blocking_service(lambda: state_service.list_violations(run_id))
