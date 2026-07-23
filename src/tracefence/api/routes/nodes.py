from fastapi import APIRouter, Header, Response

from tracefence.api.dependencies import call_blocking_service, spawn_service
from tracefence.domain.schemas import (
    CheckpointRequest,
    CheckpointResponse,
    HeartbeatRequest,
    NodeActivate,
    NodeActivated,
    SpawnCreate,
    SpawnCreated,
)

router = APIRouter(prefix="/v1/nodes", tags=["nodes"])


@router.post("/{parent_node_id}/spawns", response_model=SpawnCreated, status_code=201)
async def create_spawn(
    parent_node_id: str,
    request: SpawnCreate,
    x_node_token: str = Header(alias="X-Node-Token"),
) -> SpawnCreated:
    return await call_blocking_service(
        lambda: spawn_service.create_spawn(parent_node_id, x_node_token, request)
    )


@router.post(
    "/{parent_node_id}/replacements/{correction_command_id}",
    response_model=SpawnCreated,
    status_code=201,
)
async def create_replacement(
    parent_node_id: str,
    correction_command_id: str,
    request: SpawnCreate,
    x_node_token: str = Header(alias="X-Node-Token"),
) -> SpawnCreated:
    return await call_blocking_service(
        lambda: spawn_service.create_replacement(
            parent_node_id, x_node_token, correction_command_id, request
        )
    )


@router.post("/{node_id}/activate", response_model=NodeActivated)
async def activate_node(node_id: str, request: NodeActivate) -> NodeActivated:
    return await call_blocking_service(lambda: spawn_service.activate(node_id, request))


@router.post("/{node_id}/heartbeat", status_code=204)
async def heartbeat(
    node_id: str,
    _request: HeartbeatRequest,
    x_node_token: str = Header(alias="X-Node-Token"),
) -> Response:
    await call_blocking_service(lambda: spawn_service.heartbeat(node_id, x_node_token))
    return Response(status_code=204)


@router.post("/{node_id}/checkpoint", response_model=CheckpointResponse)
async def checkpoint(
    node_id: str,
    request: CheckpointRequest,
    x_node_token: str = Header(alias="X-Node-Token"),
) -> CheckpointResponse:
    return await call_blocking_service(
        lambda: spawn_service.checkpoint(node_id, x_node_token, request.stage)
    )


@router.post("/{node_id}/complete", status_code=204)
async def complete(
    node_id: str,
    x_node_token: str = Header(alias="X-Node-Token"),
) -> Response:
    await call_blocking_service(lambda: spawn_service.complete(node_id, x_node_token))
    return Response(status_code=204)
