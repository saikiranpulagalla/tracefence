from fastapi import APIRouter, Header

from tracefence.api.dependencies import action_gateway, call_blocking_service
from tracefence.domain.schemas import ActionExecute, ActionResult

router = APIRouter(prefix="/v1/nodes", tags=["actions"])


@router.post("/{node_id}/actions", response_model=ActionResult)
async def execute_action(
    node_id: str,
    request: ActionExecute,
    x_node_token: str = Header(alias="X-Node-Token"),
) -> ActionResult:
    return await call_blocking_service(
        lambda: action_gateway.execute(node_id, x_node_token, request)
    )
