from fastapi import APIRouter, Depends, Response

from tracefence.api.dependencies import (
    call_blocking_service,
    lease_service,
    require_operator,
    state_service,
)

router = APIRouter(prefix="/v1/runs", tags=["scenario"])


@router.post(
    "/{run_id}/scenario/seed",
    status_code=204,
    dependencies=[Depends(require_operator)],
)
async def seed(run_id: str) -> Response:
    await call_blocking_service(lambda: state_service.seed_scenario(run_id))
    return Response(status_code=204)


@router.get("/{run_id}/services", dependencies=[Depends(require_operator)])
async def services(run_id: str) -> list[dict]:
    return await call_blocking_service(lambda: state_service.list_states(run_id))


@router.post("/{run_id}/expire-leases", dependencies=[Depends(require_operator)])
async def expire_leases(run_id: str) -> dict[str, int]:
    return {
        "expired": await call_blocking_service(
            lambda: lease_service.expire_stale_nodes(run_id)
        )
    }
