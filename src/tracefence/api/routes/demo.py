from __future__ import annotations

from fastapi import APIRouter, Depends, Response

from tracefence.api.demo_security import (
    require_demo_access,
    require_demo_bootstrap,
    set_demo_cookie,
)
from tracefence.api.dependencies import call_blocking_service, demo_controller

router = APIRouter(prefix="/v1/demo", tags=["demo"])


@router.get("/bootstrap", dependencies=[Depends(require_demo_bootstrap)])
async def bootstrap(response: Response) -> dict[str, object]:
    set_demo_cookie(response)
    return {
        "enabled": True,
        "scenarios": [
            "stale-supersession",
            "cancellation",
            "lease-expiry",
            "idempotent-retry",
            "recovery-manifest-mismatch",
            "sibling-isolation",
            "concurrent-stale-valid",
        ],
        "external_telemetry_required": False,
    }


@router.post(
    "/scenarios/{scenario}/start",
    dependencies=[Depends(require_demo_access)],
)
async def start_scenario(scenario: str) -> dict[str, object]:
    return await call_blocking_service(lambda: demo_controller.start(scenario))

@router.post(
    "/checks/{scenario}/run",
    dependencies=[Depends(require_demo_access)],
)
async def run_scenario_check(scenario: str) -> dict[str, object]:
    return await call_blocking_service(lambda: demo_controller.run_check(scenario))


@router.post(
    "/checks/lease-expiry/{check_id}/finish",
    dependencies=[Depends(require_demo_access)],
)
async def finish_lease_expiry(check_id: str) -> dict[str, object]:
    return await call_blocking_service(
        lambda: demo_controller.finish_lease_expiry(check_id)
    )


@router.get(
    "/checks",
    dependencies=[Depends(require_demo_access)],
)
async def list_scenario_checks() -> list[dict[str, object]]:
    return await call_blocking_service(demo_controller.list_checks)

@router.get(
    "/sessions",
    dependencies=[Depends(require_demo_access)],
)
async def list_sessions() -> list[dict[str, object]]:
    return await call_blocking_service(demo_controller.list_sessions)


@router.get(
    "/sessions/{session_id}",
    dependencies=[Depends(require_demo_access)],
)
async def get_session(session_id: str) -> dict[str, object]:
    return await call_blocking_service(lambda: demo_controller.get(session_id))


@router.post(
    "/sessions/{session_id}/supersede",
    dependencies=[Depends(require_demo_access)],
)
async def supersede(session_id: str) -> dict[str, object]:
    return await call_blocking_service(
        lambda: demo_controller.supersede(session_id)
    )


@router.post(
    "/sessions/{session_id}/release-stale-worker",
    dependencies=[Depends(require_demo_access)],
)
async def release_stale_worker(session_id: str) -> dict[str, object]:
    return await call_blocking_service(
        lambda: demo_controller.release_stale_worker(session_id)
    )


@router.post(
    "/sessions/{session_id}/run-replacement",
    dependencies=[Depends(require_demo_access)],
)
async def run_replacement(session_id: str) -> dict[str, object]:
    return await call_blocking_service(
        lambda: demo_controller.run_replacement(session_id)
    )


@router.post(
    "/sessions/{session_id}/proof",
    dependencies=[Depends(require_demo_access)],
)
async def build_proof(session_id: str) -> dict[str, object]:
    return await call_blocking_service(
        lambda: demo_controller.build_proof(session_id)
    )


@router.post(
    "/sessions/{session_id}/reset",
    dependencies=[Depends(require_demo_access)],
)
async def reset_session(session_id: str) -> dict[str, object]:
    return await call_blocking_service(
        lambda: demo_controller.reset(session_id)
    )
