from __future__ import annotations

from tracefence.domain.schemas import NodeActivate, RunCreate
from tracefence.services.run_service import RunService
from tracefence.services.state_service import StateService

FULL_ROOT_CAPABILITIES = [
    "control:descendants",
    "tool:read_metrics",
    "tool:restart_postgres",
    "tool:reset_redis_pool",
    "tool:propose_correction",
]


async def create_seeded_run(session_factory, name: str = "test-run"):
    runs = RunService(session_factory)
    states = StateService(session_factory)
    run = await runs.create_run(
        RunCreate(name=name, root_capabilities=FULL_ROOT_CAPABILITIES)
    )
    await states.seed_scenario(run.run_id)
    return run


async def activate(spawn_service, created, process_id: int = 100):
    return await spawn_service.activate(
        created.child_node_id,
        NodeActivate(activation_token=created.activation_token, process_id=process_id),
    )
