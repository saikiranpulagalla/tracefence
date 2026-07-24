from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from tests.helpers import create_seeded_run
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import NodeActivate, SpawnCreate
from tracefence.services.spawn_service import SpawnService


async def test_activation_token_is_consumed_exactly_once_under_race(session_factory):
    spawns = SpawnService(session_factory)
    run = await create_seeded_run(session_factory, "activation-race")
    spawned = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="worker", capabilities=[]),
    )
    barrier = Barrier(2)

    def activate_once(process_id: int):
        barrier.wait()
        try:
            return asyncio.run(
                spawns.activate(
                    spawned.child_node_id,
                    NodeActivate(
                        activation_token=spawned.activation_token,
                        process_id=process_id,
                    ),
                )
            )
        except ConflictError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            pool.submit(activate_once, 1001),
            pool.submit(activate_once, 1002),
        ]
        values = [future.result(timeout=10) for future in results]

    successes = [value for value in values if not isinstance(value, ConflictError)]
    failures = [value for value in values if isinstance(value, ConflictError)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0].code in {"ACTIVATION_TOKEN_USED", "NODE_NOT_PENDING"}
