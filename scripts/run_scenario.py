from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from tracefence.evidence import validate_evidence_generation, write_evidence_bundle

REPO_DIR = Path(__file__).resolve().parents[1]


async def post(client: httpx.AsyncClient, path: str, **kwargs: Any) -> Any:
    response = await client.post(path, **kwargs)
    response.raise_for_status()
    return response.json() if response.content else None


async def get(client: httpx.AsyncClient, path: str, operator_key: str) -> Any:
    response = await client.get(path, headers={"X-Operator-Key": operator_key})
    response.raise_for_status()
    return response.json()


async def run(
    api_url: str,
    operator_key: str,
    output_dir: Path,
    evidence_signing_key: str | None = None,
) -> dict:
    if not operator_key:
        raise RuntimeError("TRACEFENCE_OPERATOR_KEY is required")
    validate_evidence_generation(
        REPO_DIR,
        signing_key=evidence_signing_key,
    )

    await asyncio.to_thread(output_dir.mkdir, parents=True, exist_ok=True)
    operator_headers = {"X-Operator-Key": operator_key}
    worker: asyncio.subprocess.Process | None = None

    async with httpx.AsyncClient(base_url=api_url, timeout=20.0) as client:
        created = await post(
            client,
            "/v1/runs",
            headers=operator_headers,
            json={
                "name": "checkout-incident",
                "root_role": "coordinator",
                "root_instruction": {"goal": "resolve checkout failures"},
                "root_capabilities": [
                    "control:descendants",
                    "tool:read_metrics",
                    "tool:restart_postgres",
                    "tool:reset_redis_pool",
                    "tool:propose_correction",
                ],
            },
        )
        run_id = created["run_id"]
        key_prefix = f"scenario-{run_id}"
        await post(
            client,
            f"/v1/runs/{run_id}/scenario/seed",
            headers=operator_headers,
        )

        root_id = created["root_node_id"]
        root_token = created["root_token"]
        root_headers = {"X-Node-Token": root_token}

        try:
            database_spawn = await post(
                client,
                f"/v1/nodes/{root_id}/spawns",
                headers=root_headers,
                json={
                    "role": "database_investigator",
                    "instruction": {"task": "investigate PostgreSQL latency"},
                    "capabilities": ["tool:restart_postgres", "tool:read_metrics"],
                    "behavior": "cooperative",
                },
            )
            database_activation = await post(
                client,
                f"/v1/nodes/{database_spawn['child_node_id']}/activate",
                json={
                    "activation_token": database_spawn["activation_token"],
                    "process_id": os.getpid(),
                },
            )
            database_headers = {"X-Node-Token": database_activation["node_token"]}

            child_spawn = await post(
                client,
                f"/v1/nodes/{database_activation['node_id']}/spawns",
                headers=database_headers,
                json={
                    "role": "non_compliant_database_child",
                    "instruction": {"task": "restart PostgreSQL"},
                    "capabilities": ["tool:restart_postgres"],
                    "behavior": "non_compliant",
                },
            )
            worker = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "tracefence.runtime.worker",
                "--api-url",
                api_url,
                "--node-id",
                child_spawn["child_node_id"],
                "--mode",
                "non_compliant_action",
                "--wait-for-release",
                "--tool",
                "restart_postgres",
                "--idempotency-key",
                f"{key_prefix}-stale-restart-postgres",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if worker.stdin is None:
                raise RuntimeError("Worker subprocess stdin pipe was not created")
            worker.stdin.write(
                (
                    json.dumps(
                        {
                            "activation_token": child_spawn["activation_token"],
                            "trace_context": child_spawn.get("trace_context", {}),
                        }
                    )
                    + "\n"
                ).encode()
            )
            await worker.stdin.drain()

            # Explicitly wait for activation. No correctness decision depends on a
            # guessed sleep duration.
            for _ in range(100):
                graph_probe = await get(client, f"/v1/runs/{run_id}/graph", operator_key)
                child_probe = next(
                    (
                        node
                        for node in graph_probe["nodes"]
                        if node["id"] == child_spawn["child_node_id"]
                    ),
                    None,
                )
                if child_probe and child_probe["declared_status"] == "ACTIVE":
                    break
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError("Independent non-compliant child did not activate")

            sibling_spawn = await post(
                client,
                f"/v1/nodes/{root_id}/spawns",
                headers=root_headers,
                json={
                    "role": "metrics_investigator",
                    "instruction": {"task": "correlate Redis metrics"},
                    "capabilities": ["tool:read_metrics"],
                    "behavior": "cooperative",
                },
            )
            sibling = await post(
                client,
                f"/v1/nodes/{sibling_spawn['child_node_id']}/activate",
                json={"activation_token": sibling_spawn["activation_token"]},
            )

            command = await post(
                client,
                "/v1/commands",
                headers=operator_headers,
                json={
                    "idempotency_key": f"{key_prefix}-correct-database-branch",
                    "command_type": "CORRECT_SUBTREE",
                    "target_node_id": database_activation["node_id"],
                    "reason_code": "WRONG_ROOT_CAUSE",
                    "reason_text": "Redis pool exhaustion is causal; PostgreSQL is healthy",
                    "replacement_instruction": {"task": "reset Redis connection pool"},
                    "replacement_expected_tool": "reset_redis_pool",
                    "recovery_stability_seconds": 2,
                },
            )
            await post(
                client,
                f"/v1/nodes/{database_activation['node_id']}/checkpoint",
                headers=database_headers,
                json={"stage": "after_redis_evidence"},
            )

            replacement_spawn = await post(
                client,
                f"/v1/nodes/{root_id}/replacements/{command['command_id']}",
                headers=root_headers,
                json={
                    "role": "redis_recovery",
                    "instruction": command["replacement_instruction"],
                    "capabilities": ["tool:reset_redis_pool"],
                    "behavior": "cooperative",
                },
            )
            replacement = await post(
                client,
                f"/v1/nodes/{replacement_spawn['child_node_id']}/activate",
                json={"activation_token": replacement_spawn["activation_token"]},
            )
            recovery = await post(
                client,
                f"/v1/nodes/{replacement['node_id']}/actions",
                headers={"X-Node-Token": replacement["node_token"]},
                json={
                    "idempotency_key": f"{key_prefix}-reset-redis-pool",
                    "tool_name": "reset_redis_pool",
                    "arguments": {},
                },
            )
            await post(
                client,
                f"/v1/nodes/{replacement['node_id']}/complete",
                headers={"X-Node-Token": replacement["node_token"]},
            )
            sibling_check = await post(
                client,
                f"/v1/nodes/{sibling['node_id']}/actions",
                headers={"X-Node-Token": sibling["node_token"]},
                json={
                    "idempotency_key": f"{key_prefix}-sibling-read-metrics",
                    "tool_name": "read_metrics",
                    "arguments": {},
                },
            )
            await post(
                client,
                f"/v1/nodes/{sibling['node_id']}/complete",
                headers={"X-Node-Token": sibling["node_token"]},
            )

            # Release the deliberately non-compliant worker only after the control
            # command has committed. This guarantees that its request is genuinely stale.
            worker.stdin.write(b"GO\n")
            await worker.stdin.drain()
            worker.stdin.close()
            await worker.stdin.wait_closed()
            stdout, stderr = await asyncio.wait_for(worker.communicate(), timeout=15)
            if worker.returncode != 0:
                raise RuntimeError(f"Non-compliant worker failed: {stderr.decode()}")

            await post(
                client,
                f"/v1/nodes/{root_id}/complete",
                headers=root_headers,
            )
            # The recovery contract requires the authoritative postcondition to
            # remain unchanged for two seconds before it can be VERIFIED.
            await asyncio.sleep(2.1)
            proof = await get(
                client, f"/v1/commands/{command['command_id']}/proof", operator_key
            )
            graph = await get(client, f"/v1/runs/{run_id}/graph", operator_key)
            actions = await get(client, f"/v1/runs/{run_id}/actions", operator_key)
            services = await get(client, f"/v1/runs/{run_id}/services", operator_key)
            violations = await get(client, f"/v1/runs/{run_id}/violations", operator_key)
        finally:
            if worker is not None and worker.returncode is None:
                worker.terminate()
                try:
                    await asyncio.wait_for(worker.wait(), timeout=5)
                except TimeoutError:
                    worker.kill()
                    await worker.wait()

    bundle = {
        "run": {"run_id": run_id, "root_node_id": root_id},
        "command": command,
        "recovery": recovery,
        "sibling_check": sibling_check,
        "worker_output": stdout.decode().strip(),
        "proof": proof,
        "graph": graph,
        "actions": actions,
        "services": services,
        "violations": violations,
    }
    write_evidence_bundle(
        output_dir,
        bundle,
        repo_dir=REPO_DIR,
        signing_key=evidence_signing_key,
        live_api_url=api_url,
    )
    return bundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default="http://127.0.0.1:9000")
    parser.add_argument("--output-dir", type=Path, default=Path("evidence"))
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    result = asyncio.run(
        run(
            args.api_url,
            os.getenv("TRACEFENCE_OPERATOR_KEY", ""),
            args.output_dir,
            os.getenv("TRACEFENCE_EVIDENCE_SIGNING_KEY", "") or None,
        )
    )
    print(json.dumps({"run_id": result["run"]["run_id"], "proof": result["proof"]}, indent=2))
