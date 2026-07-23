from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from typing import Any

import httpx
from opentelemetry import propagate, trace
from opentelemetry.trace import Link

from tracefence.telemetry.setup import (
    configure_telemetry,
    force_flush_telemetry,
    instrument_httpx,
    shutdown_telemetry,
)


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _nonnegative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _read_startup_payload() -> dict[str, Any]:
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("Worker startup payload was not provided on stdin")
    payload = json.loads(line)
    if not isinstance(payload, dict) or not isinstance(payload.get("activation_token"), str):
        raise RuntimeError("Invalid worker startup payload")
    return payload


async def run_worker(args: argparse.Namespace, startup: dict[str, Any]) -> int:
    configure_telemetry("tracefence-worker")
    instrument_httpx()

    carrier = startup.get("trace_context")
    links: list[Link] = []
    if isinstance(carrier, dict):
        extracted = propagate.extract({str(k): str(v) for k, v in carrier.items()})
        parent_context = trace.get_current_span(extracted).get_span_context()
        if parent_context.is_valid:
            links.append(Link(parent_context))

    tracer = trace.get_tracer("tracefence.worker")
    with tracer.start_as_current_span(
        "tracefence.worker.lifecycle",
        links=links,
        attributes={
            "tracefence.node.id": args.node_id,
            "tracefence.worker.mode": args.mode,
        },
    ) as lifecycle_span:
        async with httpx.AsyncClient(base_url=args.api_url, timeout=10.0) as client:
            response = await client.post(
                f"/v1/nodes/{args.node_id}/activate",
                json={
                    "activation_token": startup["activation_token"],
                    "process_id": os.getpid(),
                },
            )
            response.raise_for_status()
            activation = response.json()
            node_token = activation["node_token"]
            lifecycle_span.set_attribute("tracefence.run.id", activation["run_id"])
            lifecycle_span.set_attribute("tracefence.node.role", activation["role"])
            headers = {"X-Node-Token": node_token}
            lease_lost = asyncio.Event()

            async def heartbeat_loop() -> None:
                failures = 0
                while not lease_lost.is_set():
                    await asyncio.sleep(args.heartbeat_interval)
                    try:
                        heartbeat = await client.post(
                            f"/v1/nodes/{args.node_id}/heartbeat",
                            headers=headers,
                            json={
                                "worker_state": "RUNNING",
                                "current_operation": args.mode,
                            },
                        )
                    except Exception as exc:
                        failures += 1
                        lifecycle_span.add_event(
                            "heartbeat_transport_failure",
                            {"failure_count": failures, "error.type": type(exc).__name__},
                        )
                        if failures >= args.max_heartbeat_failures:
                            lease_lost.set()
                            return
                        await asyncio.sleep(
                            min(args.heartbeat_retry_max, args.heartbeat_retry_base * (2 ** (failures - 1)))
                        )
                        continue
                    if heartbeat.status_code >= 400:
                        lifecycle_span.add_event(
                            "heartbeat_rejected",
                            {"http.status_code": heartbeat.status_code},
                        )
                        lease_lost.set()
                        return
                    failures = 0

            async def wait_for_work_release() -> None:
                if args.wait_for_release:
                    release_task = asyncio.create_task(asyncio.to_thread(sys.stdin.readline))
                    lease_task = asyncio.create_task(lease_lost.wait())
                    done, pending = await asyncio.wait(
                        {release_task, lease_task},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    if lease_task in done and lease_lost.is_set():
                        return
                    release = release_task.result()
                    if release.strip() != "GO":
                        raise RuntimeError("Worker release signal was not received")
                else:
                    try:
                        await asyncio.wait_for(lease_lost.wait(), timeout=args.delay)
                    except TimeoutError:
                        pass

            heartbeat_task = asyncio.create_task(
                heartbeat_loop(), name=f"tracefence-heartbeat-{args.node_id}"
            )
            try:
                await wait_for_work_release()
                if lease_lost.is_set():
                    lifecycle_span.set_attribute("tracefence.worker.terminal_state", "LEASE_LOST")
                    return 3

                if args.mode == "non_compliant_action":
                    with tracer.start_as_current_span(
                        "tracefence.worker.non_compliant_action",
                        attributes={
                            "tracefence.node.id": args.node_id,
                            "tracefence.action.tool": args.tool,
                        },
                    ):
                        action = await client.post(
                            f"/v1/nodes/{args.node_id}/actions",
                            headers=headers,
                            json={
                                "idempotency_key": args.idempotency_key,
                                "tool_name": args.tool,
                                "arguments": {},
                            },
                        )
                    print(action.text, flush=True)
                    lifecycle_span.set_attribute(
                        "tracefence.worker.terminal_state",
                        "ACTION_RETURNED" if action.status_code == 200 else "ACTION_FAILED",
                    )
                    return 0 if action.status_code == 200 else 2

                checkpoint = await client.post(
                    f"/v1/nodes/{args.node_id}/checkpoint",
                    headers=headers,
                    json={"stage": "worker_loop"},
                )
                print(checkpoint.text, flush=True)
                lifecycle_span.set_attribute(
                    "tracefence.worker.terminal_state",
                    "CHECKPOINT_RETURNED" if checkpoint.status_code == 200 else "CHECKPOINT_FAILED",
                )
                return 0 if checkpoint.status_code == 200 else 2
            except Exception as exc:
                lifecycle_span.record_exception(exc)
                terminal = (
                    "TRANSPORT_FAILED" if isinstance(exc, httpx.HTTPError) else "FAILED"
                )
                lifecycle_span.set_attribute("tracefence.worker.terminal_state", terminal)
                return 4
            finally:
                lease_lost.set()
                heartbeat_task.cancel()
                await asyncio.gather(heartbeat_task, return_exceptions=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default="http://127.0.0.1:9000")
    parser.add_argument("--node-id", required=True)
    parser.add_argument(
        "--mode", choices=["cooperative", "non_compliant_action"], required=True
    )
    parser.add_argument("--delay", type=_nonnegative_float, default=2.0)
    parser.add_argument("--wait-for-release", action="store_true")
    parser.add_argument("--heartbeat-interval", type=_positive_float, default=1.0)
    parser.add_argument("--max-heartbeat-failures", type=_positive_int, default=3)
    parser.add_argument("--heartbeat-retry-base", type=_positive_float, default=0.25)
    parser.add_argument("--heartbeat-retry-max", type=_positive_float, default=2.0)
    parser.add_argument("--tool", default="restart_postgres")
    parser.add_argument("--idempotency-key", default="worker-action-001")
    return parser.parse_args()


def _install_signal_handlers() -> None:
    def terminate(_signum: int, _frame: object) -> None:
        raise SystemExit(143)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, terminate)


if __name__ == "__main__":
    _install_signal_handlers()
    arguments = parse_args()
    startup_payload = _read_startup_payload()
    try:
        exit_code = asyncio.run(run_worker(arguments, startup_payload))
    finally:
        force_flush_telemetry()
        shutdown_telemetry()
    raise SystemExit(exit_code)
