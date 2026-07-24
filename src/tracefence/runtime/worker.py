from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import threading
from typing import Any

import httpx
from opentelemetry import propagate, trace
from opentelemetry.trace import Link

from tracefence.config import settings
from tracefence.telemetry.instrumentation import instrument_httpx_client
from tracefence.telemetry.setup import (
    configure_telemetry,
    force_flush_telemetry,
    shutdown_telemetry,
)

EXIT_SUCCESS = 0
EXIT_OPERATION_REJECTED = 2
EXIT_LEASE_LOST = 3
EXIT_INTERNAL_OR_TRANSPORT_FAILURE = 4
EXIT_CHECKPOINT_DENIED = 5
EXIT_COMPLETION_REJECTED = 6
EXIT_ACTIVATION_REJECTED = 7


class _LeaseLost(Exception):
    pass


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
        retry_margin = args.heartbeat_retry_max + args.heartbeat_interval
        if args.http_timeout >= settings.lease_ttl_seconds - retry_margin:
            lifecycle_span.add_event("invalid_http_deadline")
            return EXIT_INTERNAL_OR_TRANSPORT_FAILURE
        timeout = httpx.Timeout(
            connect=args.http_timeout,
            read=args.http_timeout,
            write=args.http_timeout,
            pool=args.http_timeout,
        )
        limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
        async with httpx.AsyncClient(
            base_url=args.api_url,
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
        ) as client:
            instrument_httpx_client(client)
            try:
                response = await client.post(
                    f"/v1/nodes/{args.node_id}/activate",
                    json={
                        "operation_key": f"worker-activate-{args.node_id}",
                        "activation_token": startup["activation_token"],
                        "process_id": os.getpid(),
                    },
                )
            except httpx.HTTPError as exc:
                lifecycle_span.record_exception(exc)
                return EXIT_INTERNAL_OR_TRANSPORT_FAILURE
            if response.status_code >= 400:
                lifecycle_span.add_event(
                    "activation_rejected",
                    {"http.status_code": response.status_code},
                )
                return EXIT_ACTIVATION_REJECTED
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
                    except httpx.HTTPError as exc:
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
                    release_task = asyncio.create_task(_read_release_signal())
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

            async def post_while_live(
                path: str,
                *,
                json_payload: dict[str, Any] | None = None,
            ) -> httpx.Response:
                request_task = asyncio.create_task(
                    client.post(path, headers=headers, json=json_payload)
                )
                lease_task = asyncio.create_task(lease_lost.wait())
                done, pending = await asyncio.wait(
                    {request_task, lease_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if lease_task in done and lease_lost.is_set():
                    request_task.cancel()
                    await asyncio.gather(request_task, return_exceptions=True)
                    raise _LeaseLost
                lease_task.cancel()
                await asyncio.gather(lease_task, return_exceptions=True)
                return request_task.result()

            heartbeat_task = asyncio.create_task(
                heartbeat_loop(), name=f"tracefence-heartbeat-{args.node_id}"
            )
            try:
                await wait_for_work_release()
                if lease_lost.is_set():
                    lifecycle_span.set_attribute("tracefence.worker.terminal_state", "LEASE_LOST")
                    lifecycle_span.add_event("worker_lease_lost")
                    return EXIT_LEASE_LOST

                if args.mode == "non_compliant_action":
                    with tracer.start_as_current_span(
                        "tracefence.worker.non_compliant_action",
                        attributes={
                            "tracefence.node.id": args.node_id,
                            "tracefence.action.tool": args.tool,
                        },
                    ):
                        action = await post_while_live(
                            f"/v1/nodes/{args.node_id}/actions",
                            json_payload={
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
                    return (
                        EXIT_SUCCESS
                        if action.status_code == 200
                        else EXIT_OPERATION_REJECTED
                    )

                checkpoint = await post_while_live(
                    f"/v1/nodes/{args.node_id}/checkpoint",
                    json_payload={"stage": "worker_loop"},
                )
                print(checkpoint.text, flush=True)
                if checkpoint.status_code != 200:
                    lifecycle_span.set_attribute(
                        "tracefence.worker.terminal_state",
                        "CHECKPOINT_REJECTED",
                    )
                    return EXIT_CHECKPOINT_DENIED
                checkpoint_payload = checkpoint.json()
                if (
                    not isinstance(checkpoint_payload, dict)
                    or checkpoint_payload.get("allowed") is not True
                ):
                    lifecycle_span.set_attribute(
                        "tracefence.worker.terminal_state",
                        "CHECKPOINT_DENIED",
                    )
                    return EXIT_CHECKPOINT_DENIED
                completion = await post_while_live(
                    f"/v1/nodes/{args.node_id}/complete",
                )
                if completion.status_code != 204:
                    lifecycle_span.add_event(
                        "completion_rejected",
                        {"http.status_code": completion.status_code},
                    )
                    lifecycle_span.set_attribute(
                        "tracefence.worker.terminal_state",
                        "COMPLETION_REJECTED",
                    )
                    return EXIT_COMPLETION_REJECTED
                lifecycle_span.set_attribute(
                    "tracefence.worker.terminal_state",
                    "COMPLETED",
                )
                return EXIT_SUCCESS
            except _LeaseLost:
                lifecycle_span.set_attribute(
                    "tracefence.worker.terminal_state",
                    "LEASE_LOST",
                )
                lifecycle_span.add_event("worker_lease_lost")
                return EXIT_LEASE_LOST
            except Exception as exc:
                lifecycle_span.record_exception(exc)
                terminal = (
                    "TRANSPORT_FAILED" if isinstance(exc, httpx.HTTPError) else "FAILED"
                )
                lifecycle_span.set_attribute("tracefence.worker.terminal_state", terminal)
                return EXIT_INTERNAL_OR_TRANSPORT_FAILURE
            finally:
                lease_lost.set()
                heartbeat_task.cancel()
                await asyncio.gather(heartbeat_task, return_exceptions=True)


async def _read_release_signal() -> str:
    loop = asyncio.get_running_loop()
    result: asyncio.Future[str] = loop.create_future()

    def read() -> None:
        line = sys.stdin.readline()

        def publish() -> None:
            if not result.done():
                result.set_result(line)

        loop.call_soon_threadsafe(publish)

    threading.Thread(
        target=read,
        name="tracefence-worker-release-reader",
        daemon=True,
    ).start()
    return await result


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
    parser.add_argument("--http-timeout", type=_positive_float, default=2.0)
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
