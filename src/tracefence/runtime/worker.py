from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from collections.abc import Awaitable, Callable
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
EXIT_TERMINATED = 143


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


async def _read_startup_payload(reader: asyncio.StreamReader) -> dict[str, Any]:
    line = await reader.readline()
    if not line:
        raise RuntimeError("Worker startup payload was not provided on stdin")
    try:
        payload = json.loads(line.decode(sys.stdin.encoding or "utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Invalid worker startup payload") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("activation_token"), str):
        raise RuntimeError("Invalid worker startup payload")
    return payload


async def run_worker(
    args: argparse.Namespace,
    startup: dict[str, Any],
    *,
    release_reader: asyncio.StreamReader,
) -> int:
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
                    release_task = asyncio.create_task(
                        _read_release_signal(release_reader)
                    )
                    lease_task = asyncio.create_task(lease_lost.wait())
                    try:
                        done, _pending = await asyncio.wait(
                            {release_task, lease_task},
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if lease_task in done and lease_lost.is_set():
                            return
                        release = release_task.result()
                        if release.strip() != "GO":
                            raise RuntimeError("Worker release signal was not received")
                    finally:
                        for task in (release_task, lease_task):
                            if not task.done():
                                task.cancel()
                        await asyncio.gather(
                            release_task,
                            lease_task,
                            return_exceptions=True,
                        )
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
                if args.mode == "non_compliant_action":
                    checkpoint = await post_while_live(
                        f"/v1/nodes/{args.node_id}/checkpoint",
                        json_payload={"stage": "before_protected_action"},
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


async def _read_release_signal(reader: asyncio.StreamReader) -> str:
    line = await reader.readline()
    return line.decode(sys.stdin.encoding or "utf-8")


async def _await_worker_or_termination(
    worker_task_input: Awaitable[int],
    termination: asyncio.Event,
) -> int:
    """Return the worker result or cancel it after a loop-delivered SIGTERM."""

    worker_task = asyncio.ensure_future(worker_task_input)
    termination_task = asyncio.create_task(termination.wait())
    try:
        done, _pending = await asyncio.wait(
            {worker_task, termination_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if termination_task in done:
            worker_task.cancel()
            await asyncio.gather(worker_task, return_exceptions=True)
            return EXIT_TERMINATED
        return worker_task.result()
    finally:
        for task in (worker_task, termination_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(
            worker_task,
            termination_task,
            return_exceptions=True,
        )


def _install_termination_event_handler(
    loop: asyncio.AbstractEventLoop,
    termination: asyncio.Event,
) -> Callable[[], None]:
    """Wake the owning asyncio loop when SIGTERM is received."""

    if not hasattr(signal, "SIGTERM"):
        return lambda: None

    termination_signal = signal.SIGTERM
    try:
        loop.add_signal_handler(termination_signal, termination.set)
    except (NotImplementedError, RuntimeError):
        previous_handler = signal.getsignal(termination_signal)

        def request_termination(_signum: int, _frame: object) -> None:
            if not loop.is_closed():
                loop.call_soon_threadsafe(termination.set)

        signal.signal(termination_signal, request_termination)

        def restore_signal_handler() -> None:
            signal.signal(termination_signal, previous_handler)

        return restore_signal_handler

    def remove_signal_handler() -> None:
        loop.remove_signal_handler(termination_signal)

    return remove_signal_handler


async def _run_from_stdin(args: argparse.Namespace) -> int:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(
        lambda: protocol,
        sys.stdin.buffer,
    )
    try:
        startup = await _read_startup_payload(reader)
        return await run_worker(args, startup, release_reader=reader)
    finally:
        transport.close()


async def _run_with_termination(args: argparse.Namespace) -> int:
    loop = asyncio.get_running_loop()
    termination = asyncio.Event()
    remove_handler = _install_termination_event_handler(loop, termination)
    try:
        return await _await_worker_or_termination(_run_from_stdin(args), termination)
    finally:
        remove_handler()


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


if __name__ == "__main__":
    arguments = parse_args()
    try:
        exit_code = asyncio.run(_run_with_termination(arguments))
    finally:
        force_flush_telemetry()
        shutdown_telemetry()
    raise SystemExit(exit_code)
