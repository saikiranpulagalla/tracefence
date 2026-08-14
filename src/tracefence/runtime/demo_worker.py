from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

import httpx

EXIT_SUCCESS = 0
EXIT_OPERATION_REJECTED = 2
EXIT_INPUT_OR_TRANSPORT_FAILURE = 4
EXIT_CHECKPOINT_REJECTED = 5


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


async def _read_startup(reader: asyncio.StreamReader) -> dict[str, Any]:
    line = await reader.readline()
    if not line:
        raise RuntimeError("Demo worker startup payload was not provided")
    try:
        payload = json.loads(line.decode(sys.stdin.encoding or "utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Invalid demo worker startup payload") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("node_token"), str):
        raise RuntimeError("Invalid demo worker startup payload")
    return payload


async def run_demo_worker(
    args: argparse.Namespace,
    startup: dict[str, Any],
    *,
    release_reader: asyncio.StreamReader,
) -> int:
    """Run an intentionally stubborn worker used only by the local demo.

    The controller renews its lease before supersession. After the checkpoint,
    this process deliberately does not cooperate with later control state and
    attempts the protected action when released. The Action Gateway remains the
    only authority that decides whether the side effect commits.
    """

    timeout = httpx.Timeout(
        connect=args.http_timeout,
        read=args.http_timeout,
        write=args.http_timeout,
        pool=args.http_timeout,
    )
    limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)
    headers = {"X-Node-Token": startup["node_token"]}
    async with httpx.AsyncClient(
        base_url=args.api_url,
        timeout=timeout,
        limits=limits,
        follow_redirects=False,
        headers=headers,
    ) as client:
        try:
            checkpoint = await client.post(
                f"/v1/nodes/{args.node_id}/checkpoint",
                json={"stage": "before_protected_action"},
            )
        except httpx.HTTPError:
            return EXIT_INPUT_OR_TRANSPORT_FAILURE
        if checkpoint.status_code != 200:
            return EXIT_CHECKPOINT_REJECTED
        payload = checkpoint.json()
        if not isinstance(payload, dict) or payload.get("allowed") is not True:
            return EXIT_CHECKPOINT_REJECTED

        release = await release_reader.readline()
        if release.decode(sys.stdin.encoding or "utf-8").strip() != "GO":
            return EXIT_INPUT_OR_TRANSPORT_FAILURE
        try:
            action = await client.post(
                f"/v1/nodes/{args.node_id}/actions",
                json={
                    "idempotency_key": args.idempotency_key,
                    "tool_name": args.tool,
                    "arguments": {},
                },
            )
        except httpx.HTTPError:
            return EXIT_INPUT_OR_TRANSPORT_FAILURE
        print(action.text, flush=True)
        return EXIT_SUCCESS if action.status_code == 200 else EXIT_OPERATION_REJECTED


async def _run_from_stdin(args: argparse.Namespace) -> int:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    try:
        startup = await _read_startup(reader)
        return await run_demo_worker(args, startup, release_reader=reader)
    finally:
        transport.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the fixed adversarial worker for the local Runtime Inspector",
    )
    parser.add_argument("--api-url", default="http://127.0.0.1:9000")
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--mode", choices=["non_compliant_action"], required=True)
    parser.add_argument("--http-timeout", type=_positive_float, default=2.0)
    parser.add_argument("--tool", choices=["restart_postgres"], required=True)
    parser.add_argument("--idempotency-key", required=True)
    return parser.parse_args()


def main() -> None:
    try:
        exit_code = asyncio.run(_run_from_stdin(parse_args()))
    except Exception:
        exit_code = EXIT_INPUT_OR_TRANSPORT_FAILURE
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
