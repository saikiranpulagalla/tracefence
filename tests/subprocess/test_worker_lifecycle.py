from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


class _WorkerApi:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.heartbeat_status = 204
        self.checkpoint_payload = {"allowed": True, "effective_status": "ACTIVE"}
        self.completion_status = 204
        self.activation_token = "activation-secret-value-123456"
        self.node_token = "node-secret-value-123456789"


@pytest.fixture
def worker_api():
    state = _WorkerApi()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            content_length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(content_length)
            state.paths.append(self.path)
            if self.path.endswith("/activate"):
                assert json.loads(body)["activation_token"] == state.activation_token
                self._json(
                    200,
                    {
                        "node_id": "worker-node",
                        "run_id": "worker-run",
                        "role": "worker",
                        "node_token": state.node_token,
                        "lease_expires_at": "2099-01-01T00:00:00Z",
                    },
                )
            elif self.path.endswith("/heartbeat"):
                self._json(state.heartbeat_status, {})
            elif self.path.endswith("/checkpoint"):
                self._json(200, state.checkpoint_payload)
            elif self.path.endswith("/complete"):
                self._json(state.completion_status, {})
            else:
                self._json(404, {})

        def _json(self, status: int, payload: dict) -> None:
            encoded = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _run_worker(
    state: _WorkerApi,
    api_url: str,
    *,
    delay: float = 0.01,
    heartbeat_interval: float = 0.2,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        "-m",
        "tracefence.runtime.worker",
        "--api-url",
        api_url,
        "--node-id",
        "worker-node",
        "--mode",
        "cooperative",
        "--delay",
        str(delay),
        "--heartbeat-interval",
        str(heartbeat_interval),
        "--max-heartbeat-failures",
        "1",
    ]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        command,
        input=json.dumps({"activation_token": state.activation_token}) + "\n",
        text=True,
        capture_output=True,
        timeout=10,
        cwd=ROOT,
        env=environment,
        check=False,
    )
    joined_argv = "\0".join(command)
    assert state.activation_token not in joined_argv
    assert state.node_token not in joined_argv
    assert state.activation_token not in result.stdout + result.stderr
    assert state.node_token not in result.stdout + result.stderr
    return result


def test_successful_worker_requires_allowed_checkpoint_and_completes(worker_api):
    state, api_url = worker_api

    result = _run_worker(state, api_url)

    assert result.returncode == 0, result.stderr
    assert any(path.endswith("/checkpoint") for path in state.paths)
    assert any(path.endswith("/complete") for path in state.paths)


def test_http_200_denied_checkpoint_is_not_success(worker_api):
    state, api_url = worker_api
    state.checkpoint_payload = {
        "allowed": False,
        "effective_status": "SUPERSEDED",
        "reason_code": "SCOPE_SUPERSEDED",
    }

    result = _run_worker(state, api_url)

    assert result.returncode == 5
    assert not any(path.endswith("/complete") for path in state.paths)


def test_completion_rejection_has_deterministic_exit(worker_api):
    state, api_url = worker_api
    state.completion_status = 409

    result = _run_worker(state, api_url)

    assert result.returncode == 6


def test_heartbeat_rejection_stops_work_before_checkpoint(worker_api):
    state, api_url = worker_api
    state.heartbeat_status = 409

    result = _run_worker(
        state,
        api_url,
        delay=0.5,
        heartbeat_interval=0.02,
    )

    assert result.returncode == 3
    assert not any(path.endswith("/checkpoint") for path in state.paths)


def test_waiting_worker_terminates_without_stdin_thread_hang(worker_api):
    state, api_url = worker_api
    command = [
        sys.executable,
        "-m",
        "tracefence.runtime.worker",
        "--api-url",
        api_url,
        "--node-id",
        "worker-node",
        "--mode",
        "cooperative",
        "--wait-for-release",
        "--heartbeat-interval",
        "0.2",
    ]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=ROOT,
        env=environment,
    )
    assert process.stdin is not None
    process.stdin.write(json.dumps({"activation_token": state.activation_token}) + "\n")
    process.stdin.flush()
    # Coverage instrumentation and cold Windows process startup can exceed
    # three seconds; the assertion still requires activation before termination.
    deadline = time.monotonic() + 10
    while not any(path.endswith("/activate") for path in state.paths):
        assert time.monotonic() < deadline
        time.sleep(0.02)

    process.terminate()
    stdout, stderr = process.communicate(timeout=3)

    assert process.returncode != 0
    assert state.activation_token not in "\0".join(command)
    assert state.activation_token not in stdout + stderr
    assert state.node_token not in stdout + stderr
