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

from scripts.run_local_tests import hermetic_test_environment

ROOT = Path(__file__).resolve().parents[2]


class _WorkerApi:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.heartbeat_status = 204
        self.checkpoint_payload = {"allowed": True, "effective_status": "ACTIVE"}
        self.completion_status = 204
        self.activation_token = "activation-secret-value-123456"
        self.node_token = "node-secret-value-123456789"
        self.activation_payloads: list[dict[str, object]] = []
        self.drop_first_activation_response = False
        self.heartbeat_seen = threading.Event()


@pytest.fixture
def worker_api():
    state = _WorkerApi()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            content_length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(content_length)
            state.paths.append(self.path)
            if self.path.endswith("/activate"):
                payload = json.loads(body)
                assert payload["activation_token"] == state.activation_token
                state.activation_payloads.append(payload)
                if state.drop_first_activation_response and len(state.activation_payloads) == 1:
                    self.close_connection = True
                    return
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
                state.heartbeat_seen.set()
                self._json(state.heartbeat_status, {})
            elif self.path.endswith("/checkpoint"):
                self._json(200, state.checkpoint_payload)
            elif self.path.endswith("/complete"):
                self._json(state.completion_status, {})
            elif self.path.endswith("/actions"):
                self._json(
                    200,
                    {
                        "action_id": "audit-action",
                        "decision": "DENY",
                        "denial_reason": "SCOPE_SUPERSEDED",
                        "committed": False,
                        "duplicate": False,
                    },
                )
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


def _worker_environment() -> dict[str, str]:
    environment = hermetic_test_environment(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    return environment


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
    environment = _worker_environment()
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


def test_worker_subprocess_environment_is_hermetic(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=secret")
    monkeypatch.setenv("SIGNOZ_API_KEY", "test-signoz-key")
    monkeypatch.setenv("TRACEFENCE_NOTIFICATION_CHANNEL", "test-channel")

    environment = _worker_environment()

    assert environment["OTEL_SDK_DISABLED"] == "true"
    assert environment["OTEL_EXPORTER_OTLP_ENDPOINT"] == ""
    assert "OTEL_EXPORTER_OTLP_HEADERS" not in environment
    assert "SIGNOZ_API_KEY" not in environment
    assert "TRACEFENCE_NOTIFICATION_CHANNEL" not in environment


def test_successful_worker_requires_allowed_checkpoint_and_completes(worker_api):
    state, api_url = worker_api

    result = _run_worker(state, api_url)

    assert result.returncode == 0, result.stderr
    assert any(path.endswith("/checkpoint") for path in state.paths)
    assert any(path.endswith("/complete") for path in state.paths)


def test_worker_retries_the_identical_activation_payload_after_lost_response(worker_api):
    state, api_url = worker_api
    state.drop_first_activation_response = True

    result = _run_worker(state, api_url)

    assert result.returncode == 0, result.stderr
    assert len(state.activation_payloads) == 2
    assert state.activation_payloads[0] == state.activation_payloads[1]
    assert state.activation_token not in result.stdout + result.stderr
    assert state.node_token not in result.stdout + result.stderr


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
    environment = _worker_environment()
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

    # A heartbeat proves that the worker reached the release wait after activation.
    assert state.heartbeat_seen.wait(timeout=5)

    process.terminate()
    stdout, stderr = process.communicate(timeout=3)

    assert process.returncode != 0
    assert "Fatal Python error" not in stderr
    assert "_enter_buffered_busy" not in stderr
    assert state.activation_token not in "\0".join(command)
    assert process.returncode == 143
    assert state.activation_token not in stdout + stderr
    assert state.node_token not in stdout + stderr


def test_waiting_worker_stops_after_lease_rejection_without_release_input(worker_api):
    state, api_url = worker_api
    state.heartbeat_status = 409
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
        "0.02",
        "--max-heartbeat-failures",
        "1",
    ]
    environment = _worker_environment()
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

    process.wait(timeout=5)
    stdout, stderr = process.communicate(timeout=1)

    assert process.returncode == 3, stderr
    assert not any(path.endswith("/checkpoint") for path in state.paths)
    assert "Fatal Python error" not in stderr
    assert state.activation_token not in stdout + stderr
    assert state.node_token not in stdout + stderr


def test_waiting_worker_preserves_prebuffered_release_signal(worker_api):
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
    environment = _worker_environment()

    result = subprocess.run(
        command,
        input=json.dumps({"activation_token": state.activation_token}) + "\nGO\n",
        text=True,
        capture_output=True,
        timeout=10,
        cwd=ROOT,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert any(path.endswith("/checkpoint") for path in state.paths)
    assert any(path.endswith("/complete") for path in state.paths)
    assert state.activation_token not in result.stdout + result.stderr
    assert state.node_token not in result.stdout + result.stderr


def test_non_compliant_worker_checkpoints_before_released_action(worker_api):
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
        "non_compliant_action",
        "--wait-for-release",
        "--heartbeat-interval",
        "0.2",
        "--tool",
        "restart_postgres",
        "--idempotency-key",
        "checkpoint-before-action",
    ]
    result = subprocess.run(
        command,
        input=json.dumps({"activation_token": state.activation_token}) + "\nGO\n",
        text=True,
        capture_output=True,
        timeout=10,
        cwd=ROOT,
        env=_worker_environment(),
        check=False,
    )

    assert result.returncode == 0, result.stderr
    checkpoint_index = next(
        index
        for index, path in enumerate(state.paths)
        if path.endswith("/checkpoint")
    )
    action_index = next(
        index
        for index, path in enumerate(state.paths)
        if path.endswith("/actions")
    )
    assert checkpoint_index < action_index
    assert state.activation_token not in result.stdout + result.stderr
    assert state.node_token not in result.stdout + result.stderr
