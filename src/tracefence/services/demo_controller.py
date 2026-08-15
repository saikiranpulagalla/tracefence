from __future__ import annotations

import asyncio
import json
import logging
import os

# Security: fixed interpreter/module and list argv use shell=False; the worker token travels via stdin.
import subprocess  # nosec B404
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from tracefence.config import settings
from tracefence.db.models import ActionAttempt, Node
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.domain.schemas import (
    ActionExecute,
    ActionResult,
    CommandCreate,
    NodeActivate,
    NodeActivated,
    Principal,
    RunCreate,
    RunCreated,
    SpawnCreate,
)
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import iso_utc, utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.graph_service import GraphService
from tracefence.services.lease_service import LeaseService
from tracefence.services.proof_service import ProofService
from tracefence.services.run_service import RunService
from tracefence.services.runtime_events import record_runtime_event
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService

logger = logging.getLogger(__name__)

_CANONICAL_SCENARIO = "stale-supersession"
_SCENARIO_CHECKS = frozenset(
    {
        "cancellation",
        "lease-expiry",
        "idempotent-retry",
        "recovery-manifest-mismatch",
        "sibling-isolation",
        "concurrent-stale-valid",
    }
)
_STALE_ACTION_KEY = "demo-stale-restart-postgres"
_RECOVERY_ACTION_KEY = "demo-reset-redis-pool"
_WAITING_STAGE = "before_protected_action"
_WORKER_START_DEADLINE_SECONDS = 10.0
_WORKER_EXIT_DEADLINE_SECONDS = 15.0
_REPO_ROOT = Path(__file__).resolve().parents[3]


class DemoWorkerHandle(Protocol):
    async def release(self) -> None: ...

    def terminate(self) -> None: ...


DemoWorkerFactory = Callable[
    [str, str, str], Awaitable[DemoWorkerHandle]
]


@dataclass(slots=True)
class _DemoSecrets:
    root_token: str
    database_token: str
    sibling_token: str


@dataclass(slots=True)
class _DemoSession:
    id: str
    run_id: str
    phase: str
    root_node_id: str
    database_node_id: str
    stale_worker_node_id: str
    sibling_node_id: str
    worker: DemoWorkerHandle
    secrets: _DemoSecrets
    command_id: str | None = None
    replacement_node_id: str | None = None
    stale_action_id: str | None = None
    replacement_action_id: str | None = None
    scope_from_version: int | None = None
    scope_to_version: int | None = None
    proof: dict[str, object] | None = None
    heartbeat_manager: _DemoHeartbeatManager | None = None
    lock: threading.RLock = field(default_factory=threading.RLock)


@dataclass(slots=True)
class _PendingLeaseCheck:
    id: str
    run_id: str
    root_node_id: str
    child_node_id: str
    child_token: str
    expires_at: datetime
    heartbeat_manager: _DemoHeartbeatManager | None
    finished: bool = False


class _SubprocessWorker:
    def __init__(self, process: subprocess.Popen[str]) -> None:
        self.process = process

    async def release(self) -> None:
        await asyncio.to_thread(self._release_blocking)

    def _release_blocking(self) -> None:
        if self.process.poll() is not None:
            raise RuntimeError("Demo worker exited before release")
        if self.process.stdin is None:
            raise RuntimeError("Demo worker release pipe is unavailable")
        self.process.stdin.write("GO\n")
        self.process.stdin.flush()
        self.process.stdin.close()
        self.process.stdin = None
        stdout, stderr = self.process.communicate(
            timeout=_WORKER_EXIT_DEADLINE_SECONDS
        )
        if self.process.returncode != 0:
            raise RuntimeError(
                "Demo worker did not complete its gateway request: "
                f"exit={self.process.returncode}; stderr={stderr[-500:]}"
            )
        if "node_token" in stdout or "activation_token" in stdout:
            raise RuntimeError("Demo worker output contained credential field names")

    def terminate(self) -> None:
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)


class _DemoHeartbeatManager:
    """Own a bounded, explicitly joined keepalive loop across HTTP requests."""

    def __init__(self, spawn_service: SpawnService, nodes: dict[str, str]) -> None:
        self.spawn_service = spawn_service
        self.nodes = dict(nodes)
        self.nodes_lock = threading.RLock()
        self.stop_requested = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="tracefence-demo-heartbeats",
            daemon=False,
        )

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_requested.set()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise RuntimeError("Demo heartbeat manager did not stop")

    def remove_nodes(self, node_ids: set[str]) -> None:
        """Stop renewals and wait for any in-flight renewal to finish."""

        with self.nodes_lock:
            for node_id in node_ids:
                self.nodes.pop(node_id, None)

    def _run(self) -> None:
        interval = min(max(settings.lease_ttl_seconds / 3, 0.25), 2.0)
        while not self.stop_requested.is_set():
            with self.nodes_lock:
                if not self.nodes:
                    return
                for node_id, node_token in list(self.nodes.items()):
                    if self.stop_requested.is_set():
                        break
                    try:
                        asyncio.run(self.spawn_service.heartbeat(node_id, node_token))
                    except (ConflictError, NotFoundError) as exc:
                        self.nodes.pop(node_id, None)
                        logger.info(
                            "demo_heartbeat_stopped node_id=%s reason_code=%s",
                            node_id,
                            exc.code,
                        )
                    except Exception:
                        logger.exception(
                            "demo_heartbeat_retry node_id=%s",
                            node_id,
                        )
            self.stop_requested.wait(interval)


class DemoController:
    """Orchestrate fixed demonstrations through the existing runtime services.

    The controller owns only process-local credentials and worker handles. It
    never evaluates action authority and never mutates authoritative rows
    directly. Every domain transition is delegated to the existing services;
    the browser can request only the fixed phase transitions below.
    """

    def __init__(
        self,
        session_factory: sessionmaker,
        *,
        run_service: RunService | None = None,
        spawn_service: SpawnService | None = None,
        control_service: ControlService | None = None,
        action_gateway: ActionGateway | None = None,
        graph_service: GraphService | None = None,
        state_service: StateService | None = None,
        proof_service: ProofService | None = None,
        lease_service: LeaseService | None = None,
        worker_factory: DemoWorkerFactory | None = None,
        maintain_heartbeats: bool = True,
    ) -> None:
        self.session_factory = session_factory
        self.run_service = run_service or RunService(session_factory)
        self.spawn_service = spawn_service or SpawnService(session_factory)
        self.control_service = control_service or ControlService(session_factory)
        self.action_gateway = action_gateway or ActionGateway(session_factory)
        self.graph_service = graph_service or GraphService(session_factory)
        self.state_service = state_service or StateService(session_factory)
        self.proof_service = proof_service or ProofService(session_factory)
        self.lease_service = lease_service or LeaseService(session_factory)
        self.worker_factory = worker_factory or self._start_subprocess_worker
        self.maintain_heartbeats = maintain_heartbeats
        self._sessions: dict[str, _DemoSession] = {}
        self._checks: list[dict[str, object]] = []
        self._lease_checks: dict[str, _PendingLeaseCheck] = {}
        self._state_lock = threading.RLock()

    async def start(self, scenario: str) -> dict[str, object]:
        if scenario != _CANONICAL_SCENARIO:
            raise NotFoundError(f"Demo scenario {scenario} was not found")

        run = await self.run_service.create_run(
            RunCreate(
                name="TraceFence stale-supersession demo",
                root_role="demo-supervisor",
                root_instruction={"goal": "demonstrate runtime authority"},
                root_capabilities=[
                    "control:descendants",
                    "tool:read_metrics",
                    "tool:restart_postgres",
                    "tool:reset_redis_pool",
                    "tool:propose_correction",
                ],
            )
        )
        await self.state_service.seed_scenario(run.run_id)

        database_spawn = await self.spawn_service.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                operation_key="demo-database-branch",
                role="postgres-investigation",
                instruction={"task": "investigate PostgreSQL latency"},
                capabilities=["tool:read_metrics", "tool:restart_postgres"],
            ),
        )
        database = await self.spawn_service.activate(
            database_spawn.child_node_id,
            self._activation_request(
                database_spawn.activation_token,
                "demo-database-activation",
            ),
        )
        stale_spawn = await self.spawn_service.create_spawn(
            database.node_id,
            database.node_token,
            SpawnCreate(
                operation_key="demo-stale-worker",
                role="postgres-worker",
                instruction={"task": "restart PostgreSQL"},
                capabilities=["tool:restart_postgres"],
                behavior="non_compliant",
            ),
        )
        stale_worker = await self.spawn_service.activate(
            stale_spawn.child_node_id,
            self._activation_request(
                stale_spawn.activation_token,
                "demo-stale-worker-activation",
            ),
        )
        sibling_spawn = await self.spawn_service.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                operation_key="demo-sibling-branch",
                role="metrics-sibling",
                instruction={"task": "observe unrelated metrics"},
                capabilities=["tool:read_metrics"],
            ),
        )
        sibling = await self.spawn_service.activate(
            sibling_spawn.child_node_id,
            self._activation_request(
                sibling_spawn.activation_token,
                "demo-sibling-activation",
            ),
        )
        heartbeat_manager: _DemoHeartbeatManager | None = None
        if self.maintain_heartbeats:
            heartbeat_manager = _DemoHeartbeatManager(
                self.spawn_service,
                {
                    run.root_node_id: run.root_token,
                    database.node_id: database.node_token,
                    stale_worker.node_id: stale_worker.node_token,
                    sibling.node_id: sibling.node_token,
                },
            )
            heartbeat_manager.start()

        try:
            worker = await self.worker_factory(
                stale_worker.node_id,
                stale_worker.node_token,
                _STALE_ACTION_KEY,
            )
        except BaseException:
            if heartbeat_manager is not None:
                heartbeat_manager.close()
            raise
        session = _DemoSession(
            id=str(uuid4()),
            run_id=run.run_id,
            phase="WAITING_STALE_WORKER",
            root_node_id=run.root_node_id,
            database_node_id=database.node_id,
            stale_worker_node_id=stale_spawn.child_node_id,
            sibling_node_id=sibling.node_id,
            worker=worker,
            secrets=_DemoSecrets(
                root_token=run.root_token,
                database_token=database.node_token,
                sibling_token=sibling.node_token,
            ),
            heartbeat_manager=heartbeat_manager,
        )
        with self._state_lock:
            self._sessions[session.id] = session
        return await self._snapshot(session)

    async def supersede(self, session_id: str) -> dict[str, object]:
        demo = self._get(session_id)
        with demo.lock:
            self._require_phase(demo, "WAITING_STALE_WORKER")
            if demo.heartbeat_manager is not None:
                demo.heartbeat_manager.close()
                demo.heartbeat_manager = None
            command = await self.control_service.issue_command(
                CommandCreate(
                    idempotency_key="demo-supersede-postgres",
                    command_type=CommandType.CORRECT_SUBTREE,
                    target_node_id=demo.database_node_id,
                    reason_code="WRONG_ROOT_CAUSE",
                    reason_text=(
                        "Redis pool exhaustion is causal; PostgreSQL is healthy"
                    ),
                    replacement_instruction={"task": "reset Redis pool"},
                    replacement_expected_tool="reset_redis_pool",
                    recovery_stability_seconds=0,
                ),
                Principal(issuer_type=IssuerType.HUMAN),
            )
            checkpoint = await self.spawn_service.checkpoint(
                demo.database_node_id,
                demo.secrets.database_token,
                "after_supersession",
            )
            if checkpoint.allowed:
                raise RuntimeError("Superseded database parent remained checkpoint-valid")
            demo.command_id = command.command_id
            demo.scope_from_version = command.from_version
            demo.scope_to_version = command.to_version
            demo.phase = "SUPERSEDED"
        return await self._snapshot(demo)

    async def release_stale_worker(self, session_id: str) -> dict[str, object]:
        demo = self._get(session_id)
        with demo.lock:
            self._require_phase(demo, "SUPERSEDED")
            with self.session_factory() as session, session.begin():
                record_runtime_event(
                    session,
                    run_id=demo.run_id,
                    event_type="DEMO_WORKER_RELEASED",
                    node_id=demo.stale_worker_node_id,
                    command_id=demo.command_id,
                )
            await demo.worker.release()
            attempt = self._action_by_key(demo.stale_worker_node_id, _STALE_ACTION_KEY)
            if attempt.decision != "DENY" or attempt.denial_reason != "SCOPE_SUPERSEDED":
                raise RuntimeError("Stale demo worker was not denied by supersession")
            demo.stale_action_id = attempt.id
            demo.phase = "STALE_DENIED"
        snapshot = await self._snapshot(demo)
        postgres = self._service(snapshot, "postgres")
        if postgres["restart_count"] != 0:
            raise RuntimeError("Stale demo action changed PostgreSQL state")
        return snapshot

    async def run_replacement(self, session_id: str) -> dict[str, object]:
        demo = self._get(session_id)
        with demo.lock:
            self._require_phase(demo, "STALE_DENIED")
            if demo.command_id is None:
                raise RuntimeError("Demo correction command is missing")
            replacement_spawn = await self.spawn_service.create_replacement(
                demo.root_node_id,
                demo.secrets.root_token,
                demo.command_id,
                SpawnCreate(
                    operation_key="demo-replacement",
                    role="redis_recovery",
                    instruction={"task": "reset Redis pool"},
                    capabilities=["tool:reset_redis_pool"],
                    behavior="cooperative",
                ),
            )
            replacement = await self.spawn_service.activate(
                replacement_spawn.child_node_id,
                self._activation_request(
                    replacement_spawn.activation_token,
                    "demo-replacement-activation",
                ),
            )
            allowed = await self.action_gateway.execute(
                replacement.node_id,
                replacement.node_token,
                ActionExecute(
                    idempotency_key=_RECOVERY_ACTION_KEY,
                    tool_name="reset_redis_pool",
                    arguments={},
                ),
            )
            if allowed.decision != "ALLOW" or not allowed.committed:
                raise RuntimeError("Exact demo recovery action did not commit")
            await self.spawn_service.complete(
                replacement.node_id,
                replacement.node_token,
            )
            demo.replacement_node_id = replacement.node_id
            demo.replacement_action_id = allowed.action_id
            demo.phase = "RECOVERY_COMMITTED"
        snapshot = await self._snapshot(demo)
        redis = self._service(snapshot, "redis")
        if redis["pool_reset_count"] != 1:
            raise RuntimeError("Demo recovery side effect was not exactly once")
        return snapshot

    async def build_proof(self, session_id: str) -> dict[str, object]:
        demo = self._get(session_id)
        with demo.lock:
            self._require_phase(demo, "RECOVERY_COMMITTED")
            if demo.command_id is None:
                raise RuntimeError("Demo correction command is missing")
            proof = await self.proof_service.build(demo.command_id)
            demo.proof = proof.model_dump(mode="json")
            demo.phase = "PROOF_AVAILABLE"
            if demo.heartbeat_manager is not None:
                demo.heartbeat_manager.close()
                demo.heartbeat_manager = None
        return await self._snapshot(demo)

    async def run_check(self, scenario: str) -> dict[str, object]:
        """Run one fixed adversarial check through real runtime services."""

        dispatch = {
            "cancellation": self._check_cancellation,
            "lease-expiry": self._start_lease_expiry,
            "idempotent-retry": self._check_idempotency,
            "recovery-manifest-mismatch": self._check_manifest_mismatch,
            "sibling-isolation": self._check_sibling_isolation,
            "concurrent-stale-valid": self._check_concurrent_stale_valid,
        }
        check = dispatch.get(scenario)
        if scenario not in _SCENARIO_CHECKS or check is None:
            raise NotFoundError(f"Demo scenario {scenario} was not found")
        result = await check()
        if result.get("status") == "PASS":
            with self._state_lock:
                self._checks.append(result)
                self._checks = self._checks[-50:]
        return result

    async def list_checks(self) -> list[dict[str, object]]:
        with self._state_lock:
            return list(reversed(self._checks))

    async def _check_cancellation(self) -> dict[str, object]:
        run = await self._create_check_run("cancellation")
        child = await self._spawn_check_node(
            run.root_node_id,
            run.root_token,
            operation="cancellation-worker",
            role="cancelled-worker",
            capabilities=["tool:restart_postgres"],
        )
        checkpoint = await self.spawn_service.checkpoint(
            child.node_id, child.node_token, _WAITING_STAGE
        )
        if not checkpoint.allowed:
            raise RuntimeError("Cancellation check worker did not reach WAITING")
        await self.control_service.issue_command(
            CommandCreate(
                idempotency_key="demo-cancel-subtree",
                command_type=CommandType.CANCEL_SUBTREE,
                target_node_id=child.node_id,
                reason_code="DEMO_CANCELLATION",
                reason_text="Cancel the paused demonstration worker",
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
        denied = await self.action_gateway.execute(
            child.node_id,
            child.node_token,
            ActionExecute(
                idempotency_key="demo-cancelled-action",
                tool_name="restart_postgres",
                arguments={},
            ),
        )
        await self._close_check_run(run, "cancellation")
        snapshot = await self._check_snapshot(run.run_id, [denied.action_id])
        postgres = self._service(snapshot, "postgres")
        if denied.denial_reason != "SCOPE_CANCELLED" or postgres["restart_count"] != 0:
            raise RuntimeError("Cancellation check did not fail closed")
        return self._check_result(
            "cancellation",
            snapshot,
            expected="DENY SCOPE_CANCELLED; postgres restart_count=0",
        )

    async def _start_lease_expiry(self) -> dict[str, object]:
        run = await self._create_check_run("lease expiry")
        child = await self._spawn_check_node(
            run.root_node_id,
            run.root_token,
            operation="lease-expiry-worker",
            role="lease-expiry-worker",
            capabilities=["tool:restart_postgres"],
        )
        checkpoint = await self.spawn_service.checkpoint(
            child.node_id, child.node_token, _WAITING_STAGE
        )
        if not checkpoint.allowed:
            raise RuntimeError("Lease check worker did not reach WAITING")
        heartbeat_manager = None
        if self.maintain_heartbeats:
            heartbeat_manager = _DemoHeartbeatManager(
                self.spawn_service,
                {run.root_node_id: run.root_token},
            )
            heartbeat_manager.start()
        check = _PendingLeaseCheck(
            id=str(uuid4()),
            run_id=run.run_id,
            root_node_id=run.root_node_id,
            child_node_id=child.node_id,
            child_token=child.node_token,
            expires_at=child.lease_expires_at,
            heartbeat_manager=heartbeat_manager,
        )
        with self._state_lock:
            self._lease_checks[check.id] = check
        return {
            "scenario": "lease-expiry",
            "status": "WAITING_FOR_LEASE_EXPIRY",
            "check_id": check.id,
            "run_id": check.run_id,
            "ready_at": iso_utc(check.expires_at),
            "expected": "DENY LEASE_EXPIRED; postgres restart_count=0",
        }

    async def finish_lease_expiry(self, check_id: str) -> dict[str, object]:
        with self._state_lock:
            check = self._lease_checks.get(check_id)
        if check is None:
            raise NotFoundError(f"Demo lease check {check_id} was not found")
        if check.finished:
            raise ConflictError(
                "Lease-expiry check already completed",
                code="DEMO_INVALID_TRANSITION",
            )
        with self.session_factory() as session:
            node = session.get(Node, check.child_node_id)
            authoritative_expiry = node.lease_expires_at if node is not None else None
        if authoritative_expiry is None or utcnow() <= authoritative_expiry:
            raise ConflictError(
                "Worker lease is still authoritative",
                code="DEMO_LEASE_STILL_LIVE",
            )
        denied = await self.action_gateway.execute(
            check.child_node_id,
            check.child_token,
            ActionExecute(
                idempotency_key="demo-expired-lease-action",
                tool_name="restart_postgres",
                arguments={},
            ),
        )
        await self.lease_service.expire_stale_nodes(check.run_id)
        if check.heartbeat_manager is not None:
            check.heartbeat_manager.close()
            check.heartbeat_manager = None
        check.finished = True
        await self._close_check_run_ids(
            check.run_id,
            check.root_node_id,
            "lease-expiry",
        )
        snapshot = await self._check_snapshot(check.run_id, [denied.action_id])
        postgres = self._service(snapshot, "postgres")
        if denied.denial_reason != "LEASE_EXPIRED" or postgres["restart_count"] != 0:
            raise RuntimeError("Expired lease did not fail closed at the gateway")
        result = self._check_result(
            "lease-expiry",
            snapshot,
            expected="DENY LEASE_EXPIRED; postgres restart_count=0",
        )
        result["check_id"] = check.id
        with self._state_lock:
            self._checks.append(result)
            self._checks = self._checks[-50:]
        return result

    async def _check_idempotency(self) -> dict[str, object]:
        run = await self._create_check_run("idempotent retry")
        worker = await self._spawn_check_node(
            run.root_node_id,
            run.root_token,
            operation="idempotency-worker",
            role="idempotency-worker",
            capabilities=["tool:reset_redis_pool", "tool:restart_postgres"],
        )
        request = ActionExecute(
            idempotency_key="demo-idempotent-action",
            tool_name="reset_redis_pool",
            arguments={},
        )
        first = await self.action_gateway.execute(
            worker.node_id, worker.node_token, request
        )
        replay = await self.action_gateway.execute(
            worker.node_id, worker.node_token, request
        )
        conflict_code = None
        try:
            await self.action_gateway.execute(
                worker.node_id,
                worker.node_token,
                ActionExecute(
                    idempotency_key=request.idempotency_key,
                    tool_name="restart_postgres",
                    arguments={},
                ),
            )
        except ConflictError as exc:
            conflict_code = exc.code
        await self._close_check_run(run, "idempotent-retry")
        snapshot = await self._check_snapshot(run.run_id, [first.action_id])
        redis = self._service(snapshot, "redis")
        if (
            not replay.duplicate
            or conflict_code != "IDEMPOTENCY_PAYLOAD_MISMATCH"
            or redis["pool_reset_count"] != 1
        ):
            raise RuntimeError("Idempotency check did not preserve exactly-once state")
        result = self._check_result(
            "idempotent-retry",
            snapshot,
            expected="ALLOW, exact replay, changed-payload conflict; effect_count=1",
        )
        result["replay_duplicate"] = replay.duplicate
        result["conflict_code"] = conflict_code
        return result

    async def _check_manifest_mismatch(self) -> dict[str, object]:
        run = await self._create_check_run("recovery manifest mismatch")
        target = await self._spawn_check_node(
            run.root_node_id,
            run.root_token,
            operation="manifest-target",
            role="incorrect-investigation",
            capabilities=["tool:read_metrics"],
        )
        command = await self.control_service.issue_command(
            CommandCreate(
                idempotency_key="demo-manifest-correction",
                command_type=CommandType.CORRECT_SUBTREE,
                target_node_id=target.node_id,
                reason_code="DEMO_MANIFEST",
                reason_text="Require an exact Redis recovery",
                replacement_instruction={"task": "reset Redis pool"},
                replacement_expected_tool="reset_redis_pool",
                recovery_stability_seconds=0,
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
        replacement_spawn = await self.spawn_service.create_replacement(
            run.root_node_id,
            run.root_token,
            command.command_id,
            SpawnCreate(
                operation_key="demo-manifest-replacement",
                role="redis_recovery",
                instruction={"task": "reset Redis pool"},
                capabilities=["tool:reset_redis_pool"],
            ),
        )
        replacement = await self.spawn_service.activate(
            replacement_spawn.child_node_id,
            self._activation_request(
                replacement_spawn.activation_token,
                "demo-manifest-replacement-activation",
            ),
        )
        denied = await self.action_gateway.execute(
            replacement.node_id,
            replacement.node_token,
            ActionExecute(
                idempotency_key="demo-wrong-recovery-tool",
                tool_name="restart_postgres",
                arguments={},
            ),
        )
        allowed = await self.action_gateway.execute(
            replacement.node_id,
            replacement.node_token,
            ActionExecute(
                idempotency_key="demo-exact-recovery-tool",
                tool_name="reset_redis_pool",
                arguments={},
            ),
        )
        await self._close_check_run(run, "recovery-manifest-mismatch")
        snapshot = await self._check_snapshot(
            run.run_id, [denied.action_id, allowed.action_id]
        )
        redis = self._service(snapshot, "redis")
        if (
            denied.decision != "DENY"
            or denied.denial_reason != "RECOVERY_TOOL_MISMATCH"
            or allowed.decision != "ALLOW"
            or redis["pool_reset_count"] != 1
        ):
            raise RuntimeError("Recovery manifest check did not enforce the exact contract")
        return self._check_result(
            "recovery-manifest-mismatch",
            snapshot,
            expected="wrong tool DENY before execution; exact recovery ALLOW once",
        )

    async def _check_sibling_isolation(self) -> dict[str, object]:
        run = await self._create_check_run("sibling isolation")
        stale = await self._spawn_check_node(
            run.root_node_id,
            run.root_token,
            operation="isolated-stale-sibling",
            role="stale-sibling",
            capabilities=["tool:read_metrics"],
        )
        live = await self._spawn_check_node(
            run.root_node_id,
            run.root_token,
            operation="isolated-live-sibling",
            role="live-sibling",
            capabilities=["tool:read_metrics"],
        )
        await self.control_service.issue_command(
            CommandCreate(
                idempotency_key="demo-isolate-sibling",
                command_type=CommandType.CANCEL_SUBTREE,
                target_node_id=stale.node_id,
                reason_code="DEMO_ISOLATION",
                reason_text="Cancel one sibling only",
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
        denied, allowed = await asyncio.gather(
            self.action_gateway.execute(
                stale.node_id,
                stale.node_token,
                ActionExecute(
                    idempotency_key="demo-stale-sibling-read",
                    tool_name="read_metrics",
                    arguments={},
                ),
            ),
            self.action_gateway.execute(
                live.node_id,
                live.node_token,
                ActionExecute(
                    idempotency_key="demo-live-sibling-read",
                    tool_name="read_metrics",
                    arguments={},
                ),
            ),
        )
        await self._close_check_run(run, "sibling-isolation")
        snapshot = await self._check_snapshot(
            run.run_id, [denied.action_id, allowed.action_id]
        )
        if denied.denial_reason != "SCOPE_CANCELLED" or allowed.decision != "ALLOW":
            raise RuntimeError("Sibling isolation check disrupted unrelated authority")
        return self._check_result(
            "sibling-isolation",
            snapshot,
            expected="cancelled sibling DENY; unrelated sibling ALLOW",
        )

    async def _check_concurrent_stale_valid(self) -> dict[str, object]:
        run = await self._create_check_run("concurrent stale and valid actions")
        target = await self._spawn_check_node(
            run.root_node_id,
            run.root_token,
            operation="race-target",
            role="stale-race-target",
            capabilities=["tool:restart_postgres"],
        )
        stale = await self._spawn_check_node(
            target.node_id,
            target.node_token,
            operation="race-stale-worker",
            role="stale-race-worker",
            capabilities=["tool:restart_postgres"],
        )
        command = await self.control_service.issue_command(
            CommandCreate(
                idempotency_key="demo-race-correction",
                command_type=CommandType.CORRECT_SUBTREE,
                target_node_id=target.node_id,
                reason_code="DEMO_RACE",
                reason_text="Race stale work against the exact replacement",
                replacement_instruction={"task": "reset Redis pool"},
                replacement_expected_tool="reset_redis_pool",
                recovery_stability_seconds=0,
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )
        replacement_spawn = await self.spawn_service.create_replacement(
            run.root_node_id,
            run.root_token,
            command.command_id,
            SpawnCreate(
                operation_key="demo-race-replacement",
                role="redis_recovery",
                instruction={"task": "reset Redis pool"},
                capabilities=["tool:reset_redis_pool"],
            ),
        )
        replacement = await self.spawn_service.activate(
            replacement_spawn.child_node_id,
            self._activation_request(
                replacement_spawn.activation_token,
                "demo-race-replacement-activation",
            ),
        )

        async def execute_in_thread(
            node_id: str,
            token: str,
            request: ActionExecute,
        ) -> ActionResult:
            return await asyncio.to_thread(
                lambda: asyncio.run(
                    self.action_gateway.execute(node_id, token, request)
                )
            )

        denied, allowed = await asyncio.gather(
            execute_in_thread(
                stale.node_id,
                stale.node_token,
                ActionExecute(
                    idempotency_key="demo-race-stale",
                    tool_name="restart_postgres",
                    arguments={},
                ),
            ),
            execute_in_thread(
                replacement.node_id,
                replacement.node_token,
                ActionExecute(
                    idempotency_key="demo-race-valid",
                    tool_name="reset_redis_pool",
                    arguments={},
                ),
            ),
        )
        await self._close_check_run(run, "concurrent-stale-valid")
        snapshot = await self._check_snapshot(
            run.run_id, [denied.action_id, allowed.action_id]
        )
        postgres = self._service(snapshot, "postgres")
        redis = self._service(snapshot, "redis")
        if (
            denied.denial_reason != "SCOPE_SUPERSEDED"
            or allowed.decision != "ALLOW"
            or postgres["restart_count"] != 0
            or redis["pool_reset_count"] != 1
        ):
            raise RuntimeError("Concurrent stale/valid check violated authority")
        return self._check_result(
            "concurrent-stale-valid",
            snapshot,
            expected="stale DENY; exact replacement ALLOW; effects 0/1",
        )

    async def _create_check_run(self, label: str) -> RunCreated:
        run = await self.run_service.create_run(
            RunCreate(
                name=f"TraceFence demo check: {label}",
                root_role="demo-check-supervisor",
                root_instruction={"scenario": label},
                root_capabilities=[
                    "control:descendants",
                    "tool:read_metrics",
                    "tool:restart_postgres",
                    "tool:reset_redis_pool",
                    "tool:propose_correction",
                ],
            )
        )
        await self.state_service.seed_scenario(run.run_id)
        return run

    async def _close_check_run(self, run: RunCreated, scenario: str) -> None:
        await self._close_check_run_ids(run.run_id, run.root_node_id, scenario)

    async def _close_check_run_ids(
        self,
        run_id: str,
        root_node_id: str,
        scenario: str,
    ) -> None:
        """Terminalize a disposable check through the real control plane."""

        await self.control_service.issue_command(
            CommandCreate(
                idempotency_key=f"demo-check-complete-{scenario}-{run_id}",
                command_type=CommandType.CANCEL_RUN,
                target_node_id=root_node_id,
                reason_code="DEMO_CHECK_COMPLETE",
                reason_text="Close the completed disposable Runtime Inspector check",
            ),
            Principal(issuer_type=IssuerType.HUMAN),
        )

    async def _spawn_check_node(
        self,
        parent_id: str,
        parent_token: str,
        *,
        operation: str,
        role: str,
        capabilities: list[str],
    ) -> NodeActivated:
        spawned = await self.spawn_service.create_spawn(
            parent_id,
            parent_token,
            SpawnCreate(
                operation_key=f"demo-{operation}",
                role=role,
                instruction={"scenario_step": operation},
                capabilities=capabilities,
            ),
        )
        return await self.spawn_service.activate(
            spawned.child_node_id,
            self._activation_request(
                spawned.activation_token,
                f"demo-{operation}-activation",
            ),
        )

    async def _check_snapshot(
        self,
        run_id: str,
        action_ids: list[str],
    ) -> dict[str, object]:
        return {
            "run_id": run_id,
            "graph": (await self.graph_service.get_graph(run_id)).model_dump(
                mode="json"
            ),
            "events": await self.state_service.list_events(
                run_id, after=0, limit=500
            ),
            "services": await self.state_service.list_states(run_id),
            "actions": [
                await self.state_service.get_action(run_id, action_id)
                for action_id in action_ids
            ],
        }

    @staticmethod
    def _check_result(
        scenario: str,
        snapshot: dict[str, object],
        *,
        expected: str,
    ) -> dict[str, object]:
        return {
            "scenario": scenario,
            "status": "PASS",
            "expected": expected,
            **snapshot,
        }

    async def get(self, session_id: str) -> dict[str, object]:
        return await self._snapshot(self._get(session_id))

    async def list_sessions(self) -> list[dict[str, object]]:
        with self._state_lock:
            sessions = list(self._sessions.values())
        return [
            {
                "session_id": session.id,
                "run_id": session.run_id,
                "scenario": _CANONICAL_SCENARIO,
                "phase": session.phase,
            }
            for session in reversed(sessions)
        ]

    async def reset(self, session_id: str) -> dict[str, object]:
        with self._state_lock:
            demo = self._sessions.pop(session_id, None)
        if demo is None:
            raise NotFoundError(f"Demo session {session_id} was not found")
        demo.worker.terminate()
        if demo.heartbeat_manager is not None:
            demo.heartbeat_manager.close()
        return {
            "reset": True,
            "session_id": session_id,
            "run_id": demo.run_id,
        }

    async def close(self) -> None:
        with self._state_lock:
            sessions = list(self._sessions.values())
            lease_checks = list(self._lease_checks.values())
            self._sessions.clear()
            self._lease_checks.clear()
        for session in sessions:
            session.worker.terminate()
            if session.heartbeat_manager is not None:
                session.heartbeat_manager.close()
        for check in lease_checks:
            if check.heartbeat_manager is not None:
                check.heartbeat_manager.close()

    @staticmethod
    def _activation_request(token: str, operation_key: str) -> NodeActivate:
        return NodeActivate(
            operation_key=operation_key,
            activation_token=token,
            process_id=os.getpid(),
        )

    def _get(self, session_id: str) -> _DemoSession:
        with self._state_lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise NotFoundError(f"Demo session {session_id} was not found")
        return session

    @staticmethod
    def _require_phase(session: _DemoSession, expected: str) -> None:
        if session.phase != expected:
            raise ConflictError(
                f"Demo transition requires {expected}; current phase is {session.phase}",
                code="DEMO_INVALID_TRANSITION",
            )

    def _action_by_key(self, node_id: str, idempotency_key: str) -> ActionAttempt:
        with self.session_factory() as session:
            attempt = session.execute(
                select(ActionAttempt).where(
                    ActionAttempt.node_id == node_id,
                    ActionAttempt.idempotency_key == idempotency_key,
                )
            ).scalar_one_or_none()
            if attempt is None:
                raise RuntimeError("Demo worker returned without a persisted action")
            session.expunge(attempt)
            return cast(ActionAttempt, attempt)

    async def _snapshot(self, demo: _DemoSession) -> dict[str, object]:
        graph = await self.graph_service.get_graph(demo.run_id)
        services = await self.state_service.list_states(demo.run_id)
        events = await self.state_service.list_events(
            demo.run_id,
            after=0,
            limit=500,
        )
        stale_action = (
            await self.state_service.get_action(demo.run_id, demo.stale_action_id)
            if demo.stale_action_id is not None
            else None
        )
        replacement_action = (
            await self.state_service.get_action(
                demo.run_id, demo.replacement_action_id
            )
            if demo.replacement_action_id is not None
            else None
        )
        return {
            "session_id": demo.id,
            "scenario": _CANONICAL_SCENARIO,
            "phase": demo.phase,
            "run_id": demo.run_id,
            "root_node_id": demo.root_node_id,
            "database_node_id": demo.database_node_id,
            "stale_worker_node_id": demo.stale_worker_node_id,
            "sibling_node_id": demo.sibling_node_id,
            "command_id": demo.command_id,
            "replacement_node_id": demo.replacement_node_id,
            "scope_from_version": demo.scope_from_version,
            "scope_to_version": demo.scope_to_version,
            "allowed_transitions": self._allowed_transitions(demo.phase),
            "graph": graph.model_dump(mode="json"),
            "events": events,
            "services": services,
            "stale_action": stale_action,
            "replacement_action": replacement_action,
            "proof": demo.proof,
        }

    @staticmethod
    def _allowed_transitions(phase: str) -> list[str]:
        return {
            "WAITING_STALE_WORKER": ["SUPERSEDE"],
            "SUPERSEDED": ["RELEASE_STALE_WORKER"],
            "STALE_DENIED": ["RUN_REPLACEMENT"],
            "RECOVERY_COMMITTED": ["BUILD_PROOF"],
            "PROOF_AVAILABLE": [],
        }.get(phase, [])

    @staticmethod
    def _service(snapshot: dict[str, object], name: str) -> dict[str, object]:
        services = snapshot["services"]
        if not isinstance(services, list):
            raise RuntimeError("Demo service projection is malformed")
        for item in services:
            if isinstance(item, dict) and item.get("service_name") == name:
                return item
        raise RuntimeError(f"Demo service state {name} is missing")

    async def _start_subprocess_worker(
        self,
        node_id: str,
        activation_token: str,
        idempotency_key: str,
    ) -> DemoWorkerHandle:
        api_url = os.getenv("TRACEFENCE_DEMO_API_URL", "http://127.0.0.1:9000")
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(_REPO_ROOT / "src")
        environment["OTEL_SDK_DISABLED"] = "true"
        environment["OTEL_EXPORTER_OTLP_ENDPOINT"] = ""
        environment.pop("OTEL_EXPORTER_OTLP_HEADERS", None)
        environment.pop("SIGNOZ_API_KEY", None)
        environment.pop("TRACEFENCE_NOTIFICATION_CHANNEL", None)
        process = await asyncio.to_thread(
            subprocess.Popen,
            [
                sys.executable,
                "-m",
                "tracefence.runtime.demo_worker",
                "--api-url",
                api_url,
                "--node-id",
                node_id,
                "--mode",
                "non_compliant_action",
                "--http-timeout",
                "2",
                "--tool",
                "restart_postgres",
                "--idempotency-key",
                idempotency_key,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            cwd=_REPO_ROOT,
            env=environment,
        )
        if process.stdin is None:
            process.terminate()
            raise RuntimeError("Demo worker startup pipe was not created")
        process.stdin.write(json.dumps({"node_token": activation_token}) + "\n")
        process.stdin.flush()

        deadline = time.monotonic() + _WORKER_START_DEADLINE_SECONDS
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _stdout, stderr = process.communicate()
                raise RuntimeError(
                    "Demo worker exited before its checkpoint: "
                    f"exit={process.returncode}; stderr={stderr[-500:]}"
                )
            with self.session_factory() as session:
                node = session.get(Node, node_id)
                if node is not None and node.status == NodeStatus.WAITING:
                    return _SubprocessWorker(process)
            await asyncio.sleep(0.02)

        process.terminate()
        process.wait(timeout=3)
        raise RuntimeError("Demo worker did not reach its explicit checkpoint")
