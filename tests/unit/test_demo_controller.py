from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from tracefence.db.models import Node
from tracefence.domain.enums import NodeStatus, ProofVerdict, RunStatus
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.domain.schemas import ActionExecute
from tracefence.services import demo_controller
from tracefence.services.action_gateway import ActionGateway
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.demo_controller import DemoController
from tracefence.services.graph_service import GraphService
from tracefence.services.proof_service import ProofService
from tracefence.services.run_service import RunService
from tracefence.services.spawn_service import SpawnService
from tracefence.services.state_service import StateService


@dataclass
class _InProcessWorker:
    gateway: ActionGateway
    node_id: str
    node_token: str
    idempotency_key: str

    async def release(self) -> None:
        await self.gateway.execute(
            self.node_id,
            self.node_token,
            ActionExecute(
                idempotency_key=self.idempotency_key,
                tool_name="restart_postgres",
                arguments={},
            ),
        )

    def terminate(self) -> None:
        return


class _CapturedStdin:
    def __init__(self) -> None:
        self.writes: list[str] = []

    def write(self, value: str) -> int:
        self.writes.append(value)
        return len(value)

    def flush(self) -> None:
        return


class _CapturedProcess:
    def __init__(self) -> None:
        self.stdin = _CapturedStdin()

    def poll(self) -> None:
        return None


class _WaitingSession:
    def __enter__(self) -> _WaitingSession:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None

    def get(self, model, node_id: str) -> SimpleNamespace:
        return SimpleNamespace(status=NodeStatus.WAITING)


async def test_subprocess_worker_launch_is_fixed_and_secret_aware(monkeypatch):
    captured: dict[str, object] = {}
    process = _CapturedProcess()

    async def capture_to_thread(function, *args, **kwargs):
        captured["function"] = function
        captured["args"] = args
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=secret")
    monkeypatch.setenv("SIGNOZ_API_KEY", "secret")
    monkeypatch.setenv("TRACEFENCE_NOTIFICATION_CHANNEL", "live-channel")
    monkeypatch.setattr(demo_controller.asyncio, "to_thread", capture_to_thread)
    controller = DemoController(
        lambda: _WaitingSession(),
        maintain_heartbeats=False,
    )

    activation_token = "worker-token-must-not-be-an-argument"
    await controller._start_subprocess_worker(
        "internally-created-node-id",
        activation_token,
        "internally-created-action-key",
    )

    assert captured["function"] is demo_controller.subprocess.Popen
    argv = captured["args"][0]
    assert isinstance(argv, list)
    assert argv[:3] == [sys.executable, "-m", "tracefence.runtime.demo_worker"]
    assert activation_token not in argv
    kwargs = captured["kwargs"]
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == demo_controller._REPO_ROOT
    environment = kwargs["env"]
    assert environment["OTEL_SDK_DISABLED"] == "true"
    assert environment["OTEL_EXPORTER_OTLP_ENDPOINT"] == ""
    assert "OTEL_EXPORTER_OTLP_HEADERS" not in environment
    assert "SIGNOZ_API_KEY" not in environment
    assert "TRACEFENCE_NOTIFICATION_CHANNEL" not in environment


async def test_canonical_demo_uses_real_authority_and_gateway(session_factory):
    spawns = SpawnService(session_factory)
    gateway = ActionGateway(session_factory)

    async def worker_factory(node_id: str, node_token: str, key: str):
        checkpoint = await spawns.checkpoint(
            node_id,
            node_token,
            "before_protected_action",
        )
        assert checkpoint.allowed is True
        return _InProcessWorker(
            gateway=gateway,
            node_id=node_id,
            node_token=node_token,
            idempotency_key=key,
        )

    controller = DemoController(
        session_factory,
        run_service=RunService(session_factory),
        spawn_service=spawns,
        control_service=ControlService(session_factory),
        action_gateway=gateway,
        graph_service=GraphService(session_factory),
        state_service=StateService(session_factory),
        proof_service=ProofService(session_factory),
        worker_factory=worker_factory,
        maintain_heartbeats=False,
    )

    started = await controller.start("stale-supersession")
    assert started["phase"] == "WAITING_STALE_WORKER"
    assert started["allowed_transitions"] == ["SUPERSEDE"]

    superseded = await controller.supersede(started["session_id"])
    assert superseded["phase"] == "SUPERSEDED"
    assert superseded["scope_from_version"] == 1
    assert superseded["scope_to_version"] == 2

    denied = await controller.release_stale_worker(started["session_id"])
    assert denied["phase"] == "STALE_DENIED"
    assert denied["stale_action"]["decision"] == "DENY"
    assert denied["stale_action"]["denial_reason"] == "SCOPE_SUPERSEDED"
    denied_event_types = [event["event_type"] for event in denied["events"]]
    assert "DEMO_WORKER_RELEASED" in denied_event_types
    assert denied_event_types.index("DEMO_WORKER_RELEASED") < denied_event_types.index("ACTION_DENIED")
    services = {item["service_name"]: item for item in denied["services"]}
    assert services["postgres"]["restart_count"] == 0

    recovered = await controller.run_replacement(started["session_id"])
    assert recovered["phase"] == "RECOVERY_COMMITTED"
    assert recovered["replacement_action"]["decision"] == "ALLOW"
    recovered_event_types = [event["event_type"] for event in recovered["events"]]
    assert "NODE_COMPLETED" in recovered_event_types
    assert "RECOVERY_COMPLETED" in recovered_event_types
    services = {item["service_name"]: item for item in recovered["services"]}
    assert services["redis"]["pool_reset_count"] == 1

    proven = await controller.build_proof(started["session_id"])
    assert proven["phase"] == "PROOF_AVAILABLE"
    assert proven["proof"]["runtime_verdict"] == ProofVerdict.VERIFIED
    assert proven["proof"]["telemetry_verdict"] == ProofVerdict.UNAVAILABLE
    assert proven["proof"]["overall_verdict"] == ProofVerdict.UNAVAILABLE
    assert proven["proof"]["stale_actions_committed"] == 0
    assert proven["proof"]["unrelated_branches_interrupted"] == 0


def _check_controller(session_factory) -> DemoController:
    return DemoController(
        session_factory,
        run_service=RunService(session_factory),
        spawn_service=SpawnService(session_factory),
        control_service=ControlService(session_factory),
        action_gateway=ActionGateway(session_factory),
        graph_service=GraphService(session_factory),
        state_service=StateService(session_factory),
        proof_service=ProofService(session_factory),
        maintain_heartbeats=False,
    )


@pytest.mark.parametrize(
    ("scenario", "decisions", "reason"),
    [
        ("cancellation", ["DENY"], "SCOPE_CANCELLED"),
        ("idempotent-retry", ["ALLOW"], None),
        ("recovery-manifest-mismatch", ["DENY", "ALLOW"], "RECOVERY_TOOL_MISMATCH"),
        ("sibling-isolation", ["DENY", "ALLOW"], "SCOPE_CANCELLED"),
        ("concurrent-stale-valid", ["DENY", "ALLOW"], "SCOPE_SUPERSEDED"),
    ],
)
async def test_fixed_adversarial_demo_checks_use_real_gateway(
    session_factory,
    scenario,
    decisions,
    reason,
):
    controller = _check_controller(session_factory)
    result = await controller.run_check(scenario)
    assert result["status"] == "PASS"
    assert [action["decision"] for action in result["actions"]] == decisions
    assert result["actions"][0]["denial_reason"] == reason
    assert result["graph"]["status"] == RunStatus.CANCELLED
    assert (await controller.list_checks())[0]["scenario"] == scenario


async def test_lease_expiry_check_refuses_early_release_and_uses_gateway(
    session_factory,
):
    controller = _check_controller(session_factory)
    waiting = await controller.run_check("lease-expiry")
    assert waiting["status"] == "WAITING_FOR_LEASE_EXPIRY"
    with pytest.raises(ConflictError) as early:
        await controller.finish_lease_expiry(waiting["check_id"])
    assert early.value.code == "DEMO_LEASE_STILL_LIVE"

    with session_factory() as session, session.begin():
        child = session.execute(
            select(Node).where(
                Node.run_id == waiting["run_id"],
                Node.role == "lease-expiry-worker",
            )
        ).scalar_one()
        child.lease_expires_at = utcnow() - timedelta(seconds=1)

    result = await controller.finish_lease_expiry(waiting["check_id"])
    assert result["status"] == "PASS"
    assert result["actions"][0]["decision"] == "DENY"
    assert result["actions"][0]["denial_reason"] == "LEASE_EXPIRED"
    services = {item["service_name"]: item for item in result["services"]}
    assert services["postgres"]["restart_count"] == 0


async def test_unknown_demo_check_is_rejected_without_a_run(session_factory):
    controller = _check_controller(session_factory)
    with pytest.raises(NotFoundError):
        await controller.run_check("arbitrary-tool")
    assert await controller.list_checks() == []


async def test_completed_demo_checks_do_not_exhaust_active_run_quota(
    session_factory,
):
    controller = _check_controller(session_factory)
    for _ in range(10):
        result = await controller.run_check("cancellation")
        assert result["graph"]["status"] == RunStatus.CANCELLED

    assert len(await controller.list_checks()) == 10


async def test_canonical_demo_heartbeat_cannot_mask_scope_supersession(
    session_factory,
):
    spawns = SpawnService(session_factory)
    gateway = ActionGateway(session_factory)

    async def worker_factory(node_id: str, node_token: str, key: str):
        checkpoint = await spawns.checkpoint(
            node_id,
            node_token,
            "before_protected_action",
        )
        assert checkpoint.allowed is True
        return _InProcessWorker(
            gateway=gateway,
            node_id=node_id,
            node_token=node_token,
            idempotency_key=key,
        )

    controller = DemoController(
        session_factory,
        run_service=RunService(session_factory),
        spawn_service=spawns,
        control_service=ControlService(session_factory),
        action_gateway=gateway,
        graph_service=GraphService(session_factory),
        state_service=StateService(session_factory),
        proof_service=ProofService(session_factory),
        worker_factory=worker_factory,
        maintain_heartbeats=True,
    )
    try:
        started = await controller.start("stale-supersession")
        await controller.supersede(started["session_id"])
        denied = await controller.release_stale_worker(started["session_id"])
    finally:
        await controller.close()

    assert denied["stale_action"]["decision"] == "DENY"
