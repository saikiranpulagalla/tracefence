from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock

from opentelemetry import metrics, trace
from opentelemetry.metrics import Observation


@dataclass(frozen=True, slots=True)
class _GaugeSnapshot:
    active_nodes: int = 0
    live_affected_nodes: int = 0
    unacknowledged_live_nodes: int = 0
    orphan_nodes: int = 0
    telemetry_outbox_pending: int = 0


_gauge_lock = Lock()
_gauge_snapshot = _GaugeSnapshot()


def update_runtime_gauges(
    *,
    active_nodes: int,
    live_affected_nodes: int,
    unacknowledged_live_nodes: int,
    orphan_nodes: int,
) -> None:
    global _gauge_snapshot
    with _gauge_lock:
        _gauge_snapshot = _GaugeSnapshot(
            active_nodes=active_nodes,
            live_affected_nodes=live_affected_nodes,
            unacknowledged_live_nodes=unacknowledged_live_nodes,
            orphan_nodes=orphan_nodes,
            telemetry_outbox_pending=_gauge_snapshot.telemetry_outbox_pending,
        )


def update_outbox_gauge(pending: int) -> None:
    global _gauge_snapshot
    with _gauge_lock:
        _gauge_snapshot = _GaugeSnapshot(
            active_nodes=_gauge_snapshot.active_nodes,
            live_affected_nodes=_gauge_snapshot.live_affected_nodes,
            unacknowledged_live_nodes=_gauge_snapshot.unacknowledged_live_nodes,
            orphan_nodes=_gauge_snapshot.orphan_nodes,
            telemetry_outbox_pending=max(0, pending),
        )


def _observe(field: str) -> Callable[[object], list[Observation]]:
    def callback(_options: object) -> list[Observation]:
        with _gauge_lock:
            value = getattr(_gauge_snapshot, field)
        return [Observation(value)]

    return callback


@dataclass(frozen=True, slots=True)
class Telemetry:
    tracer: trace.Tracer
    runs_total: metrics.Counter
    nodes_spawned_total: metrics.Counter
    commands_total: metrics.Counter
    action_attempts_total: metrics.Counter
    actions_allowed_total: metrics.Counter
    actions_denied_total: metrics.Counter
    stale_attempts_total: metrics.Counter
    stale_committed_total: metrics.Counter
    leases_expired_total: metrics.Counter
    action_gateway_duration_ms: metrics.Histogram
    scope_validation_duration_ms: metrics.Histogram
    control_ack_latency_ms: metrics.Histogram
    proof_duration_ms: metrics.Histogram


def build_telemetry() -> Telemetry:
    meter = metrics.get_meter("tracefence")
    meter.create_observable_gauge(
        "tracefence_active_nodes",
        callbacks=[_observe("active_nodes")],
        description="Registered nodes with live leases and active inherited scopes",
    )
    meter.create_observable_gauge(
        "tracefence_live_affected_nodes",
        callbacks=[_observe("live_affected_nodes")],
        description="Live nodes affected by a control command",
    )
    meter.create_observable_gauge(
        "tracefence_unacknowledged_live_nodes",
        callbacks=[_observe("unacknowledged_live_nodes")],
        description="Live affected nodes without a convergence classification",
    )
    meter.create_observable_gauge(
        "tracefence_orphan_nodes",
        callbacks=[_observe("orphan_nodes")],
        description="Live stale nodes that have not acknowledged or been blocked",
    )
    meter.create_observable_gauge(
        "tracefence_telemetry_outbox_pending",
        callbacks=[_observe("telemetry_outbox_pending")],
        description="Durable safety telemetry events awaiting confirmed export",
    )
    return Telemetry(
        tracer=trace.get_tracer("tracefence"),
        runs_total=meter.create_counter("tracefence_runs_total"),
        nodes_spawned_total=meter.create_counter("tracefence_nodes_spawned_total"),
        commands_total=meter.create_counter("tracefence_control_commands_total"),
        action_attempts_total=meter.create_counter("tracefence_action_attempts_total"),
        actions_allowed_total=meter.create_counter("tracefence_actions_allowed_total"),
        actions_denied_total=meter.create_counter("tracefence_actions_denied_total"),
        stale_attempts_total=meter.create_counter("tracefence_stale_action_attempts_total"),
        stale_committed_total=meter.create_counter("tracefence_stale_actions_committed_total"),
        leases_expired_total=meter.create_counter("tracefence_leases_expired_total"),
        action_gateway_duration_ms=meter.create_histogram(
            "tracefence_action_gateway_duration_ms", unit="ms"
        ),
        scope_validation_duration_ms=meter.create_histogram(
            "tracefence_scope_validation_duration_ms", unit="ms"
        ),
        control_ack_latency_ms=meter.create_histogram(
            "tracefence_control_ack_latency_ms", unit="ms"
        ),
        proof_duration_ms=meter.create_histogram(
            "tracefence_proof_generation_duration_ms", unit="ms"
        ),
    )


telemetry = build_telemetry()
