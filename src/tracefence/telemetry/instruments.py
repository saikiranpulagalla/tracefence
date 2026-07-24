from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock

from opentelemetry import metrics, trace
from opentelemetry.metrics import Observation


@dataclass(frozen=True, slots=True)
class GaugeSnapshot:
    active_nodes: int = 0
    live_affected_nodes: int = 0
    unacknowledged_live_nodes: int = 0
    orphan_nodes: int = 0
    telemetry_outbox_pending: int = 0
    stale_violation_latched: int = 0
    telemetry_delivery_last_success_unixtime: int = 0


_gauge_lock = Lock()
_gauge_snapshot = GaugeSnapshot()


def gauge_snapshot() -> GaugeSnapshot:
    with _gauge_lock:
        return _gauge_snapshot


def update_runtime_gauges(
    *,
    active_nodes: int,
    live_affected_nodes: int,
    unacknowledged_live_nodes: int,
    orphan_nodes: int,
) -> None:
    global _gauge_snapshot
    with _gauge_lock:
        _gauge_snapshot = GaugeSnapshot(
            active_nodes=active_nodes,
            live_affected_nodes=live_affected_nodes,
            unacknowledged_live_nodes=unacknowledged_live_nodes,
            orphan_nodes=orphan_nodes,
            telemetry_outbox_pending=_gauge_snapshot.telemetry_outbox_pending,
            stale_violation_latched=_gauge_snapshot.stale_violation_latched,
            telemetry_delivery_last_success_unixtime=(
                _gauge_snapshot.telemetry_delivery_last_success_unixtime
            ),
        )


def update_outbox_gauge(pending: int) -> None:
    global _gauge_snapshot
    with _gauge_lock:
        _gauge_snapshot = GaugeSnapshot(
            active_nodes=_gauge_snapshot.active_nodes,
            live_affected_nodes=_gauge_snapshot.live_affected_nodes,
            unacknowledged_live_nodes=_gauge_snapshot.unacknowledged_live_nodes,
            orphan_nodes=_gauge_snapshot.orphan_nodes,
            telemetry_outbox_pending=max(0, pending),
            stale_violation_latched=_gauge_snapshot.stale_violation_latched,
            telemetry_delivery_last_success_unixtime=(
                _gauge_snapshot.telemetry_delivery_last_success_unixtime
            ),
        )


def update_stale_violation_gauge(count: int) -> None:
    global _gauge_snapshot
    with _gauge_lock:
        _gauge_snapshot = GaugeSnapshot(
            active_nodes=_gauge_snapshot.active_nodes,
            live_affected_nodes=_gauge_snapshot.live_affected_nodes,
            unacknowledged_live_nodes=_gauge_snapshot.unacknowledged_live_nodes,
            orphan_nodes=_gauge_snapshot.orphan_nodes,
            telemetry_outbox_pending=_gauge_snapshot.telemetry_outbox_pending,
            stale_violation_latched=max(
                _gauge_snapshot.stale_violation_latched,
                int(count > 0),
            ),
            telemetry_delivery_last_success_unixtime=(
                _gauge_snapshot.telemetry_delivery_last_success_unixtime
            ),
        )


def update_telemetry_delivery_success(timestamp: int) -> None:
    global _gauge_snapshot
    with _gauge_lock:
        _gauge_snapshot = GaugeSnapshot(
            active_nodes=_gauge_snapshot.active_nodes,
            live_affected_nodes=_gauge_snapshot.live_affected_nodes,
            unacknowledged_live_nodes=_gauge_snapshot.unacknowledged_live_nodes,
            orphan_nodes=_gauge_snapshot.orphan_nodes,
            telemetry_outbox_pending=_gauge_snapshot.telemetry_outbox_pending,
            stale_violation_latched=_gauge_snapshot.stale_violation_latched,
            telemetry_delivery_last_success_unixtime=max(0, timestamp),
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
    exporter_failures_total: metrics.Counter
    proof_inconsistent_total: metrics.Counter
    recovery_postcondition_failures_total: metrics.Counter
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
    meter.create_observable_gauge(
        "tracefence_stale_violation_latched",
        callbacks=[_observe("stale_violation_latched")],
        description="Latched process gauge backed by persistent stale-commit violations",
    )
    meter.create_observable_gauge(
        "tracefence_telemetry_delivery_last_success_unixtime",
        callbacks=[_observe("telemetry_delivery_last_success_unixtime")],
        description="Last confirmed outbox delivery time for external dead-man monitoring",
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
        exporter_failures_total=meter.create_counter(
            "tracefence_exporter_failures_total"
        ),
        proof_inconsistent_total=meter.create_counter(
            "tracefence_proof_inconsistent_total"
        ),
        recovery_postcondition_failures_total=meter.create_counter(
            "tracefence_recovery_postcondition_failures_total"
        ),
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
