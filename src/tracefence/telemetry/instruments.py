from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock

from opentelemetry import metrics, trace
from opentelemetry.metrics import Observation

from tracefence.telemetry.schema import (
    METRIC_ACTION_ATTEMPTS_TOTAL,
    METRIC_ACTION_GATEWAY_DURATION_MS,
    METRIC_ACTIONS_ALLOWED_TOTAL,
    METRIC_ACTIONS_DENIED_TOTAL,
    METRIC_ACTIVE_NODES,
    METRIC_CONTROL_ACK_LATENCY_MS,
    METRIC_CONTROL_COMMANDS_TOTAL,
    METRIC_EXPORTER_FAILURES_TOTAL,
    METRIC_LEASES_EXPIRED_TOTAL,
    METRIC_LIVE_AFFECTED_NODES,
    METRIC_NODES_SPAWNED_TOTAL,
    METRIC_ORPHAN_NODES,
    METRIC_PROOF_GENERATION_DURATION_MS,
    METRIC_PROOF_INCONSISTENT_TOTAL,
    METRIC_RECOVERY_POSTCONDITION_FAILURES_TOTAL,
    METRIC_RUNS_TOTAL,
    METRIC_SCOPE_VALIDATION_DURATION_MS,
    METRIC_STALE_ACTION_ATTEMPTS_TOTAL,
    METRIC_STALE_ACTIONS_COMMITTED_TOTAL,
    METRIC_STALE_VIOLATION_LATCHED,
    METRIC_TELEMETRY_DELIVERY_LAST_SUCCESS_UNIXTIME,
    METRIC_TELEMETRY_OUTBOX_PENDING,
    METRIC_UNACKNOWLEDGED_LIVE_NODES,
)


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
        METRIC_ACTIVE_NODES.name,
        callbacks=[_observe("active_nodes")],
        description="Registered nodes with live leases and active inherited scopes",
    )
    meter.create_observable_gauge(
        METRIC_LIVE_AFFECTED_NODES.name,
        callbacks=[_observe("live_affected_nodes")],
        description="Live nodes affected by a control command",
    )
    meter.create_observable_gauge(
        METRIC_UNACKNOWLEDGED_LIVE_NODES.name,
        callbacks=[_observe("unacknowledged_live_nodes")],
        description="Live affected nodes without a convergence classification",
    )
    meter.create_observable_gauge(
        METRIC_ORPHAN_NODES.name,
        callbacks=[_observe("orphan_nodes")],
        description="Live stale nodes that have not acknowledged or been blocked",
    )
    meter.create_observable_gauge(
        METRIC_TELEMETRY_OUTBOX_PENDING.name,
        callbacks=[_observe("telemetry_outbox_pending")],
        description="Durable safety telemetry events awaiting confirmed export",
    )
    meter.create_observable_gauge(
        METRIC_STALE_VIOLATION_LATCHED.name,
        callbacks=[_observe("stale_violation_latched")],
        description="Latched process gauge backed by persistent stale-commit violations",
    )
    meter.create_observable_gauge(
        METRIC_TELEMETRY_DELIVERY_LAST_SUCCESS_UNIXTIME.name,
        callbacks=[_observe("telemetry_delivery_last_success_unixtime")],
        description="Last confirmed outbox delivery time for external dead-man monitoring",
    )
    return Telemetry(
        tracer=trace.get_tracer("tracefence"),
        runs_total=meter.create_counter(METRIC_RUNS_TOTAL.name),
        nodes_spawned_total=meter.create_counter(METRIC_NODES_SPAWNED_TOTAL.name),
        commands_total=meter.create_counter(METRIC_CONTROL_COMMANDS_TOTAL.name),
        action_attempts_total=meter.create_counter(METRIC_ACTION_ATTEMPTS_TOTAL.name),
        actions_allowed_total=meter.create_counter(METRIC_ACTIONS_ALLOWED_TOTAL.name),
        actions_denied_total=meter.create_counter(METRIC_ACTIONS_DENIED_TOTAL.name),
        stale_attempts_total=meter.create_counter(METRIC_STALE_ACTION_ATTEMPTS_TOTAL.name),
        stale_committed_total=meter.create_counter(METRIC_STALE_ACTIONS_COMMITTED_TOTAL.name),
        exporter_failures_total=meter.create_counter(METRIC_EXPORTER_FAILURES_TOTAL.name),
        proof_inconsistent_total=meter.create_counter(METRIC_PROOF_INCONSISTENT_TOTAL.name),
        recovery_postcondition_failures_total=meter.create_counter(
            METRIC_RECOVERY_POSTCONDITION_FAILURES_TOTAL.name
        ),
        leases_expired_total=meter.create_counter(METRIC_LEASES_EXPIRED_TOTAL.name),
        action_gateway_duration_ms=meter.create_histogram(
            METRIC_ACTION_GATEWAY_DURATION_MS.name, unit="ms"
        ),
        scope_validation_duration_ms=meter.create_histogram(
            METRIC_SCOPE_VALIDATION_DURATION_MS.name, unit="ms"
        ),
        control_ack_latency_ms=meter.create_histogram(
            METRIC_CONTROL_ACK_LATENCY_MS.name, unit="ms"
        ),
        proof_duration_ms=meter.create_histogram(
            METRIC_PROOF_GENERATION_DURATION_MS.name, unit="ms"
        ),
    )


telemetry = build_telemetry()
