from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class MetricInstrumentKind(StrEnum):
    OBSERVABLE_GAUGE = "observable_gauge"
    COUNTER = "counter"
    HISTOGRAM = "histogram"


class MetricDiscoveryPolicy(StrEnum):
    STARTUP_REQUIRED = "startup_required"
    EVENT_DRIVEN = "event_driven"
    FAILURE_ONLY = "failure_only"


class MetricDiscoveryError(RuntimeError):
    """A bounded live metric-discovery operation could not complete safely."""


@dataclass(frozen=True, slots=True)
class MetricDefinition:
    name: str
    instrument_kind: MetricInstrumentKind
    discovery_policy: MetricDiscoveryPolicy
    time_aggregations: frozenset[str]
    space_aggregations: frozenset[str]


_GAUGE_TIME_AGGREGATIONS = frozenset({"latest", "last"})
_GAUGE_SPACE_AGGREGATIONS = frozenset({"latest", "last", "max"})
_COUNTER_TIME_AGGREGATIONS = frozenset({"increase", "rate"})
_COUNTER_SPACE_AGGREGATIONS = frozenset({"sum"})
_HISTOGRAM_AGGREGATIONS = frozenset(
    {"avg", "average", "p50", "p75", "p90", "p95", "p99"}
)


def _metric(
    name: str,
    instrument_kind: MetricInstrumentKind,
    discovery_policy: MetricDiscoveryPolicy,
    time_aggregations: frozenset[str],
    space_aggregations: frozenset[str],
) -> MetricDefinition:
    return MetricDefinition(
        name=name,
        instrument_kind=instrument_kind,
        discovery_policy=discovery_policy,
        time_aggregations=time_aggregations,
        space_aggregations=space_aggregations,
    )


METRIC_ACTIVE_NODES = _metric(
    "tracefence_active_nodes",
    MetricInstrumentKind.OBSERVABLE_GAUGE,
    MetricDiscoveryPolicy.STARTUP_REQUIRED,
    _GAUGE_TIME_AGGREGATIONS,
    _GAUGE_SPACE_AGGREGATIONS,
)
METRIC_LIVE_AFFECTED_NODES = _metric(
    "tracefence_live_affected_nodes",
    MetricInstrumentKind.OBSERVABLE_GAUGE,
    MetricDiscoveryPolicy.STARTUP_REQUIRED,
    _GAUGE_TIME_AGGREGATIONS,
    _GAUGE_SPACE_AGGREGATIONS,
)
METRIC_UNACKNOWLEDGED_LIVE_NODES = _metric(
    "tracefence_unacknowledged_live_nodes",
    MetricInstrumentKind.OBSERVABLE_GAUGE,
    MetricDiscoveryPolicy.STARTUP_REQUIRED,
    _GAUGE_TIME_AGGREGATIONS,
    _GAUGE_SPACE_AGGREGATIONS,
)
METRIC_ORPHAN_NODES = _metric(
    "tracefence_orphan_nodes",
    MetricInstrumentKind.OBSERVABLE_GAUGE,
    MetricDiscoveryPolicy.STARTUP_REQUIRED,
    _GAUGE_TIME_AGGREGATIONS,
    _GAUGE_SPACE_AGGREGATIONS,
)
METRIC_TELEMETRY_OUTBOX_PENDING = _metric(
    "tracefence_telemetry_outbox_pending",
    MetricInstrumentKind.OBSERVABLE_GAUGE,
    MetricDiscoveryPolicy.STARTUP_REQUIRED,
    _GAUGE_TIME_AGGREGATIONS,
    _GAUGE_SPACE_AGGREGATIONS,
)
METRIC_STALE_VIOLATION_LATCHED = _metric(
    "tracefence_stale_violation_latched",
    MetricInstrumentKind.OBSERVABLE_GAUGE,
    MetricDiscoveryPolicy.STARTUP_REQUIRED,
    _GAUGE_TIME_AGGREGATIONS,
    _GAUGE_SPACE_AGGREGATIONS,
)
METRIC_TELEMETRY_DELIVERY_LAST_SUCCESS_UNIXTIME = _metric(
    "tracefence_telemetry_delivery_last_success_unixtime",
    MetricInstrumentKind.OBSERVABLE_GAUGE,
    MetricDiscoveryPolicy.STARTUP_REQUIRED,
    _GAUGE_TIME_AGGREGATIONS,
    _GAUGE_SPACE_AGGREGATIONS,
)
METRIC_RUNS_TOTAL = _metric(
    "tracefence_runs_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_NODES_SPAWNED_TOTAL = _metric(
    "tracefence_nodes_spawned_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_CONTROL_COMMANDS_TOTAL = _metric(
    "tracefence_control_commands_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_ACTION_ATTEMPTS_TOTAL = _metric(
    "tracefence_action_attempts_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_ACTIONS_ALLOWED_TOTAL = _metric(
    "tracefence_actions_allowed_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_ACTIONS_DENIED_TOTAL = _metric(
    "tracefence_actions_denied_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_STALE_ACTION_ATTEMPTS_TOTAL = _metric(
    "tracefence_stale_action_attempts_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_LEASES_EXPIRED_TOTAL = _metric(
    "tracefence_leases_expired_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_ACTION_GATEWAY_DURATION_MS = _metric(
    "tracefence_action_gateway_duration_ms",
    MetricInstrumentKind.HISTOGRAM,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _HISTOGRAM_AGGREGATIONS,
    _HISTOGRAM_AGGREGATIONS,
)
METRIC_SCOPE_VALIDATION_DURATION_MS = _metric(
    "tracefence_scope_validation_duration_ms",
    MetricInstrumentKind.HISTOGRAM,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _HISTOGRAM_AGGREGATIONS,
    _HISTOGRAM_AGGREGATIONS,
)
METRIC_CONTROL_ACK_LATENCY_MS = _metric(
    "tracefence_control_ack_latency_ms",
    MetricInstrumentKind.HISTOGRAM,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _HISTOGRAM_AGGREGATIONS,
    _HISTOGRAM_AGGREGATIONS,
)
METRIC_PROOF_GENERATION_DURATION_MS = _metric(
    "tracefence_proof_generation_duration_ms",
    MetricInstrumentKind.HISTOGRAM,
    MetricDiscoveryPolicy.EVENT_DRIVEN,
    _HISTOGRAM_AGGREGATIONS,
    _HISTOGRAM_AGGREGATIONS,
)
METRIC_STALE_ACTIONS_COMMITTED_TOTAL = _metric(
    "tracefence_stale_actions_committed_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.FAILURE_ONLY,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_EXPORTER_FAILURES_TOTAL = _metric(
    "tracefence_exporter_failures_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.FAILURE_ONLY,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_PROOF_INCONSISTENT_TOTAL = _metric(
    "tracefence_proof_inconsistent_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.FAILURE_ONLY,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)
METRIC_RECOVERY_POSTCONDITION_FAILURES_TOTAL = _metric(
    "tracefence_recovery_postcondition_failures_total",
    MetricInstrumentKind.COUNTER,
    MetricDiscoveryPolicy.FAILURE_ONLY,
    _COUNTER_TIME_AGGREGATIONS,
    _COUNTER_SPACE_AGGREGATIONS,
)

METRIC_CATALOG = (
    METRIC_ACTIVE_NODES,
    METRIC_LIVE_AFFECTED_NODES,
    METRIC_UNACKNOWLEDGED_LIVE_NODES,
    METRIC_ORPHAN_NODES,
    METRIC_TELEMETRY_OUTBOX_PENDING,
    METRIC_STALE_VIOLATION_LATCHED,
    METRIC_TELEMETRY_DELIVERY_LAST_SUCCESS_UNIXTIME,
    METRIC_RUNS_TOTAL,
    METRIC_NODES_SPAWNED_TOTAL,
    METRIC_CONTROL_COMMANDS_TOTAL,
    METRIC_ACTION_ATTEMPTS_TOTAL,
    METRIC_ACTIONS_ALLOWED_TOTAL,
    METRIC_ACTIONS_DENIED_TOTAL,
    METRIC_STALE_ACTION_ATTEMPTS_TOTAL,
    METRIC_LEASES_EXPIRED_TOTAL,
    METRIC_ACTION_GATEWAY_DURATION_MS,
    METRIC_SCOPE_VALIDATION_DURATION_MS,
    METRIC_CONTROL_ACK_LATENCY_MS,
    METRIC_PROOF_GENERATION_DURATION_MS,
    METRIC_STALE_ACTIONS_COMMITTED_TOTAL,
    METRIC_EXPORTER_FAILURES_TOTAL,
    METRIC_PROOF_INCONSISTENT_TOTAL,
    METRIC_RECOVERY_POSTCONDITION_FAILURES_TOTAL,
)

_metric_mapping = {metric.name: metric for metric in METRIC_CATALOG}
if len(_metric_mapping) != len(METRIC_CATALOG):
    raise RuntimeError("TraceFence metric catalog contains duplicate names")
METRICS_BY_NAME = MappingProxyType(_metric_mapping)


@dataclass(frozen=True, slots=True)
class MetricReference:
    name: str
    time_aggregation: str | None
    space_aggregation: str | None
    metric_type: str | None = None
    is_monotonic: bool | None = None
    temporality: str | None = None


@dataclass(frozen=True, slots=True)
class MetricDiscoveryObservation:
    observed_metric_names: frozenset[str]
    live_metric_query_succeeded: bool


@dataclass(frozen=True, slots=True)
class MetricPreflight:
    metric_catalog_digest: str
    referenced_metrics: tuple[str, ...]
    observed_metrics: tuple[str, ...]
    startup_required_metrics: tuple[str, ...]
    startup_required_missing: tuple[str, ...]
    event_driven_not_yet_observed: tuple[str, ...]
    failure_only_not_yet_observed: tuple[str, ...]
    catalog_startup_required_metrics: tuple[str, ...]
    catalog_startup_required_not_yet_observed: tuple[str, ...]
    live_metric_query_succeeded: bool

    def as_evidence(self) -> dict[str, object]:
        return {
            "metric_catalog_digest": self.metric_catalog_digest,
            "referenced_metrics": list(self.referenced_metrics),
            "observed_metrics": list(self.observed_metrics),
            "startup_required_metrics": list(self.startup_required_metrics),
            "startup_required_missing": list(self.startup_required_missing),
            "event_driven_not_yet_observed": list(self.event_driven_not_yet_observed),
            "failure_only_not_yet_observed": list(self.failure_only_not_yet_observed),
            "catalog_startup_required_metrics": list(self.catalog_startup_required_metrics),
            "catalog_startup_required_not_yet_observed": list(
                self.catalog_startup_required_not_yet_observed
            ),
            "live_metric_query_succeeded": self.live_metric_query_succeeded,
        }


def metric_catalog_digest() -> str:
    payload = [
        {
            "name": metric.name,
            "instrument_kind": metric.instrument_kind.value,
            "discovery_policy": metric.discovery_policy.value,
            "time_aggregations": sorted(metric.time_aggregations),
            "space_aggregations": sorted(metric.space_aggregations),
        }
        for metric in METRIC_CATALOG
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def extract_metric_references(*documents: object) -> tuple[MetricReference, ...]:
    references: list[MetricReference] = []

    def walk(value: object) -> None:
        if isinstance(value, dict):
            if "metricName" in value:
                metric_name = value.get("metricName")
                references.append(
                    MetricReference(
                        name=metric_name if isinstance(metric_name, str) else "",
                        time_aggregation=value.get("timeAggregation"),
                        space_aggregation=value.get("spaceAggregation"),
                        metric_type=value.get("metricType"),
                        is_monotonic=value.get("isMonotonic"),
                        temporality=value.get("temporality"),
                    )
                )
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    for document in documents:
        walk(document)
    return tuple(references)


def validate_metric_references(references: Sequence[MetricReference]) -> None:
    seen: dict[str, tuple[str, str, str | None, bool | None, str | None]] = {}
    for reference in references:
        metric = METRICS_BY_NAME.get(reference.name)
        if metric is None:
            raise ValueError(f"Unknown TraceFence metric: {reference.name!r}")
        time_aggregation = _validated_aggregation(
            reference.name,
            "time",
            reference.time_aggregation,
            metric.time_aggregations,
        )
        space_aggregation = _validated_aggregation(
            reference.name,
            "space",
            reference.space_aggregation,
            metric.space_aggregations,
        )
        metadata = _validated_optional_metadata(reference, metric)
        current = (time_aggregation, space_aggregation, *metadata)
        existing = seen.get(reference.name)
        if existing is None:
            seen[reference.name] = current
            continue
        if existing[:2] != current[:2] or any(
            old is not None and new is not None and old != new
            for old, new in zip(existing[2:], current[2:], strict=True)
        ):
            raise ValueError(
                f"TraceFence metric {reference.name!r} has contradictory aggregation definitions"
            )
        seen[reference.name] = (
            existing[0],
            existing[1],
            existing[2] if existing[2] is not None else current[2],
            existing[3] if existing[3] is not None else current[3],
            existing[4] if existing[4] is not None else current[4],
        )


def _validated_aggregation(
    metric_name: str,
    dimension: str,
    aggregation: str | None,
    allowed: frozenset[str],
) -> str:
    if not isinstance(aggregation, str) or aggregation not in allowed:
        rendered = aggregation if isinstance(aggregation, str) else "<missing>"
        raise ValueError(
            f"TraceFence metric {metric_name!r} does not support {dimension} aggregation "
            f"{rendered!r}"
        )
    return aggregation


def _validated_optional_metadata(
    reference: MetricReference,
    metric: MetricDefinition,
) -> tuple[str | None, bool | None, str | None]:
    metric_type: str | None = None
    if reference.metric_type is not None:
        if not isinstance(reference.metric_type, str):
            raise ValueError(f"TraceFence metric {reference.name!r} has an invalid metric type")
        metric_type = reference.metric_type.casefold()
        expected_types = {
            MetricInstrumentKind.OBSERVABLE_GAUGE: {"gauge"},
            MetricInstrumentKind.COUNTER: {"sum"},
            MetricInstrumentKind.HISTOGRAM: {"histogram", "exponential_histogram"},
        }[metric.instrument_kind]
        if metric_type not in expected_types:
            raise ValueError(
                f"TraceFence metric {reference.name!r} type does not match its catalog instrument kind"
            )

    is_monotonic: bool | None = reference.is_monotonic
    if is_monotonic is not None and not isinstance(is_monotonic, bool):
        raise ValueError(f"TraceFence metric {reference.name!r} has invalid monotonicity")
    expected_monotonicity = {
        MetricInstrumentKind.OBSERVABLE_GAUGE: False,
        MetricInstrumentKind.COUNTER: True,
    }.get(metric.instrument_kind)
    if expected_monotonicity is not None and is_monotonic not in {
        None,
        expected_monotonicity,
    }:
        raise ValueError(
            f"TraceFence metric {reference.name!r} monotonicity does not match its catalog instrument kind"
        )

    temporality: str | None = None
    if reference.temporality is not None:
        if not isinstance(reference.temporality, str):
            raise ValueError(f"TraceFence metric {reference.name!r} has invalid temporality")
        temporality = reference.temporality.casefold()
        if metric.instrument_kind is MetricInstrumentKind.COUNTER and temporality != "cumulative":
            raise ValueError(
                f"TraceFence counter {reference.name!r} must use cumulative temporality"
            )
    return metric_type, is_monotonic, temporality


def classify_metric_discovery(
    references: Sequence[MetricReference],
    observed_metric_names: Iterable[str],
    *,
    live_metric_query_succeeded: bool = True,
) -> MetricPreflight:
    validate_metric_references(references)
    referenced_names = tuple(sorted({reference.name for reference in references}))
    observed = {name for name in observed_metric_names if name in METRICS_BY_NAME}
    observed_catalog_metrics = tuple(sorted(observed))

    def referenced_names_for(policy: MetricDiscoveryPolicy) -> tuple[str, ...]:
        return tuple(
            name
            for name in referenced_names
            if METRICS_BY_NAME[name].discovery_policy is policy
        )

    def catalog_names_for(policy: MetricDiscoveryPolicy) -> tuple[str, ...]:
        return tuple(sorted(metric.name for metric in METRIC_CATALOG if metric.discovery_policy is policy))

    startup_required = referenced_names_for(MetricDiscoveryPolicy.STARTUP_REQUIRED)
    catalog_startup_required = catalog_names_for(MetricDiscoveryPolicy.STARTUP_REQUIRED)
    event_driven = catalog_names_for(MetricDiscoveryPolicy.EVENT_DRIVEN)
    failure_only = catalog_names_for(MetricDiscoveryPolicy.FAILURE_ONLY)
    return MetricPreflight(
        metric_catalog_digest=metric_catalog_digest(),
        referenced_metrics=referenced_names,
        observed_metrics=observed_catalog_metrics,
        startup_required_metrics=startup_required,
        startup_required_missing=tuple(name for name in startup_required if name not in observed),
        event_driven_not_yet_observed=tuple(name for name in event_driven if name not in observed),
        failure_only_not_yet_observed=tuple(name for name in failure_only if name not in observed),
        catalog_startup_required_metrics=catalog_startup_required,
        catalog_startup_required_not_yet_observed=tuple(
            name for name in catalog_startup_required if name not in observed
        ),
        live_metric_query_succeeded=live_metric_query_succeeded,
    )


MetricFetchResult = Iterable[str] | MetricDiscoveryObservation
MetricFetcher = Callable[[], Awaitable[MetricFetchResult]]
MonotonicClock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[Any]]


async def wait_for_metric_discovery(
    fetch_observed_metric_names: MetricFetcher,
    references: Sequence[MetricReference],
    *,
    deadline_seconds: float = 60.0,
    poll_seconds: float = 2.0,
    monotonic: MonotonicClock = time.monotonic,
    sleep: Sleeper = asyncio.sleep,
) -> MetricPreflight:
    if deadline_seconds < 0:
        raise ValueError("Metric discovery deadline must not be negative")
    if poll_seconds <= 0:
        raise ValueError("Metric discovery poll interval must be positive")
    validate_metric_references(references)
    deadline = monotonic() + deadline_seconds
    while True:
        remaining = max(0.0, deadline - monotonic())
        try:
            async with asyncio.timeout(max(remaining, 0.001)):
                observation = await fetch_observed_metric_names()
        except TimeoutError as exc:
            raise MetricDiscoveryError(
                "SigNoz metric discovery exceeded its bounded deadline"
            ) from exc
        observed_metric_names: Iterable[str]
        live_metric_query_succeeded: bool
        if isinstance(observation, MetricDiscoveryObservation):
            observed_metric_names = observation.observed_metric_names
            live_metric_query_succeeded = observation.live_metric_query_succeeded
        else:
            if isinstance(observation, (str, bytes)):
                raise MetricDiscoveryError("Metric discovery returned an invalid metric-name container")
            observed_metric_names = observation
            live_metric_query_succeeded = True
        preflight = classify_metric_discovery(
            references,
            observed_metric_names,
            live_metric_query_succeeded=live_metric_query_succeeded,
        )
        if not preflight.startup_required_missing and preflight.live_metric_query_succeeded:
            return preflight
        remaining = deadline - monotonic()
        if remaining <= 0:
            return preflight
        await sleep(min(poll_seconds, remaining))
