from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import tracefence.telemetry.instruments as instruments
from tracefence.telemetry.schema import (
    METRIC_CATALOG,
    METRICS_BY_NAME,
    MetricDiscoveryPolicy,
    MetricInstrumentKind,
    MetricReference,
    extract_metric_references,
    metric_catalog_digest,
    validate_metric_references,
)

ROOT = Path(__file__).resolve().parents[2]


class _Meter:
    def __init__(self) -> None:
        self.created: dict[str, MetricInstrumentKind] = {}

    def create_observable_gauge(self, name: str, **_kwargs: object) -> object:
        self.created[name] = MetricInstrumentKind.OBSERVABLE_GAUGE
        return object()

    def create_counter(self, name: str, **_kwargs: object) -> object:
        self.created[name] = MetricInstrumentKind.COUNTER
        return object()

    def create_histogram(self, name: str, **_kwargs: object) -> object:
        self.created[name] = MetricInstrumentKind.HISTOGRAM
        return object()


def _specs() -> tuple[dict[str, object], list[dict[str, object]]]:
    dashboard = json.loads(
        (ROOT / "observability" / "dashboard.json").read_text(encoding="utf-8")
    )
    alerts = json.loads(
        (ROOT / "observability" / "alerts.json").read_text(encoding="utf-8")
    )
    return dashboard, alerts


def _first_metric_mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        if isinstance(value.get("metricName"), str):
            return value
        for nested in value.values():
            found = _first_metric_mapping(nested)
            if found:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _first_metric_mapping(nested)
            if found:
                return found
    return {}


def test_runtime_created_instruments_exactly_match_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    meter = _Meter()
    monkeypatch.setattr(instruments.metrics, "get_meter", lambda _name: meter)

    instruments.build_telemetry()

    expected = {definition.name: definition.instrument_kind for definition in METRIC_CATALOG}
    assert meter.created == expected


def test_catalog_metric_names_are_unique_and_digest_is_stable() -> None:
    names = [definition.name for definition in METRIC_CATALOG]

    assert len(names) == len(set(names))
    assert set(names) == set(METRICS_BY_NAME)
    assert len(metric_catalog_digest()) == 64
    assert metric_catalog_digest() == metric_catalog_digest()


def test_catalog_assigns_every_required_startup_and_failure_policy() -> None:
    startup_required = {
        "tracefence_active_nodes",
        "tracefence_live_affected_nodes",
        "tracefence_unacknowledged_live_nodes",
        "tracefence_orphan_nodes",
        "tracefence_telemetry_outbox_pending",
        "tracefence_stale_violation_latched",
        "tracefence_telemetry_delivery_last_success_unixtime",
    }
    failure_only = {
        "tracefence_stale_actions_committed_total",
        "tracefence_exporter_failures_total",
        "tracefence_proof_inconsistent_total",
        "tracefence_recovery_postcondition_failures_total",
    }

    assert {
        name
        for name, metric in METRICS_BY_NAME.items()
        if metric.discovery_policy is MetricDiscoveryPolicy.STARTUP_REQUIRED
    } == startup_required
    assert {
        name
        for name, metric in METRICS_BY_NAME.items()
        if metric.discovery_policy is MetricDiscoveryPolicy.FAILURE_ONLY
    } == failure_only


def test_checked_in_dashboard_and_alert_metric_references_are_catalog_valid() -> None:
    dashboard, alerts = _specs()
    references = extract_metric_references(dashboard, alerts)

    validate_metric_references(references)
    assert {reference.name for reference in references} <= set(METRICS_BY_NAME)


def test_unknown_dashboard_metric_is_rejected() -> None:
    dashboard, _alerts = _specs()
    mutated = copy.deepcopy(dashboard)
    reference = _first_metric_mapping(mutated)
    reference["metricName"] = "tracefence_typo_metric"

    with pytest.raises(ValueError, match="Unknown TraceFence metric"):
        validate_metric_references(extract_metric_references(mutated))


def test_unknown_alert_metric_is_rejected() -> None:
    _dashboard, alerts = _specs()
    mutated = copy.deepcopy(alerts)
    reference = _first_metric_mapping(mutated)
    reference["metricName"] = "tracefence_typo_metric"

    with pytest.raises(ValueError, match="Unknown TraceFence metric"):
        validate_metric_references(extract_metric_references(mutated))


@pytest.mark.parametrize(
    ("name", "time_aggregation", "space_aggregation", "message"),
    (
        (
            "tracefence_active_nodes",
            "increase",
            "max",
            "does not support time aggregation",
        ),
        (
            "tracefence_control_commands_total",
            "latest",
            "sum",
            "does not support time aggregation",
        ),
        (
            "tracefence_action_gateway_duration_ms",
            "increase",
            "p95",
            "does not support time aggregation",
        ),
    ),
)
def test_catalog_rejects_incompatible_metric_aggregations(
    name: str,
    time_aggregation: str,
    space_aggregation: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_metric_references(
            (
                MetricReference(
                    name=name,
                    time_aggregation=time_aggregation,
                    space_aggregation=space_aggregation,
                ),
            )
        )


def test_catalog_rejects_contradictory_duplicate_metric_references() -> None:
    with pytest.raises(ValueError, match="contradictory aggregation"):
        validate_metric_references(
            (
                MetricReference(
                    name="tracefence_control_commands_total",
                    time_aggregation="increase",
                    space_aggregation="sum",
                ),
                MetricReference(
                    name="tracefence_control_commands_total",
                    time_aggregation="rate",
                    space_aggregation="sum",
                ),
            )
        )


@pytest.mark.parametrize(
    "reference",
    (
        MetricReference(
            name="tracefence_active_nodes",
            time_aggregation="latest",
            space_aggregation="max",
            metric_type="sum",
        ),
        MetricReference(
            name="tracefence_control_commands_total",
            time_aggregation="increase",
            space_aggregation="sum",
            is_monotonic=False,
        ),
        MetricReference(
            name="tracefence_control_commands_total",
            time_aggregation="increase",
            space_aggregation="sum",
            temporality="Delta",
        ),
    ),
)
def test_catalog_rejects_explicit_metadata_inconsistent_with_instrument_kind(
    reference: MetricReference,
) -> None:
    with pytest.raises(ValueError):
        validate_metric_references((reference,))


def test_catalog_accepts_explicit_compatible_counter_metadata() -> None:
    validate_metric_references(
        (
            MetricReference(
                name="tracefence_control_commands_total",
                time_aggregation="increase",
                space_aggregation="sum",
                metric_type="sum",
                is_monotonic=True,
                temporality="Cumulative",
            ),
        )
    )


def test_verifier_uses_catalog_policy_instead_of_legacy_all_metrics_set() -> None:
    verifier = (ROOT / "scripts" / "verify_signoz.py").read_text(encoding="utf-8")

    assert "REQUIRED_METRICS" not in verifier
    assert "wait_for_metric_discovery" in verifier
