"""Shared validation for checked-in SigNoz alert templates."""

from __future__ import annotations

from typing import Any

ALERT_CHANNEL_PLACEHOLDER = "${TRACEFENCE_NOTIFICATION_CHANNEL}"
_REQUIRED_ALERT_FIELDS = (
    "alert",
    "alertType",
    "ruleType",
    "version",
    "schemaVersion",
    "condition",
    "evaluation",
    "notificationSettings",
    "labels",
    "annotations",
)


def validate_alert_templates(
    alerts: object,
    *,
    channel_placeholder: str = ALERT_CHANNEL_PLACEHOLDER,
) -> dict[str, dict[str, Any]]:
    """Validate alert templates and return them by their exact declared name.

    The provisioner and verifier share this function so a local specification is
    rejected consistently before either script opens an MCP connection.
    """

    if not isinstance(alerts, list) or not alerts:
        raise ValueError("At least one alert template is required")

    templates_by_name: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError("Each alert template must be an object")
        missing = [field for field in _REQUIRED_ALERT_FIELDS if field not in alert]
        if missing:
            label = alert.get("alert", "<unknown>")
            raise ValueError(f"Alert {label!r} is missing {', '.join(missing)}")

        name = alert["alert"]
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Alert template must have a non-empty string alert name")
        if name in templates_by_name:
            raise ValueError(f"Duplicate alert name: {name}")

        if alert["ruleType"] != "threshold_rule" or alert["schemaVersion"] != "v2alpha1":
            raise ValueError(f"Alert {name} must use the v2alpha1 threshold-rule schema")

        condition = alert["condition"]
        if not isinstance(condition, dict):
            raise ValueError(f"Alert {name} has no valid condition")
        thresholds = condition.get("thresholds")
        threshold_spec = thresholds.get("spec") if isinstance(thresholds, dict) else None
        if not isinstance(threshold_spec, list) or not threshold_spec:
            raise ValueError(f"Alert {name} has no threshold tier")
        if not any(
            isinstance(tier, dict)
            and isinstance(tier.get("channels"), list)
            and channel_placeholder in tier["channels"]
            for tier in threshold_spec
        ):
            raise ValueError(f"Alert {name} must use the notification-channel placeholder")

        composite = condition.get("compositeQuery")
        if not isinstance(composite, dict):
            raise ValueError(f"Alert {name} has no valid composite query")
        queries = composite.get("queries")
        if not isinstance(queries, list) or not queries:
            raise ValueError(f"Alert {name} has no catalog-validated metric query")
        for query in queries:
            if not isinstance(query, dict) or query.get("type") != "builder_query":
                raise ValueError(f"Alert {name} must use a builder metric query")
            spec = query.get("spec")
            aggregations = spec.get("aggregations") if isinstance(spec, dict) else None
            if not isinstance(aggregations, list) or not aggregations:
                raise ValueError(f"Alert {name} has no metric aggregation")

        templates_by_name[name] = alert
    return templates_by_name
