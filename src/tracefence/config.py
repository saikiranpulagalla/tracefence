from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

_PROCESS_LOCAL_SECRET = secrets.token_urlsafe(48)
_PROCESS_LOCAL_RECOVERY_SECRET = secrets.token_urlsafe(48)


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    truthy = {"1", "true", "yes", "on"}
    falsy = {"0", "false", "no", "off"}
    if normalized in truthy:
        return True
    if normalized in falsy:
        return False
    raise RuntimeError(
        f"{name} must be one of: true, false, 1, 0, yes, no, on, off"
    )


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def _looks_like_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    markers = ("change-me", "changeme", "replace-", "generate-", "placeholder", "example")
    return any(marker in normalized for marker in markers)


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str = os.getenv("TRACEFENCE_ENV", "development")
    database_url: str = os.getenv(
        "TRACEFENCE_DATABASE_URL", "sqlite+pysqlite:///./data/tracefence.db"
    )
    operator_key: str = os.getenv("TRACEFENCE_OPERATOR_KEY", "")
    token_hash_secret: str = os.getenv("TRACEFENCE_TOKEN_HASH_SECRET", _PROCESS_LOCAL_SECRET)
    credential_recovery_key: str = os.getenv(
        "TRACEFENCE_CREDENTIAL_RECOVERY_KEY",
        _PROCESS_LOCAL_RECOVERY_SECRET,
    )
    credential_recovery_ttl_seconds: int = _int_env(
        "TRACEFENCE_CREDENTIAL_RECOVERY_TTL_SECONDS",
        30,
    )
    allow_insecure_dev: bool = _bool_env("TRACEFENCE_ALLOW_INSECURE_DEV", False)
    heartbeat_interval_seconds: int = _int_env("TRACEFENCE_HEARTBEAT_INTERVAL_SECONDS", 2)
    lease_ttl_seconds: int = _int_env("TRACEFENCE_LEASE_TTL_SECONDS", 7)
    lease_scan_interval_seconds: int = _int_env("TRACEFENCE_LEASE_SCAN_INTERVAL_SECONDS", 2)
    control_convergence_slo_seconds: int = _int_env("TRACEFENCE_CONTROL_CONVERGENCE_SLO_SECONDS", 10)
    control_plane_workers: int = _int_env("TRACEFENCE_CONTROL_PLANE_WORKERS", 8)
    max_active_runs: int = _int_env("TRACEFENCE_MAX_ACTIVE_RUNS", 32)
    max_nodes_per_run: int = _int_env("TRACEFENCE_MAX_NODES_PER_RUN", 128)
    max_graph_depth: int = _int_env("TRACEFENCE_MAX_GRAPH_DEPTH", 12)
    max_children_per_node: int = _int_env("TRACEFENCE_MAX_CHILDREN_PER_NODE", 16)
    max_commands_per_run: int = _int_env("TRACEFENCE_MAX_COMMANDS_PER_RUN", 128)
    max_actions_per_run: int = _int_env("TRACEFENCE_MAX_ACTIONS_PER_RUN", 2048)
    max_proposals_per_run: int = _int_env("TRACEFENCE_MAX_PROPOSALS_PER_RUN", 256)
    proof_cache_seconds: int = _int_env("TRACEFENCE_PROOF_CACHE_SECONDS", 2)
    max_request_bytes: int = _int_env("TRACEFENCE_MAX_REQUEST_BYTES", 262144)
    rate_limit_per_minute: int = _int_env("TRACEFENCE_RATE_LIMIT_PER_MINUTE", 600)
    proof_rate_limit_per_minute: int = _int_env(
        "TRACEFENCE_PROOF_RATE_LIMIT_PER_MINUTE", 60
    )
    rate_limit_max_buckets: int = _int_env("TRACEFENCE_RATE_LIMIT_MAX_BUCKETS", 10_000)
    otlp_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    otel_metric_export_interval_ms: int = _int_env("TRACEFENCE_OTEL_METRIC_EXPORT_INTERVAL_MS", 2000)
    otel_export_timeout_ms: int = _int_env("TRACEFENCE_OTEL_EXPORT_TIMEOUT_MS", 5000)
    build_commit: str = os.getenv("TRACEFENCE_BUILD_COMMIT", "")
    signoz_url: str = os.getenv("SIGNOZ_URL", "http://localhost:8080")
    signoz_mcp_url: str = os.getenv("SIGNOZ_MCP_URL", "http://localhost:8000/mcp")
    signoz_api_key: str = os.getenv("SIGNOZ_API_KEY", "")
    evidence_signing_key: str = os.getenv("TRACEFENCE_EVIDENCE_SIGNING_KEY", "")
    frontend_origin: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")

    def validate_security(self) -> None:
        if self.environment.lower() == "test":
            return
        errors: list[str] = []
        if not self.operator_key:
            errors.append("TRACEFENCE_OPERATOR_KEY is required")
        elif len(self.operator_key) < 24:
            errors.append("TRACEFENCE_OPERATOR_KEY must contain at least 24 characters")
        elif _looks_like_placeholder(self.operator_key):
            errors.append("TRACEFENCE_OPERATOR_KEY must not be a placeholder value")
        if self.token_hash_secret == _PROCESS_LOCAL_SECRET and not self.allow_insecure_dev:
            errors.append("TRACEFENCE_TOKEN_HASH_SECRET must be explicitly configured")
        elif len(self.token_hash_secret) < 32:
            errors.append("TRACEFENCE_TOKEN_HASH_SECRET must contain at least 32 characters")
        elif _looks_like_placeholder(self.token_hash_secret):
            errors.append("TRACEFENCE_TOKEN_HASH_SECRET must not be a placeholder value")
        if (
            self.credential_recovery_key == _PROCESS_LOCAL_RECOVERY_SECRET
            and not self.allow_insecure_dev
        ):
            errors.append("TRACEFENCE_CREDENTIAL_RECOVERY_KEY must be explicitly configured")
        elif len(self.credential_recovery_key) < 32:
            errors.append(
                "TRACEFENCE_CREDENTIAL_RECOVERY_KEY must contain at least 32 characters"
            )
        elif _looks_like_placeholder(self.credential_recovery_key):
            errors.append("TRACEFENCE_CREDENTIAL_RECOVERY_KEY must not be a placeholder value")
        elif self.credential_recovery_key in {
            self.operator_key,
            self.token_hash_secret,
            self.evidence_signing_key,
        }:
            errors.append(
                "TRACEFENCE_CREDENTIAL_RECOVERY_KEY must be independent from all other keys"
            )
        if not self.evidence_signing_key:
            errors.append("TRACEFENCE_EVIDENCE_SIGNING_KEY is required")
        elif len(self.evidence_signing_key) < 32:
            errors.append("TRACEFENCE_EVIDENCE_SIGNING_KEY must contain at least 32 characters")
        elif _looks_like_placeholder(self.evidence_signing_key):
            errors.append("TRACEFENCE_EVIDENCE_SIGNING_KEY must not be a placeholder value")
        elif self.evidence_signing_key == self.operator_key:
            errors.append(
                "TRACEFENCE_EVIDENCE_SIGNING_KEY must be independent from "
                "TRACEFENCE_OPERATOR_KEY"
            )
        elif self.evidence_signing_key == self.token_hash_secret:
            errors.append(
                "TRACEFENCE_EVIDENCE_SIGNING_KEY must be independent from "
                "TRACEFENCE_TOKEN_HASH_SECRET"
            )
        if self.heartbeat_interval_seconds <= 0:
            errors.append("TRACEFENCE_HEARTBEAT_INTERVAL_SECONDS must be positive")
        if self.lease_ttl_seconds <= self.heartbeat_interval_seconds:
            errors.append("TRACEFENCE_LEASE_TTL_SECONDS must exceed the heartbeat interval")
        if self.lease_scan_interval_seconds <= 0:
            errors.append("TRACEFENCE_LEASE_SCAN_INTERVAL_SECONDS must be positive")
        if self.control_convergence_slo_seconds <= 0:
            errors.append("TRACEFENCE_CONTROL_CONVERGENCE_SLO_SECONDS must be positive")
        if not 5 <= self.credential_recovery_ttl_seconds <= 300:
            errors.append(
                "TRACEFENCE_CREDENTIAL_RECOVERY_TTL_SECONDS must be between 5 and 300"
            )
        if not 1 <= self.control_plane_workers <= 64:
            errors.append("TRACEFENCE_CONTROL_PLANE_WORKERS must be between 1 and 64")
        for name, value, maximum in (
            ("TRACEFENCE_MAX_ACTIVE_RUNS", self.max_active_runs, 10_000),
            ("TRACEFENCE_MAX_NODES_PER_RUN", self.max_nodes_per_run, 100_000),
            ("TRACEFENCE_MAX_GRAPH_DEPTH", self.max_graph_depth, 1_000),
            ("TRACEFENCE_MAX_CHILDREN_PER_NODE", self.max_children_per_node, 10_000),
            ("TRACEFENCE_MAX_COMMANDS_PER_RUN", self.max_commands_per_run, 100_000),
            ("TRACEFENCE_MAX_ACTIONS_PER_RUN", self.max_actions_per_run, 1_000_000),
            ("TRACEFENCE_MAX_PROPOSALS_PER_RUN", self.max_proposals_per_run, 100_000),
        ):
            if not 1 <= value <= maximum:
                errors.append(f"{name} must be between 1 and {maximum}")
        if self.max_children_per_node >= self.max_nodes_per_run:
            errors.append(
                "TRACEFENCE_MAX_CHILDREN_PER_NODE must be below TRACEFENCE_MAX_NODES_PER_RUN"
            )
        if self.proof_cache_seconds < 0:
            errors.append("TRACEFENCE_PROOF_CACHE_SECONDS cannot be negative")
        if self.max_request_bytes < 1024:
            errors.append("TRACEFENCE_MAX_REQUEST_BYTES must be at least 1024")
        if not 1 <= self.rate_limit_per_minute <= 100_000:
            errors.append("TRACEFENCE_RATE_LIMIT_PER_MINUTE must be between 1 and 100000")
        if not 1 <= self.proof_rate_limit_per_minute <= self.rate_limit_per_minute:
            errors.append(
                "TRACEFENCE_PROOF_RATE_LIMIT_PER_MINUTE must be positive and no greater "
                "than TRACEFENCE_RATE_LIMIT_PER_MINUTE"
            )
        if not 100 <= self.rate_limit_max_buckets <= 1_000_000:
            errors.append("TRACEFENCE_RATE_LIMIT_MAX_BUCKETS must be between 100 and 1000000")
        if self.otel_metric_export_interval_ms <= 0:
            errors.append("TRACEFENCE_OTEL_METRIC_EXPORT_INTERVAL_MS must be positive")
        if self.otel_export_timeout_ms <= 0:
            errors.append("TRACEFENCE_OTEL_EXPORT_TIMEOUT_MS must be positive")
        if errors:
            raise RuntimeError("; ".join(errors))


settings = Settings()
