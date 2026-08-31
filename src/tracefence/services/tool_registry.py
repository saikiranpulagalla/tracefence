from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from tracefence.config import settings
from tracefence.db.models import ServiceState, utcnow
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import RecoveryContract
from tracefence.providers.contracts import ProviderAdapterContract
from tracefence.security import payload_digest
from tracefence.services.operation_lifecycle import CooperativeOperationContext

ToolExecutor = Callable[[Session, str, str, dict[str, Any]], dict[str, Any]]
CooperativeToolExecutor = Callable[
    [CooperativeOperationContext, dict[str, Any]], Awaitable[dict[str, Any]]
]
RecoveryContractBuilder = Callable[[Session, str, str, dict[str, Any], int], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class PostconditionEvaluation:
    discrepancies: tuple[str, ...]
    postconditions_inconsistent: bool
    postconditions_incomplete: bool
    stability_incomplete: bool


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    capability: str
    side_effecting: bool
    allowed_argument_keys: frozenset[str]
    resources: frozenset[str]
    executor: ToolExecutor | None = None
    execution_mode: Literal["sqlite_atomic", "cooperative", "provider_external"] = "sqlite_atomic"
    cooperative_executor: CooperativeToolExecutor | None = None
    provider_contract: ProviderAdapterContract | None = None
    recommended_replacement_role: str | None = None
    recovery_contract_builder: RecoveryContractBuilder | None = None
    # Explicit successor recovery is intentionally disabled unless a
    # server-owned tool registration supplies a stable policy identifier.
    explicit_recovery_policy_version: str | None = None

    @property
    def allows_explicit_recovery(self) -> bool:
        return self.explicit_recovery_policy_version is not None

    def __post_init__(self) -> None:
        if self.execution_mode == "sqlite_atomic":
            if self.executor is None or self.cooperative_executor is not None:
                raise ValueError(
                    "sqlite_atomic tools require exactly one synchronous executor"
                )
            if self.provider_contract is None:
                return
            raise ValueError("sqlite_atomic tools cannot declare a provider contract")
        if self.execution_mode == "cooperative":
            if (
                self.executor is not None
                or self.cooperative_executor is None
                or self.provider_contract is not None
            ):
                raise ValueError(
                    "cooperative tools require exactly one cooperative executor"
                )
            return
        if self.execution_mode == "provider_external":
            if (
                self.executor is not None
                or self.cooperative_executor is not None
                or self.provider_contract is None
            ):
                raise ValueError(
                    "provider_external tools require exactly one provider contract"
                )
            return
        raise ValueError(f"Unsupported tool execution mode: {self.execution_mode}")

    def validate_arguments(self, arguments: dict[str, Any]) -> None:
        unknown = set(arguments) - set(self.allowed_argument_keys)
        if unknown:
            raise ConflictError(
                f"Unsupported arguments for {self.name}: {', '.join(sorted(unknown))}",
                code="INVALID_TOOL_ARGUMENTS",
            )

    def execute(
        self,
        session: Session,
        run_id: str,
        action_id: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        self.validate_arguments(arguments)
        if self.execution_mode != "sqlite_atomic" or self.executor is None:
            raise RuntimeError("Non-SQLite tools cannot execute in a SQLite transaction")
        return self.executor(session, run_id, action_id, arguments)

    async def execute_cooperative(
        self, context: CooperativeOperationContext, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        self.validate_arguments(arguments)
        if self.execution_mode != "cooperative" or self.cooperative_executor is None:
            raise RuntimeError("Only cooperative tools can execute cooperatively")
        return await self.cooperative_executor(context, arguments)

    def build_recovery_contract(
        self,
        session: Session,
        run_id: str,
        arguments: dict[str, Any],
        stability_window_seconds: int,
    ) -> dict[str, Any]:
        if self.recovery_contract_builder is None:
            return {
                "schema_version": 1,
                "expected_tool": self.name,
                "expected_arguments_digest": payload_digest(arguments),
                "allowed_environment": settings.environment,
                "allowed_resources": sorted(self.resources),
                "max_committed_invocations": 1,
                "stability_window_seconds": stability_window_seconds,
                "postconditions": [],
            }
        contract = self.recovery_contract_builder(
            session,
            run_id,
            self.name,
            arguments,
            stability_window_seconds,
        )
        contract["allowed_environment"] = settings.environment
        contract["allowed_resources"] = sorted(self.resources)
        return contract

    def verify_postconditions(
        self,
        session: Session,
        run_id: str,
        action_id: str,
        contract: RecoveryContract,
        stable_before: datetime,
    ) -> PostconditionEvaluation:
        discrepancies: list[str] = []
        inconsistent = False
        incomplete = False
        stability_incomplete = False
        for postcondition in contract.postconditions:
            state = session.get(ServiceState, (run_id, postcondition.service_name))
            if state is None:
                discrepancies.append(
                    "Recovery postcondition service is missing: "
                    f"{postcondition.service_name}"
                )
                incomplete = True
                stability_incomplete = True
                continue
            actual = getattr(state, postcondition.field)
            if actual != postcondition.expected:
                discrepancies.append(
                    f"Recovery postcondition failed: {postcondition.service_name}."
                    f"{postcondition.field} expected {postcondition.expected!r}, "
                    f"found {actual!r}"
                )
                incomplete = True
                stability_incomplete = True
                continue
            if postcondition.require_recovery_action and state.last_action_id != action_id:
                discrepancies.append(
                    f"Recovery postcondition {postcondition.service_name}."
                    f"{postcondition.field} is not causally bound to the authorized "
                    "recovery action"
                )
                inconsistent = True
                continue
            if (
                contract.stability_window_seconds > 0
                and state.updated_at > stable_before
            ):
                discrepancies.append(
                    f"Recovery postcondition {postcondition.service_name}."
                    f"{postcondition.field} has not remained stable for "
                    f"{contract.stability_window_seconds} seconds"
                )
                stability_incomplete = True
        return PostconditionEvaluation(
            discrepancies=tuple(discrepancies),
            postconditions_inconsistent=inconsistent,
            postconditions_incomplete=incomplete,
            stability_incomplete=stability_incomplete,
        )


def _state(session: Session, run_id: str, service_name: str, default_status: str) -> ServiceState:
    state = session.get(ServiceState, (run_id, service_name))
    if state is None:
        state = ServiceState(
            run_id=run_id,
            service_name=service_name,
            status=default_status,
            restart_count=0,
            pool_reset_count=0,
            updated_at=utcnow(),
        )
        session.add(state)
    return state


def _read_metrics(
    session: Session, run_id: str, _action_id: str, _arguments: dict[str, Any]
) -> dict[str, Any]:
    rows = session.execute(
        select(ServiceState).where(ServiceState.run_id == run_id)
    ).scalars().all()
    return {
        "services": [
            {
                "service": row.service_name,
                "status": row.status,
                "restart_count": row.restart_count,
                "pool_reset_count": row.pool_reset_count,
            }
            for row in rows
        ]
    }


def _restart_postgres(
    session: Session, run_id: str, action_id: str, _arguments: dict[str, Any]
) -> dict[str, Any]:
    state = _state(session, run_id, "postgres", "healthy")
    state.restart_count += 1
    state.status = "healthy"
    state.last_action_id = action_id
    state.updated_at = utcnow()
    return {
        "service": "postgres",
        "status": "healthy",
        "restart_count": state.restart_count,
    }


def _reset_redis_pool(
    session: Session, run_id: str, action_id: str, _arguments: dict[str, Any]
) -> dict[str, Any]:
    redis = _state(session, run_id, "redis", "connection_pool_exhausted")
    redis.pool_reset_count += 1
    redis.status = "healthy"
    redis.last_action_id = action_id
    redis.updated_at = utcnow()

    checkout = _state(session, run_id, "checkout", "degraded")
    checkout.status = "healthy"
    checkout.last_action_id = action_id
    checkout.updated_at = utcnow()
    return {
        "service": "redis",
        "status": "healthy",
        "pool_reset_count": redis.pool_reset_count,
        "checkout_status": "healthy",
    }


def _restart_postgres_contract(
    session: Session,
    run_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    stability_window_seconds: int,
) -> dict[str, Any]:
    postgres = _state(session, run_id, "postgres", "healthy")
    return {
        "schema_version": 1,
        "expected_tool": tool_name,
        "expected_arguments_digest": payload_digest(arguments),
        "max_committed_invocations": 1,
        "stability_window_seconds": stability_window_seconds,
        "postconditions": [
            {
                "service_name": "postgres",
                "field": "status",
                "operator": "equals",
                "expected": "healthy",
                "require_recovery_action": True,
            },
            {
                "service_name": "postgres",
                "field": "restart_count",
                "operator": "equals",
                "expected": postgres.restart_count + 1,
                "require_recovery_action": True,
            },
        ],
    }


def _reset_redis_contract(
    session: Session,
    run_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    stability_window_seconds: int,
) -> dict[str, Any]:
    redis = _state(session, run_id, "redis", "connection_pool_exhausted")
    _state(session, run_id, "checkout", "degraded")
    postgres = _state(session, run_id, "postgres", "healthy")
    return {
        "schema_version": 1,
        "expected_tool": tool_name,
        "expected_arguments_digest": payload_digest(arguments),
        "max_committed_invocations": 1,
        "stability_window_seconds": stability_window_seconds,
        "postconditions": [
            {
                "service_name": "redis",
                "field": "status",
                "operator": "equals",
                "expected": "healthy",
                "require_recovery_action": True,
            },
            {
                "service_name": "redis",
                "field": "pool_reset_count",
                "operator": "equals",
                "expected": redis.pool_reset_count + 1,
                "require_recovery_action": True,
            },
            {
                "service_name": "checkout",
                "field": "status",
                "operator": "equals",
                "expected": "healthy",
                "require_recovery_action": True,
            },
            {
                "service_name": "postgres",
                "field": "restart_count",
                "operator": "equals",
                "expected": postgres.restart_count,
                "require_recovery_action": False,
            },
        ],
    }


TOOL_REGISTRY: dict[str, ToolSpec] = {
    "read_metrics": ToolSpec(
        name="read_metrics",
        capability="tool:read_metrics",
        side_effecting=False,
        allowed_argument_keys=frozenset(),
        resources=frozenset({"metrics"}),
        executor=_read_metrics,
    ),
    "restart_postgres": ToolSpec(
        name="restart_postgres",
        capability="tool:restart_postgres",
        side_effecting=True,
        allowed_argument_keys=frozenset(),
        resources=frozenset({"postgres"}),
        executor=_restart_postgres,
        recommended_replacement_role="postgres_recovery",
        recovery_contract_builder=_restart_postgres_contract,
    ),
    "reset_redis_pool": ToolSpec(
        name="reset_redis_pool",
        capability="tool:reset_redis_pool",
        side_effecting=True,
        allowed_argument_keys=frozenset(),
        resources=frozenset({"checkout", "postgres", "redis"}),
        executor=_reset_redis_pool,
        recommended_replacement_role="redis_recovery",
        recovery_contract_builder=_reset_redis_contract,
    ),
}


def get_tool_spec(tool_name: str) -> ToolSpec:
    spec = TOOL_REGISTRY.get(tool_name)
    if spec is None:
        raise ConflictError(f"Unsupported tool: {tool_name}", code="UNSUPPORTED_TOOL")
    return spec
