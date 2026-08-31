"""Provider-neutral contracts.  No production adapter is registered here."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ProviderAdapterContract:
    """Server-owned immutable identity for one provider dispatch contract."""

    provider_adapter_id: str
    provider_config_ref: str
    provider_scope_ref: str
    reconciliation_version: str
    dispatch_contract_version: str

    def __post_init__(self) -> None:
        if not all(
            (
                self.provider_adapter_id,
                self.provider_config_ref,
                self.provider_scope_ref,
                self.reconciliation_version,
                self.dispatch_contract_version,
            )
        ):
            raise ValueError("Provider adapter contract fields must be non-empty")


@dataclass(frozen=True, slots=True)
class ProviderDispatchRequest:
    """A durable, non-secret request envelope returned after a delivery claim."""

    action_id: str
    run_id: str
    provider_idempotency_key: str
    provider_request: dict[str, Any]
    claim_token: str


class ProviderDispatchOutcomeKind(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED_NONEXECUTED = "REJECTED_NONEXECUTED"
    INDETERMINATE = "INDETERMINATE"
    PERMANENT_PROTOCOL_ERROR = "PERMANENT_PROTOCOL_ERROR"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class ProviderDispatchOutcome:
    """A typed semantic outcome; transport exceptions are not semantic truth."""

    kind: ProviderDispatchOutcomeKind
    provider_handle: str | None = None
    evidence: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.provider_handle == "":
            raise ValueError("provider_handle must be non-empty when supplied")
        if self.kind != ProviderDispatchOutcomeKind.ACCEPTED and self.provider_handle:
            raise ValueError("only accepted dispatch may carry a provider handle")


@dataclass(frozen=True, slots=True)
class ProviderObservationIdentity:
    action_id: str
    run_id: str
    provider_idempotency_key: str
    operation_key: str
    provider_handle: str | None


class ProviderObservationKind(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"
    DEFINITIVE_NONEXECUTION = "DEFINITIVE_NONEXECUTION"
    UNCERTAIN = "UNCERTAIN"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    kind: ProviderObservationKind
    evidence: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if (
            self.kind
            in {
                ProviderObservationKind.SUCCEEDED,
                ProviderObservationKind.FAILED,
                ProviderObservationKind.CONFLICT,
            }
            and self.evidence is None
        ):
            raise ValueError(f"{self.kind} requires evidence")


class ProviderOperationAdapter(Protocol):
    """Future provider adapter boundary; Phase 3A-1 never invokes it."""

    async def dispatch(self, request: ProviderDispatchRequest) -> ProviderDispatchOutcome:
        """Deliver a request outside database transactions."""

    async def observe(self, identity: ProviderObservationIdentity) -> ProviderObservation:
        """Observe an operation outside database transactions."""
