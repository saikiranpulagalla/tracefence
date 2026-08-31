"""Provider-neutral contracts.  No production adapter is registered here."""
from __future__ import annotations

from dataclasses import dataclass
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


class ProviderOperationAdapter(Protocol):
    """Future provider adapter boundary; Phase 3A-1 never invokes it."""

    async def dispatch(self, request: ProviderDispatchRequest) -> None:
        """Deliver a request outside database transactions."""

