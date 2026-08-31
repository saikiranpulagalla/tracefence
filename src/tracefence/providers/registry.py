"""Static server-owned provider adapter registration.

The production registry is deliberately empty in Phase 3A-1.  Test adapters
must be supplied explicitly, and no provider URL, credential, or network I/O is
introduced by this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from tracefence.providers.contracts import ProviderAdapterContract, ProviderOperationAdapter


@dataclass(frozen=True, slots=True)
class RegisteredProviderAdapter:
    contract: ProviderAdapterContract
    adapter: ProviderOperationAdapter


class ProviderAdapterRegistry:
    def __init__(self, registered: tuple[RegisteredProviderAdapter, ...] = ()) -> None:
        entries: dict[
            tuple[str, str, str, str], RegisteredProviderAdapter
        ] = {}
        for item in registered:
            contract = item.contract
            key = (
                contract.provider_adapter_id,
                contract.provider_config_ref,
                contract.provider_scope_ref,
                contract.dispatch_contract_version,
            )
            if key in entries:
                raise ValueError("Provider adapter contract identity must be unique")
            entries[key] = item
        self._registered = MappingProxyType(entries)

    def resolve(
        self, contract: ProviderAdapterContract
    ) -> RegisteredProviderAdapter | None:
        return self._registered.get(
            (
                contract.provider_adapter_id,
                contract.provider_config_ref,
                contract.provider_scope_ref,
                contract.dispatch_contract_version,
            )
        )


PRODUCTION_PROVIDER_ADAPTER_REGISTRY = ProviderAdapterRegistry()

