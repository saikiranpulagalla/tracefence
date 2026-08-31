"""Deterministic provider adapter for Phase 3A-1 tests only."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from tracefence.providers.contracts import (
    ProviderDispatchOutcome,
    ProviderDispatchOutcomeKind,
    ProviderDispatchRequest,
    ProviderObservation,
    ProviderObservationIdentity,
    ProviderObservationKind,
)


@dataclass
class FakeProviderAdapter:
    dispatch_outcomes: deque[ProviderDispatchOutcome] = field(default_factory=deque)
    observations: deque[ProviderObservation] = field(default_factory=deque)
    dispatch_requests: list[ProviderDispatchRequest] = field(default_factory=list)
    observation_identities: list[ProviderObservationIdentity] = field(default_factory=list)

    async def dispatch(self, request: ProviderDispatchRequest) -> ProviderDispatchOutcome:
        self.dispatch_requests.append(request)
        if self.dispatch_outcomes:
            return self.dispatch_outcomes.popleft()
        return ProviderDispatchOutcome(ProviderDispatchOutcomeKind.INDETERMINATE)

    async def observe(self, identity: ProviderObservationIdentity) -> ProviderObservation:
        self.observation_identities.append(identity)
        if self.observations:
            return self.observations.popleft()
        return ProviderObservation(ProviderObservationKind.UNCERTAIN)
