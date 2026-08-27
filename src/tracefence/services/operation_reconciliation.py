"""C-C1 durable external-operation reconciliation identity and evidence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from tracefence.db.models import (
    ActionAttempt,
    ActionExternalOperationBinding,
    ActionReconciliationEvidence,
)
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.security import payload_digest
from tracefence.services.common import utcnow
from tracefence.services.operation_lifecycle import OperationLifecycleService


class ObservationKind(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"
    NOT_FOUND = "NOT_FOUND"
    UNCERTAIN = "UNCERTAIN"
    CONFLICT = "CONFLICT"


class NotFoundStrength(StrEnum):
    WEAK_NOT_FOUND = "WEAK_NOT_FOUND"
    DEFINITIVE_NONEXECUTION = "DEFINITIVE_NONEXECUTION"


@dataclass(frozen=True, slots=True)
class ReconciliationIdentity:
    action_id: str
    run_id: str
    node_id: str
    tool_name: str
    request_payload_digest: str
    arguments_digest: str
    worker_instance_id: str
    worker_incarnation: int
    provider_adapter_id: str
    provider_config_ref: str
    provider_scope_ref: str
    tool_reconciliation_version: str
    operation_key: str
    provider_handle: str | None


@dataclass(frozen=True, slots=True)
class ReconciliationObservation:
    kind: ObservationKind
    result: dict[str, Any] | None = None
    provider_evidence_ref: str | None = None
    provider_evidence_digest: str | None = None
    not_found_strength: NotFoundStrength | None = None

    def __post_init__(self) -> None:
        terminal = {ObservationKind.SUCCEEDED, ObservationKind.FAILED, ObservationKind.CONFLICT}
        if self.kind in terminal and self.result is None:
            raise ValueError(f"{self.kind} requires bounded material payload")
        if self.kind not in terminal and self.result is not None:
            raise ValueError(f"{self.kind} cannot carry terminal result")
        if self.kind == ObservationKind.NOT_FOUND and self.not_found_strength is None:
            raise ValueError("NOT_FOUND requires an explicit strength")
        if self.kind != ObservationKind.NOT_FOUND and self.not_found_strength is not None:
            raise ValueError("not-found strength applies only to NOT_FOUND")
        if (self.provider_evidence_ref is None) != (self.provider_evidence_digest is None):
            raise ValueError("provider evidence reference and digest must be supplied together")

    @property
    def is_material(self) -> bool:
        return self.kind in {
            ObservationKind.SUCCEEDED,
            ObservationKind.FAILED,
            ObservationKind.CONFLICT,
        } or (
            self.kind == ObservationKind.NOT_FOUND
            and self.not_found_strength == NotFoundStrength.DEFINITIVE_NONEXECUTION
        )


class OperationReconciler(Protocol):
    async def reconcile(self, identity: ReconciliationIdentity) -> ReconciliationObservation: ...


@dataclass(frozen=True, slots=True)
class ReconcilerCapabilities:
    """Server-owned capabilities for one exact provider reconciliation contract."""

    supports_definitive_nonexecution: bool = False


@dataclass(frozen=True, slots=True)
class ReconcilerContract:
    """Trusted, server-composed identity and capabilities of one reconciler."""

    provider_adapter_id: str
    provider_config_ref: str
    provider_scope_ref: str
    tool_reconciliation_version: str
    capabilities: ReconcilerCapabilities

    def matches_binding(self, binding: ActionExternalOperationBinding) -> bool:
        return (
            self.provider_adapter_id,
            self.provider_config_ref,
            self.provider_scope_ref,
            self.tool_reconciliation_version,
        ) == (
            binding.provider_adapter_id,
            binding.provider_config_ref,
            binding.provider_scope_ref,
            binding.tool_reconciliation_version,
        )


@dataclass(frozen=True, slots=True)
class RegisteredOperationReconciler:
    """One trusted server-side reconciler and its exact contract."""

    contract: ReconcilerContract
    reconciler: OperationReconciler


class ReconcilerRegistry:
    """Server-composed registry; bindings cannot create reconciler capabilities."""

    def __init__(self, registered: tuple[RegisteredOperationReconciler, ...] = ()) -> None:
        entries: dict[tuple[str, str, str, str], RegisteredOperationReconciler] = {}
        for item in registered:
            contract = item.contract
            key = self._key(
                contract.provider_adapter_id,
                contract.provider_config_ref,
                contract.provider_scope_ref,
                contract.tool_reconciliation_version,
            )
            if not all(key) or key in entries:
                raise ValueError("Reconciler contract identity must be unique and non-empty")
            entries[key] = item
        self._registered = MappingProxyType(entries)

    @staticmethod
    def _key(
        provider_adapter_id: str,
        provider_config_ref: str,
        provider_scope_ref: str,
        tool_reconciliation_version: str,
    ) -> tuple[str, str, str, str]:
        return (
            provider_adapter_id,
            provider_config_ref,
            provider_scope_ref,
            tool_reconciliation_version,
        )

    def resolve(
        self, binding: ActionExternalOperationBinding
    ) -> RegisteredOperationReconciler | None:
        return self._registered.get(
            self._key(
                binding.provider_adapter_id,
                binding.provider_config_ref,
                binding.provider_scope_ref,
                binding.tool_reconciliation_version,
            )
        )


@dataclass(frozen=True, slots=True)
class TrustedReconciliationObservation:
    """Raw provider data accompanied by a resolved trusted reconciler contract."""

    identity: ReconciliationIdentity
    contract: ReconcilerContract
    observation: ReconciliationObservation


@dataclass(frozen=True, slots=True)
class ReconciliationApplication:
    action: ActionAttempt
    evidence_recorded: bool
    accepted: bool
    status: str
    stale_reason: str | None = None


class OperationReconciliationService:
    """Applies already-obtained provider observations; it never performs provider I/O."""

    def __init__(
        self,
        session_factory: sessionmaker,
        registry: ReconcilerRegistry | None = None,
    ) -> None:
        self.session_factory = session_factory
        # Production composition registers no reconciler in C-C1. An empty
        # registry fails closed until a later reviewed adapter is composed.
        self.registry = registry or ReconcilerRegistry()

    async def query(self, *, identity: ReconciliationIdentity) -> TrustedReconciliationObservation:
        """Query one registered reconciler outside any SQLite writer transaction."""
        with self.session_factory() as session:
            action, binding = self._load_exact(session, identity)
            registered = self._registered_for_binding(binding)
            canonical_identity = self._identity(action, binding)
        observation = await registered.reconciler.reconcile(canonical_identity)
        self._validate_observation_capability(registered.contract, observation)
        return TrustedReconciliationObservation(
            identity=canonical_identity,
            contract=registered.contract,
            observation=observation,
        )

    async def create_binding(
        self,
        *,
        action_id: str,
        provider_adapter_id: str,
        provider_config_ref: str,
        provider_scope_ref: str,
        tool_reconciliation_version: str,
    ) -> ReconciliationIdentity:
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action = self._action(session, action_id)
                if action.execution_state != "AUTHORIZED" or action.lifecycle_version != 1:
                    raise ConflictError(
                        "External reconciliation binding must precede dispatch",
                        code="ACTION_EXTERNAL_BINDING_STATE_INVALID",
                    )
                binding = session.get(ActionExternalOperationBinding, action_id)
                if binding is None:
                    binding = ActionExternalOperationBinding(
                        run_id=action.run_id,
                        action_id=action.id,
                        provider_adapter_id=provider_adapter_id,
                        provider_config_ref=provider_config_ref,
                        provider_scope_ref=provider_scope_ref,
                        tool_reconciliation_version=tool_reconciliation_version,
                        operation_key=self._operation_key(),
                        created_at=utcnow(),
                    )
                    session.add(binding)
                elif (
                    binding.provider_adapter_id,
                    binding.provider_config_ref,
                    binding.provider_scope_ref,
                    binding.tool_reconciliation_version,
                ) != (
                    provider_adapter_id,
                    provider_config_ref,
                    provider_scope_ref,
                    tool_reconciliation_version,
                ):
                    raise ConflictError(
                        "External operation binding identity mismatch",
                        code="ACTION_EXTERNAL_BINDING_MISMATCH",
                    )
                session.flush()
                identity = self._identity(action, binding)
                session.commit()
                return identity
            except Exception:
                session.rollback()
                raise

    async def bind_provider_handle(
        self, *, identity: ReconciliationIdentity, provider_handle: str
    ) -> ReconciliationIdentity:
        if not provider_handle:
            raise ValueError("provider handle must be non-empty")
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action, binding = self._load_exact(session, identity)
                if binding.provider_handle is None:
                    binding.provider_handle = provider_handle
                    binding.provider_handle_bound_at = utcnow()
                elif binding.provider_handle != provider_handle:
                    raise ConflictError(
                        "Provider handle cannot be overwritten",
                        code="ACTION_PROVIDER_HANDLE_CONFLICT",
                    )
                session.flush()
                result = self._identity(action, binding)
                session.commit()
                return result
            except Exception:
                session.rollback()
                raise

    async def apply(
        self,
        *,
        identity: ReconciliationIdentity,
        observation: ReconciliationObservation,
    ) -> ReconciliationApplication:
        """Reject raw provider data at the public application boundary."""
        raise ConflictError(
            "Raw reconciliation observations cannot mutate durable operation state",
            code="UNTRUSTED_RECONCILIATION_CLAIM",
        )

    async def apply_trusted_observation(
        self,
        *,
        identity: ReconciliationIdentity,
        trusted_observation: TrustedReconciliationObservation,
    ) -> ReconciliationApplication:
        """Apply an observation produced through the registered query boundary."""
        if not isinstance(trusted_observation, TrustedReconciliationObservation):
            raise ConflictError(
                "Material reconciliation requires trusted reconciler provenance",
                code="UNTRUSTED_RECONCILIATION_CLAIM",
            )
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                action, binding = self._load_exact(session, identity)
                self._validate_trusted_observation(binding, identity, trusted_observation)
                observation = trusted_observation.observation
                if not observation.is_material:
                    session.commit()
                    return ReconciliationApplication(action, False, False, observation.kind.value)
                evidence_kind, outcome, payload = self._material_shape(observation)
                conflict = observation.kind == ObservationKind.CONFLICT or self._terminal_conflict(
                    action, observation, payload
                )
                if conflict:
                    evidence_kind = "CONFLICT"
                    outcome = "CONFLICT"
                    payload = self._conflict_payload(action, observation, payload)
                digest = self._evidence_digest(
                    identity, evidence_kind, outcome, payload, observation
                )
                existing = session.scalar(
                    select(ActionReconciliationEvidence).where(
                        ActionReconciliationEvidence.action_id == action.id,
                        ActionReconciliationEvidence.evidence_digest == digest,
                    )
                )
                if existing is not None:
                    session.commit()
                    return ReconciliationApplication(
                        action,
                        False,
                        action.execution_state in {"SUCCEEDED", "FAILED"},
                        "IDEMPOTENT",
                    )
                if conflict:
                    self._add_evidence(
                        session,
                        action,
                        evidence_kind=evidence_kind,
                        outcome=outcome,
                        payload=payload,
                        observation=observation,
                        identity=identity,
                    )
                    if action.execution_state == "DISPATCHED":
                        action.execution_state = "AMBIGUOUS"
                    session.commit()
                    return ReconciliationApplication(action, True, False, "CONFLICT")
                self._add_evidence(
                    session,
                    action,
                    evidence_kind=evidence_kind,
                    outcome=outcome,
                    payload=payload,
                    observation=observation,
                    identity=identity,
                )
                lifecycle = OperationLifecycleService(self.session_factory)
                accepted = await lifecycle._accept_result_in_session(
                    session,
                    action=action,
                    worker_instance_id=identity.worker_instance_id,
                    worker_incarnation=identity.worker_incarnation,
                    tool_name=identity.tool_name,
                    arguments_digest=identity.arguments_digest,
                    result=payload,
                    failed=evidence_kind in {"FAILED", "NONEXECUTION"},
                )
                session.commit()
                return ReconciliationApplication(
                    action,
                    True,
                    accepted.accepted,
                    action.execution_state or "UNKNOWN",
                    accepted.stale_reason,
                )
            except Exception:
                session.rollback()
                raise

    def _registered_for_binding(
        self, binding: ActionExternalOperationBinding
    ) -> RegisteredOperationReconciler:
        registered = self.registry.resolve(binding)
        if registered is None or not registered.contract.matches_binding(binding):
            raise ConflictError(
                "No trusted reconciler contract matches this external operation binding",
                code="RECONCILER_CONTRACT_UNREGISTERED",
            )
        return registered

    def _validate_trusted_observation(
        self,
        binding: ActionExternalOperationBinding,
        identity: ReconciliationIdentity,
        trusted: TrustedReconciliationObservation,
    ) -> None:
        registered = self._registered_for_binding(binding)
        if trusted.identity != identity or trusted.contract is not registered.contract:
            raise ConflictError(
                "Trusted reconciliation provenance does not match the durable binding",
                code="RECONCILER_CONTRACT_MISMATCH",
            )
        self._validate_observation_capability(registered.contract, trusted.observation)

    @staticmethod
    def _validate_observation_capability(
        contract: ReconcilerContract,
        observation: ReconciliationObservation,
    ) -> None:
        if (
            observation.kind == ObservationKind.NOT_FOUND
            and observation.not_found_strength == NotFoundStrength.DEFINITIVE_NONEXECUTION
            and not contract.capabilities.supports_definitive_nonexecution
        ):
            raise ConflictError(
                "Trusted reconciler contract cannot establish definitive nonexecution",
                code="INVALID_RECONCILIATION_CAPABILITY",
            )

    @staticmethod
    def _operation_key() -> str:
        return f"tfop_{uuid4().hex}"

    @staticmethod
    def _action(session: Session, action_id: str) -> ActionAttempt:
        action = session.get(ActionAttempt, action_id)
        if action is None:
            raise NotFoundError(f"Action attempt {action_id} was not found")
        return action

    def _load_exact(
        self, session: Session, identity: ReconciliationIdentity
    ) -> tuple[ActionAttempt, ActionExternalOperationBinding]:
        action = self._action(session, identity.action_id)
        binding = session.get(ActionExternalOperationBinding, action.id)
        if binding is None:
            raise ConflictError(
                "Action has no reconciliation binding", code="ACTION_RECONCILIATION_BINDING_MISSING"
            )
        if self._identity(action, binding) != identity:
            raise ConflictError(
                "Reconciliation identity does not match durable binding",
                code="ACTION_RECONCILIATION_IDENTITY_MISMATCH",
            )
        return action, binding

    @staticmethod
    def _identity(
        action: ActionAttempt, binding: ActionExternalOperationBinding
    ) -> ReconciliationIdentity:
        if action.worker_instance_id is None or action.worker_incarnation is None:
            raise ConflictError(
                "Lifecycle action is missing exact worker ownership",
                code="ACTION_RECONCILIATION_IDENTITY_INVALID",
            )
        return ReconciliationIdentity(
            action.id,
            action.run_id,
            action.node_id,
            action.tool_name,
            action.request_payload_digest,
            action.arguments_digest,
            action.worker_instance_id,
            action.worker_incarnation,
            binding.provider_adapter_id,
            binding.provider_config_ref,
            binding.provider_scope_ref,
            binding.tool_reconciliation_version,
            binding.operation_key,
            binding.provider_handle,
        )

    @staticmethod
    def _material_shape(observation: ReconciliationObservation) -> tuple[str, str, dict[str, Any]]:
        if observation.kind == ObservationKind.SUCCEEDED:
            return "SUCCEEDED", "SUCCESS", dict(observation.result or {})
        if observation.kind == ObservationKind.FAILED:
            return "FAILED", "FAILURE", dict(observation.result or {})
        if (
            observation.kind == ObservationKind.NOT_FOUND
            and observation.not_found_strength == NotFoundStrength.DEFINITIVE_NONEXECUTION
        ):
            return "NONEXECUTION", "NONEXECUTED", {"external_outcome": "NONEXECUTED"}
        if observation.kind == ObservationKind.CONFLICT:
            return "CONFLICT", "CONFLICT", dict(observation.result or {})
        raise ValueError("observation is not material")

    @staticmethod
    def _evidence_digest(
        identity: ReconciliationIdentity,
        kind: str,
        outcome: str,
        payload: dict[str, Any],
        observation: ReconciliationObservation,
    ) -> str:
        return payload_digest(
            {
                "action_id": identity.action_id,
                "provider_adapter_id": identity.provider_adapter_id,
                "provider_config_ref": identity.provider_config_ref,
                "provider_scope_ref": identity.provider_scope_ref,
                "operation_key": identity.operation_key,
                "kind": kind,
                "outcome": outcome,
                "payload": payload,
                "provider_evidence_ref": observation.provider_evidence_ref,
                "provider_evidence_digest": observation.provider_evidence_digest,
            }
        )

    def _add_evidence(
        self,
        session: Session,
        action: ActionAttempt,
        *,
        evidence_kind: str,
        outcome: str,
        payload: dict[str, Any],
        observation: ReconciliationObservation,
        identity: ReconciliationIdentity,
    ) -> None:
        session.add(
            ActionReconciliationEvidence(
                id=str(uuid4()),
                run_id=action.run_id,
                action_id=action.id,
                observation_kind=evidence_kind,
                outcome_class=outcome,
                payload_json=payload,
                payload_digest=payload_digest(payload),
                provider_evidence_ref=observation.provider_evidence_ref,
                provider_evidence_digest=observation.provider_evidence_digest,
                evidence_digest=self._evidence_digest(
                    identity, evidence_kind, outcome, payload, observation
                ),
                observed_at=utcnow(),
                recorded_at=utcnow(),
            )
        )

    @staticmethod
    def _terminal_conflict(
        action: ActionAttempt, observation: ReconciliationObservation, payload: dict[str, Any]
    ) -> bool:
        if action.execution_state not in {"SUCCEEDED", "FAILED", "STALE"}:
            return False
        expected_failed = observation.kind in {ObservationKind.FAILED, ObservationKind.NOT_FOUND}
        return (
            action.execution_state == "STALE"
            or action.result_digest != payload_digest(payload)
            or (action.execution_state == "FAILED") != expected_failed
        )

    @staticmethod
    def _conflict_payload(
        action: ActionAttempt, observation: ReconciliationObservation, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return {"incoming_kind": observation.kind.value, "incoming_payload": payload}
