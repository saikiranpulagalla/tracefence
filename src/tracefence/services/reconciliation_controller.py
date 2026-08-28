"""Bounded, callable orchestration for C-C1 operation reconciliation.

This controller deliberately owns only candidate selection and serial
orchestration. C-C1 remains the sole boundary that resolves a trusted
reconciler, performs the provider status read, and applies material evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import and_, select
from sqlalchemy.orm import sessionmaker

from tracefence.db.models import ActionAttempt, ActionExternalOperationBinding
from tracefence.domain.errors import ConflictError, NotFoundError, ServiceUnavailableError
from tracefence.services.operation_reconciliation import (
    OperationReconciliationService,
    ReconciliationApplication,
)


class ReconciliationActionStatus(StrEnum):
    """Ephemeral result of one bounded controller attempt."""

    RECONCILED_MATERIAL = "RECONCILED_MATERIAL"
    RECONCILED_NON_MATERIAL = "RECONCILED_NON_MATERIAL"
    RECONCILED_CONFLICT = "RECONCILED_CONFLICT"
    SKIPPED_NO_RECONCILER = "SKIPPED_NO_RECONCILER"
    SKIPPED_NO_LONGER_ELIGIBLE = "SKIPPED_NO_LONGER_ELIGIBLE"
    ERROR_TRANSIENT = "ERROR_TRANSIENT"


@dataclass(frozen=True, slots=True)
class ReconciliationActionResult:
    """One non-durable orchestration result.

    service_status and error_code are bounded diagnostic classifications, not
    provider observations or a second source of action authority.
    """

    action_id: str
    status: ReconciliationActionStatus
    service_status: str | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class ReconciliationBatchResult:
    """Immutable summary of one bounded controller invocation."""

    actions: tuple[ReconciliationActionResult, ...]
    selected_count: int
    attempted_count: int
    material_count: int
    non_material_count: int
    conflict_count: int
    skipped_no_reconciler_count: int
    error_count: int
    next_after_action_id: str | None
    has_more: bool


class ReconciliationController:
    """Select and reconcile a bounded set of externally bound unresolved actions.

    The cursor is caller-owned navigation state only. It is neither persisted
    nor authority, and this class intentionally provides no loop, scheduler, or
    startup wiring.
    """

    def __init__(
        self,
        session_factory: sessionmaker,
        reconciliation_service: OperationReconciliationService,
    ) -> None:
        self._session_factory = session_factory
        self._reconciliation_service = reconciliation_service

    async def run_once(
        self,
        *,
        limit: int,
        after_action_id: str | None = None,
    ) -> ReconciliationBatchResult:
        """Reconcile at most limit structurally eligible action IDs serially.

        Candidate selection is a short read session. It is closed before every
        C-C1 call, so provider I/O never occurs in a controller-held database
        transaction. C-C1 reloads the action and remains responsible for all
        live authority and material-outcome decisions.
        """
        self._validate_limit(limit)
        self._validate_cursor(after_action_id)
        selected = self._select_candidate_ids(limit=limit, after_action_id=after_action_id)
        has_more = len(selected) > limit
        attempted_ids = selected[:limit]
        results: list[ReconciliationActionResult] = []

        for action_id in attempted_ids:
            results.append(await self._reconcile_one(action_id))

        action_results = tuple(results)
        return ReconciliationBatchResult(
            actions=action_results,
            selected_count=len(attempted_ids),
            attempted_count=len(attempted_ids),
            material_count=sum(
                result.status == ReconciliationActionStatus.RECONCILED_MATERIAL
                for result in action_results
            ),
            non_material_count=sum(
                result.status == ReconciliationActionStatus.RECONCILED_NON_MATERIAL
                for result in action_results
            ),
            conflict_count=sum(
                result.status == ReconciliationActionStatus.RECONCILED_CONFLICT
                for result in action_results
            ),
            skipped_no_reconciler_count=sum(
                result.status == ReconciliationActionStatus.SKIPPED_NO_RECONCILER
                for result in action_results
            ),
            error_count=sum(
                result.status == ReconciliationActionStatus.ERROR_TRANSIENT
                for result in action_results
            ),
            next_after_action_id=attempted_ids[-1] if attempted_ids else after_action_id,
            has_more=has_more,
        )

    def _select_candidate_ids(self, *, limit: int, after_action_id: str | None) -> tuple[str, ...]:
        """Return immutable IDs from the structural, keyset-paginated query."""
        statement = (
            select(ActionAttempt.id)
            .join(
                ActionExternalOperationBinding,
                and_(
                    ActionExternalOperationBinding.run_id == ActionAttempt.run_id,
                    ActionExternalOperationBinding.action_id == ActionAttempt.id,
                ),
            )
            .where(
                ActionAttempt.lifecycle_version == 1,
                ActionAttempt.execution_state.in_(("DISPATCHED", "AMBIGUOUS")),
            )
            .order_by(ActionAttempt.id.asc())
            .limit(limit + 1)
        )
        if after_action_id is not None:
            statement = statement.where(ActionAttempt.id > after_action_id)
        with self._session_factory() as session:
            return tuple(session.scalars(statement).all())

    async def _reconcile_one(self, action_id: str) -> ReconciliationActionResult:
        try:
            application = await self._reconciliation_service.reconcile_action(action_id=action_id)
        except ConflictError as error:
            if error.code == "RECONCILER_CONTRACT_UNREGISTERED":
                return ReconciliationActionResult(
                    action_id,
                    ReconciliationActionStatus.SKIPPED_NO_RECONCILER,
                    error_code=error.code,
                )
            if error.code in {
                "ACTION_RECONCILIATION_BINDING_MISSING",
                "ACTION_RECONCILIATION_IDENTITY_MISMATCH",
            }:
                return ReconciliationActionResult(
                    action_id,
                    ReconciliationActionStatus.SKIPPED_NO_LONGER_ELIGIBLE,
                    error_code=error.code,
                )
            raise
        except NotFoundError as error:
            return ReconciliationActionResult(
                action_id,
                ReconciliationActionStatus.SKIPPED_NO_LONGER_ELIGIBLE,
                error_code=error.code,
            )
        except (ServiceUnavailableError, TimeoutError, OSError) as error:
            return ReconciliationActionResult(
                action_id,
                ReconciliationActionStatus.ERROR_TRANSIENT,
                error_code=getattr(error, "code", type(error).__name__.upper()),
            )
        return self._result_from_application(action_id, application)

    @staticmethod
    def _result_from_application(
        action_id: str, application: ReconciliationApplication
    ) -> ReconciliationActionResult:
        if application.status == "CONFLICT":
            status = ReconciliationActionStatus.RECONCILED_CONFLICT
        elif application.evidence_recorded or application.status == "IDEMPOTENT":
            status = ReconciliationActionStatus.RECONCILED_MATERIAL
        else:
            status = ReconciliationActionStatus.RECONCILED_NON_MATERIAL
        return ReconciliationActionResult(
            action_id,
            status,
            service_status=application.status,
        )

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit <= 0:
            raise ValueError("limit must be positive")

    @staticmethod
    def _validate_cursor(after_action_id: str | None) -> None:
        if after_action_id is not None and not isinstance(after_action_id, str):
            raise TypeError("after_action_id must be a string or None")
