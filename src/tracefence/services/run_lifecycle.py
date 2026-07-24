from __future__ import annotations

from datetime import datetime

from sqlalchemy import update
from sqlalchemy.orm import Session

from tracefence.db.models import Run
from tracefence.domain.enums import RunStatus
from tracefence.domain.errors import ConflictError
from tracefence.services.common import utcnow

RUN_STATE_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.CREATED: frozenset(
        {RunStatus.RUNNING, RunStatus.CANCELLED, RunStatus.FAILED}
    ),
    RunStatus.RUNNING: frozenset(
        {RunStatus.COMPLETED, RunStatus.CANCELLED, RunStatus.FAILED}
    ),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
    RunStatus.FAILED: frozenset(),
}

TERMINAL_RUN_STATES = frozenset(
    {RunStatus.COMPLETED, RunStatus.CANCELLED, RunStatus.FAILED}
)


def transition_run(
    session: Session,
    run: Run,
    target: RunStatus,
    *,
    finished_at: datetime | None = None,
) -> None:
    """Conditionally perform one allowed run transition.

    The source status and NULL terminal timestamp are part of the UPDATE
    predicate, so concurrent terminal operations have exactly one winner.
    Terminal statuses have no outgoing edges and the original ``finished_at``
    can never be overwritten by this API.
    """

    source = RunStatus(run.status)
    if target not in RUN_STATE_TRANSITIONS[source]:
        code = (
            "RUN_TERMINAL_STATE"
            if source in TERMINAL_RUN_STATES
            else "RUN_TRANSITION_INVALID"
        )
        raise ConflictError(
            f"Run transition {source.value} -> {target.value} is not allowed",
            code=code,
        )
    terminal_at = finished_at or utcnow()
    result = session.execute(
        update(Run)
        .where(
            Run.id == run.id,
            Run.status == source,
            Run.finished_at.is_(None),
        )
        .values(
            status=target,
            finished_at=(terminal_at if target in TERMINAL_RUN_STATES else None),
        )
        .execution_options(synchronize_session=False)
    )
    if getattr(result, "rowcount", 0) != 1:
        session.expire(run)
        raise ConflictError(
            "Run state changed concurrently",
            code="RUN_TERMINAL_STATE",
        )
    session.expire(run)
    session.refresh(run)
