from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from tracefence.db.models import RuntimeEvent
from tracefence.services.common import utcnow


def record_runtime_event(
    session: Session,
    *,
    run_id: str,
    event_type: str,
    occurred_at: datetime | None = None,
    node_id: str | None = None,
    parent_node_id: str | None = None,
    command_id: str | None = None,
    action_id: str | None = None,
    scope_id: str | None = None,
    decision: str | None = None,
    reason_code: str | None = None,
    snapshot_version: int | None = None,
    authoritative_version: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> RuntimeEvent:
    """Record a fact already decided by an authoritative service.

    Callers must pass their existing transaction-bound Session. This helper does
    not commit, evaluate policy, or catch persistence errors: a covered domain
    transition and its projection succeed or fail together.
    """

    event = RuntimeEvent(
        run_id=run_id,
        event_type=event_type,
        occurred_at=occurred_at or utcnow(),
        node_id=node_id,
        parent_node_id=parent_node_id,
        command_id=command_id,
        action_id=action_id,
        scope_id=scope_id,
        decision=decision,
        reason_code=reason_code,
        snapshot_version=snapshot_version,
        authoritative_version=authoritative_version,
        metadata_json=dict(metadata or {}),
    )
    session.add(event)
    return event
