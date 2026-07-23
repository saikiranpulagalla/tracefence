from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from tracefence.db.models import ControlCommand, ControlScope, Node, Run
from tracefence.domain.enums import NodeStatus, RunStatus, ScopeStatus
from tracefence.domain.errors import AuthenticationError, NotFoundError
from tracefence.security import token_matches


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return f"{value.isoformat(timespec='microseconds')}Z"


@dataclass(frozen=True, slots=True)
class ScopeMismatch:
    scope_id: str
    snapshot_version: int
    live_version: int | None
    live_status: str | None
    reason_code: str


@dataclass(frozen=True, slots=True)
class ScopeEvaluation:
    allowed: bool
    effective_status: NodeStatus
    mismatches: tuple[ScopeMismatch, ...]
    live_scopes: tuple[dict[str, Any], ...]

    @property
    def primary_reason(self) -> str | None:
        return self.mismatches[0].reason_code if self.mismatches else None


async def get_run(session: Session, run_id: str) -> Run:
    run = session.get(Run, run_id)
    if run is None:
        raise NotFoundError(f"Run {run_id} was not found")
    return run


async def get_node(session: Session, node_id: str) -> Node:
    node = session.get(Node, node_id)
    if node is None:
        raise NotFoundError(f"Node {node_id} was not found")
    return node


async def authenticate_node(session: Session, node_id: str, token: str) -> Node:
    node = await get_node(session, node_id)
    if not token_matches(token, node.token_hash):
        raise AuthenticationError("Invalid node token")
    return node


async def evaluate_scopes(session: Session, node: Node) -> ScopeEvaluation:
    snapshot = list(node.scope_snapshot_json or [])
    scope_ids = [item["scope_id"] for item in snapshot]
    if not scope_ids:
        return ScopeEvaluation(False, NodeStatus.CANCELLED, (), ())

    rows = session.execute(
        select(ControlScope).where(ControlScope.id.in_(scope_ids), ControlScope.run_id == node.run_id)
    ).scalars()
    live_by_id = {scope.id: scope for scope in rows}

    mismatches: list[ScopeMismatch] = []
    live_payload: list[dict[str, Any]] = []
    effective_status = NodeStatus.ACTIVE

    for item in snapshot:
        scope_id = item["scope_id"]
        snapshot_version = int(item["version"])
        live = live_by_id.get(scope_id)
        if live is None:
            mismatches.append(
                ScopeMismatch(scope_id, snapshot_version, None, None, "SCOPE_NOT_FOUND")
            )
            effective_status = NodeStatus.CANCELLED
            continue

        live_payload.append(
            {"scope_id": live.id, "version": live.version, "status": live.status}
        )
        if live.status == ScopeStatus.CANCELLED:
            mismatches.append(
                ScopeMismatch(
                    scope_id,
                    snapshot_version,
                    live.version,
                    live.status,
                    "SCOPE_CANCELLED",
                )
            )
            effective_status = NodeStatus.CANCELLED
        elif live.status == ScopeStatus.SUPERSEDED:
            mismatches.append(
                ScopeMismatch(
                    scope_id,
                    snapshot_version,
                    live.version,
                    live.status,
                    "SCOPE_SUPERSEDED",
                )
            )
            if effective_status != NodeStatus.CANCELLED:
                effective_status = NodeStatus.SUPERSEDED
        elif live.version != snapshot_version:
            mismatches.append(
                ScopeMismatch(
                    scope_id,
                    snapshot_version,
                    live.version,
                    live.status,
                    "SCOPE_VERSION_MISMATCH",
                )
            )
            if effective_status == NodeStatus.ACTIVE:
                effective_status = NodeStatus.SUPERSEDED

    return ScopeEvaluation(
        allowed=not mismatches,
        effective_status=effective_status,
        mismatches=tuple(mismatches),
        live_scopes=tuple(live_payload),
    )


async def validate_node_runtime_state(
    session: Session,
    node: Node,
    *,
    require_live_lease: bool = True,
) -> tuple[bool, str | None, ScopeEvaluation]:
    run = await get_run(session, node.run_id)
    evaluation = await evaluate_scopes(session, node)

    if run.status != RunStatus.RUNNING:
        return False, "RUN_NOT_ACTIVE", evaluation
    if node.status not in {NodeStatus.ACTIVE, NodeStatus.WAITING}:
        return False, "NODE_NOT_ACTIVE", evaluation
    if require_live_lease and (node.lease_expires_at is None or node.lease_expires_at <= utcnow()):
        return False, "LEASE_EXPIRED", evaluation
    if not evaluation.allowed:
        return False, evaluation.primary_reason, evaluation
    return True, None, evaluation


async def is_descendant(
    session: Session,
    *,
    run_id: str,
    ancestor_node_id: str,
    target_node_id: str,
) -> bool:
    """Return whether target is a strict descendant using authoritative parent links.

    ``lineage_path`` is a denormalized display/cache field and is deliberately not
    trusted for authorization. Cycle detection makes corrupted registries fail
    closed rather than granting control accidentally.
    """
    if ancestor_node_id == target_node_id:
        return False
    current_id: str | None = target_node_id
    visited: set[str] = set()
    while current_id is not None:
        if current_id in visited:
            return False
        visited.add(current_id)
        node = session.get(Node, current_id)
        if node is None or node.run_id != run_id:
            return False
        parent_id = node.parent_id
        if parent_id == ancestor_node_id:
            return True
        current_id = parent_id
    return False


async def descendants_including_self(
    session: Session,
    *,
    run_id: str,
    root_node_id: str,
    registered_before: datetime | None = None,
) -> list[Node]:
    """Enumerate an authoritative subtree from parent links.

    This is used only for retrospective proof/recovery inspection. Runtime
    enforcement remains O(1) per inherited scope check and never needs subtree
    enumeration.
    """
    query = select(Node).where(Node.run_id == run_id)
    if registered_before is not None:
        query = query.where(Node.registered_at <= registered_before)
    nodes = session.execute(query).scalars().all()
    by_parent: dict[str | None, list[Node]] = {}
    by_id = {node.id: node for node in nodes}
    for node in nodes:
        by_parent.setdefault(node.parent_id, []).append(node)
    root = by_id.get(root_node_id)
    if root is None:
        return []
    result: list[Node] = []
    stack = [root]
    visited: set[str] = set()
    while stack:
        node = stack.pop()
        if node.id in visited:
            continue
        visited.add(node.id)
        result.append(node)
        stack.extend(by_parent.get(node.id, []))
    return result


async def commands_for_scope_mismatches(
    session: Session,
    mismatches: list[ScopeMismatch] | tuple[ScopeMismatch, ...],
    *,
    run_id: str,
) -> list[ControlCommand]:
    """Return every command causally represented by the live scope mismatches.

    A descendant can inherit several invalid scopes when nested or broader commands
    overlap. Recording only the most recent command loses acknowledgement for the
    earlier command. Scope version matching makes attribution exact and excludes
    unrelated historical commands.
    """
    if not mismatches:
        return []
    by_scope = {m.scope_id: m for m in mismatches if m.live_version is not None}
    if not by_scope:
        return []
    rows = session.execute(
        select(ControlCommand).where(
            ControlCommand.run_id == run_id,
            ControlCommand.target_scope_id.in_(list(by_scope)),
        ).order_by(ControlCommand.created_at.asc(), ControlCommand.id.asc())
    ).scalars().all()
    return [
        command
        for command in rows
        if by_scope[command.target_scope_id].live_version == command.to_version
    ]
