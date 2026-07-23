from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import sessionmaker

from tracefence.config import settings
from tracefence.db.models import ControlScope, Node, Run
from tracefence.domain.enums import NodeStatus, RunStatus, ScopeStatus
from tracefence.domain.errors import ConflictError
from tracefence.domain.schemas import RunCreate, RunCreated
from tracefence.security import generate_token, hash_token
from tracefence.services.common import iso_utc, utcnow
from tracefence.services.tool_registry import TOOL_REGISTRY
from tracefence.telemetry.instruments import telemetry


_ALLOWED_NON_TOOL_CAPABILITIES = {"control:descendants", "tool:propose_correction"}


class RunService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def create_run(self, request: RunCreate) -> RunCreated:
        allowed_capabilities = _ALLOWED_NON_TOOL_CAPABILITIES | {
            spec.capability for spec in TOOL_REGISTRY.values()
        }
        unknown = set(request.root_capabilities) - allowed_capabilities
        if unknown:
            raise ConflictError(
                f"Unknown root capabilities: {', '.join(sorted(unknown))}",
                code="UNKNOWN_CAPABILITY",
            )

        run_id = str(uuid4())
        root_node_id = str(uuid4())
        run_scope_id = str(uuid4())
        root_scope_id = str(uuid4())
        root_token = generate_token()
        now = utcnow()

        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            active_runs = session.scalar(
                select(func.count(Run.id)).where(Run.status.in_([RunStatus.CREATED, RunStatus.RUNNING]))
            ) or 0
            if active_runs >= settings.max_active_runs:
                session.rollback()
                raise ConflictError(
                    "Active run quota exceeded", code="ACTIVE_RUN_QUOTA_EXCEEDED"
                )
            session.add(
                Run(
                    id=run_id,
                    name=request.name,
                    status=RunStatus.RUNNING,
                    root_node_id=root_node_id,
                    run_scope_id=run_scope_id,
                    created_at=now,
                )
            )
            session.flush()
            session.add_all(
                [
                    ControlScope(
                        id=run_scope_id,
                        run_id=run_id,
                        owner_node_id=None,
                        version=1,
                        status=ScopeStatus.ACTIVE,
                        updated_at=now,
                    ),
                    ControlScope(
                        id=root_scope_id,
                        run_id=run_id,
                        owner_node_id=root_node_id,
                        version=1,
                        status=ScopeStatus.ACTIVE,
                        updated_at=now,
                    ),
                ]
            )
            session.add(
                Node(
                    id=root_node_id,
                    run_id=run_id,
                    parent_id=None,
                    supersedes_node_id=None,
                    caused_by_command_id=None,
                    role=request.root_role,
                    behavior="cooperative",
                    generation=0,
                    lineage_path="/",
                    status=NodeStatus.ACTIVE,
                    own_scope_id=root_scope_id,
                    scope_snapshot_json=[
                        {"scope_id": run_scope_id, "version": 1},
                        {"scope_id": root_scope_id, "version": 1},
                    ],
                    instruction_version=1,
                    instruction_json=request.root_instruction,
                    capabilities_json=sorted(set(request.root_capabilities)),
                    token_hash=hash_token(root_token),
                    registered_at=now,
                    activated_at=now,
                    last_heartbeat_at=now,
                    lease_expires_at=now + timedelta(seconds=settings.lease_ttl_seconds),
                )
            )
            session.commit()

        telemetry.runs_total.add(1, {"environment": settings.environment})
        with telemetry.tracer.start_as_current_span("tracefence.run.create") as span:
            span.set_attribute("tracefence.run.id", run_id)
            span.set_attribute("tracefence.node.id", root_node_id)
            span.set_attribute("tracefence.node.role", request.root_role)

        return RunCreated(
            run_id=run_id,
            root_node_id=root_node_id,
            root_token=root_token,
            status=RunStatus.RUNNING,
        )

    async def list_runs(self) -> list[dict]:
        with self.session_factory() as session:
            rows = session.execute(select(Run).order_by(Run.created_at.desc())).scalars().all()
            return [
                {
                    "id": row.id,
                    "name": row.name,
                    "status": row.status,
                    "root_node_id": row.root_node_id,
                    "created_at": iso_utc(row.created_at),
                    "finished_at": iso_utc(row.finished_at),
                }
                for row in rows
            ]
