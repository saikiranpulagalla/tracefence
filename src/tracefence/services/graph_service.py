from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from tracefence.db.models import ControlCommand, ControlScope, Node
from tracefence.domain.enums import NodeStatus
from tracefence.domain.schemas import GraphNode, GraphResponse
from tracefence.services.common import evaluate_scopes, get_run, iso_utc, utcnow


class GraphService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def get_graph(self, run_id: str) -> GraphResponse:
        with self.session_factory() as session:
            run = await get_run(session, run_id)
            nodes = session.execute(
                select(Node).where(Node.run_id == run_id).order_by(Node.registered_at)
            ).scalars().all()
            commands = session.execute(
                select(ControlCommand)
                .where(ControlCommand.run_id == run_id)
                .order_by(ControlCommand.created_at)
            ).scalars().all()
            scopes = session.execute(
                select(ControlScope).where(ControlScope.run_id == run_id)
            ).scalars().all()
            scopes_by_id = {scope.id: scope for scope in scopes}

            graph_nodes: list[GraphNode] = []
            edges: list[dict[str, str]] = []
            now = utcnow()
            for node in nodes:
                evaluation = await evaluate_scopes(session, node)
                effective = (
                    evaluation.effective_status
                    if not evaluation.allowed
                    else NodeStatus(node.status)
                )
                own_scope = scopes_by_id.get(node.own_scope_id)
                if own_scope is None:
                    # A missing owned scope is an authoritative-registry corruption.
                    # Keep the graph endpoint fail-closed rather than inventing state.
                    raise RuntimeError(f"Node {node.id} has no owned control scope")
                primary_mismatch = evaluation.mismatches[0] if evaluation.mismatches else None
                graph_nodes.append(
                    GraphNode(
                        id=node.id,
                        parent_id=node.parent_id,
                        supersedes_node_id=node.supersedes_node_id,
                        caused_by_command_id=node.caused_by_command_id,
                        role=node.role,
                        behavior=node.behavior,
                        capabilities=sorted(set(node.capabilities_json or [])),
                        generation=node.generation,
                        declared_status=NodeStatus(node.status),
                        effective_status=effective,
                        instruction_version=node.instruction_version,
                        own_scope_id=node.own_scope_id,
                        own_scope_version=own_scope.version,
                        own_scope_status=own_scope.status,
                        inherited_scope_count=len(node.scope_snapshot_json or []),
                        blocking_scope_id=(
                            primary_mismatch.scope_id if primary_mismatch is not None else None
                        ),
                        blocking_reason=(
                            primary_mismatch.reason_code if primary_mismatch is not None else None
                        ),
                        lease_state=(
                            "NOT_ACTIVATED"
                            if node.status == NodeStatus.PENDING
                            else "TERMINAL"
                            if node.status
                            in {
                                NodeStatus.COMPLETED,
                                NodeStatus.CANCELLED,
                                NodeStatus.SUPERSEDED,
                                NodeStatus.LEASE_EXPIRED,
                            }
                            else "LIVE"
                            if node.lease_expires_at is not None
                            and node.lease_expires_at > now
                            else "EXPIRED"
                        ),
                    )
                )
                if node.parent_id:
                    edges.append({"source": node.parent_id, "target": node.id, "type": "spawn"})
                if node.supersedes_node_id:
                    edges.append(
                        {
                            "source": node.supersedes_node_id,
                            "target": node.id,
                            "type": "supersedes",
                        }
                    )

            return GraphResponse(
                run_id=run.id,
                status=run.status,
                nodes=graph_nodes,
                edges=edges,
                commands=[
                    {
                        "id": command.id,
                        "type": command.command_type,
                        "target_node_id": command.target_node_id,
                        "target_scope_id": command.target_scope_id,
                        "from_version": command.from_version,
                        "to_version": command.to_version,
                        "reason_code": command.reason_code,
                        "source_proposal_id": command.source_proposal_id,
                        "replacement_node_id": command.replacement_node_id,
                        "replacement_manifest_digest": command.replacement_manifest_digest,
                        "replacement_manifest": command.replacement_manifest_json,
                        "created_at": iso_utc(command.created_at),
                    }
                    for command in commands
                ],
            )
