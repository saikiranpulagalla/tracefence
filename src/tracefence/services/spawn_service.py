from __future__ import annotations

import logging
from datetime import datetime, timedelta
from uuid import uuid4

from opentelemetry.propagate import inject
from pydantic import ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from tracefence.config import settings
from tracefence.db.models import (
    CommandAcknowledgement,
    ControlCommand,
    ControlScope,
    CredentialRecoveryEnvelope,
    Node,
    Run,
    SpawnIntent,
)
from tracefence.domain.enums import (
    AckType,
    CommandType,
    NodeStatus,
    ReplacementStatus,
    RunStatus,
    ScopeStatus,
)
from tracefence.domain.errors import AuthorizationError, ConflictError, NotFoundError
from tracefence.domain.schemas import (
    CheckpointResponse,
    NodeActivate,
    NodeActivated,
    ReplacementManifest,
    SpawnCreate,
    SpawnCreated,
)
from tracefence.rate_limits import authenticated_rate_limiter
from tracefence.security import generate_token, hash_token, payload_digest, token_matches
from tracefence.services.common import (
    authenticate_node,
    commands_for_scope_mismatches,
    evaluate_scopes,
    utcnow,
    validate_node_runtime_state,
)
from tracefence.services.credential_recovery import (
    find_envelope,
    open_envelope,
    recovery_request_digest,
    seal_envelope,
)
from tracefence.services.run_lifecycle import transition_run
from tracefence.services.runtime_events import record_runtime_event
from tracefence.telemetry.instruments import telemetry

logger = logging.getLogger(__name__)


class SpawnService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    async def create_spawn(
        self, parent_node_id: str, parent_token: str, request: SpawnCreate
    ) -> SpawnCreated:
        request_digest = recovery_request_digest(request)
        with telemetry.tracer.start_as_current_span(
            "tracefence.node.spawn_authorize"
        ) as span:
            carrier: dict[str, str] = {}
            inject(carrier)
            with self.session_factory() as session:
                session.execute(text("BEGIN IMMEDIATE"))
                try:
                    parent = await authenticate_node(session, parent_node_id, parent_token)
                    recovered = False
                    if request.operation_key is not None:
                        envelope = find_envelope(
                            session,
                            operation_type="SPAWN",
                            caller_node_id=parent.id,
                            operation_key=request.operation_key,
                            request_digest=request_digest,
                        )
                        if envelope is not None:
                            created = self._recover_spawn_response(
                                session,
                                envelope,
                            )
                            recovered = True
                    if not recovered:
                        authenticated_rate_limiter.check(
                            "spawn",
                            f"{parent.run_id}:{parent.id}",
                        )
                        allowed, reason, _ = await validate_node_runtime_state(
                            session, parent
                        )
                        if not allowed:
                            raise ConflictError(
                                f"Parent cannot spawn: {reason}",
                                code=reason or "SPAWN_DENIED",
                            )
                        self._enforce_graph_budget(session, parent)
                        self._enforce_parent_child_budget(session, parent)
                        self._validate_capability_delegation(parent, request)
                        created = self._create_spawn_locked(
                            session, parent, request, trace_context=carrier
                        )
                        if request.operation_key is not None:
                            # The envelope's composite subject FK requires the
                            # newly registered node to exist first.
                            session.flush()
                            seal_envelope(
                                session,
                                existing=None,
                                run_id=parent.run_id,
                                operation_type="SPAWN",
                                caller_node_id=parent.id,
                                subject_node_id=created.child_node_id,
                                operation_key=request.operation_key,
                                request_digest=request_digest,
                                response=created,
                            )
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
            span.set_attribute("tracefence.node.parent_id", parent_node_id)
            span.set_attribute("tracefence.node.id", created.child_node_id)
            span.set_attribute("tracefence.node.role", request.role)

        self._record_spawn(parent_node_id, created.child_node_id, request.role)
        return created

    async def activate(self, node_id: str, request: NodeActivate) -> NodeActivated:
        permanent_token = generate_token()
        now = utcnow()
        lease_expires_at = now + timedelta(seconds=settings.lease_ttl_seconds)
        request_digest = recovery_request_digest(request)

        with self.session_factory() as session:
            # Serialize token consumption before checking consumed_at. This makes
            # activation a true one-shot compare-and-set on SQLite.
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                node = session.get(Node, node_id)
                if node is None:
                    raise NotFoundError(f"Node {node_id} was not found")
                intent = session.execute(
                    select(SpawnIntent).where(SpawnIntent.child_node_id == node_id)
                ).scalar_one_or_none()
                if intent is None or not token_matches(
                    request.activation_token, intent.activation_token_hash
                ):
                    raise ConflictError(
                        "Invalid activation token", code="INVALID_ACTIVATION_TOKEN"
                    )
                if request.operation_key is not None:
                    envelope = find_envelope(
                        session,
                        operation_type="ACTIVATION",
                        caller_node_id=node.id,
                        operation_key=request.operation_key,
                        request_digest=request_digest,
                    )
                    if envelope is not None:
                        if envelope.expires_at > now:
                            recovered = open_envelope(envelope, NodeActivated)
                            session.commit()
                            return NodeActivated.model_validate(recovered)
                        if (
                            node.status not in {NodeStatus.ACTIVE, NodeStatus.WAITING}
                            or node.lease_expires_at is None
                            or node.lease_expires_at <= now
                        ):
                            raise ConflictError(
                                "Expired activation recovery cannot revive an inactive node",
                                code="CREDENTIAL_RECOVERY_EXPIRED",
                            )
                        permanent_token = generate_token()
                        node.token_hash = hash_token(permanent_token)
                        rotated = NodeActivated(
                            node_id=node.id,
                            run_id=node.run_id,
                            role=node.role,
                            node_token=permanent_token,
                            lease_expires_at=node.lease_expires_at,
                        )
                        seal_envelope(
                            session,
                            existing=envelope,
                            run_id=node.run_id,
                            operation_type="ACTIVATION",
                            caller_node_id=node.id,
                            subject_node_id=node.id,
                            operation_key=request.operation_key,
                            request_digest=request_digest,
                            response=rotated,
                        )
                        session.commit()
                        return rotated
                if intent.consumed_at is not None:
                    raise ConflictError(
                        "Activation token already used", code="ACTIVATION_TOKEN_USED"
                    )
                authenticated_rate_limiter.check(
                    "activation",
                    f"{node.run_id}:{node.id}",
                )
                if intent.expires_at <= now:
                    raise ConflictError(
                        "Activation token expired", code="ACTIVATION_TOKEN_EXPIRED"
                    )
                if node.status != NodeStatus.PENDING or node.token_hash is not None:
                    raise ConflictError("Node is not pending activation", code="NODE_NOT_PENDING")

                evaluation = await evaluate_scopes(session, node)
                if not evaluation.allowed:
                    raise ConflictError(
                        "Inherited control state is no longer active",
                        code=evaluation.primary_reason or "SCOPE_INVALID",
                    )

                intent.consumed_at = now
                node.status = NodeStatus.ACTIVE
                node.token_hash = hash_token(permanent_token)
                node.activated_at = now
                node.last_heartbeat_at = now
                node.lease_expires_at = lease_expires_at
                node.process_id = request.process_id
                if node.caused_by_command_id is not None:
                    command = session.get(ControlCommand, node.caused_by_command_id)
                    if (
                        command is None
                        or command.replacement_node_id != node.id
                        or command.replacement_status != ReplacementStatus.PENDING
                    ):
                        raise ConflictError(
                            "Replacement activation lifecycle is inconsistent",
                            code="REPLACEMENT_LIFECYCLE_INVALID",
                        )
                    command.replacement_status = ReplacementStatus.ACTIVE
                activated = NodeActivated(
                    node_id=node_id,
                    run_id=node.run_id,
                    role=node.role,
                    node_token=permanent_token,
                    lease_expires_at=lease_expires_at,
                )
                if request.operation_key is not None:
                    seal_envelope(
                        session,
                        existing=None,
                        run_id=node.run_id,
                        operation_type="ACTIVATION",
                        caller_node_id=node.id,
                        subject_node_id=node.id,
                        operation_key=request.operation_key,
                        request_digest=request_digest,
                        response=activated,
                    )
                record_runtime_event(
                    session,
                    run_id=node.run_id,
                    event_type="NODE_ACTIVATED",
                    occurred_at=now,
                    node_id=node.id,
                    parent_node_id=node.parent_id,
                    command_id=node.caused_by_command_id,
                    metadata={"role": node.role},
                )
                record_runtime_event(
                    session,
                    run_id=node.run_id,
                    event_type="LEASE_GRANTED",
                    occurred_at=now,
                    node_id=node.id,
                    metadata={
                        "lease_expires_at": lease_expires_at.isoformat(
                            timespec="microseconds"
                        )
                        + "Z"
                    },
                )
                session.commit()
            except Exception:
                session.rollback()
                raise

        logger.info("node_activated node_id=%s", node_id)
        with telemetry.tracer.start_as_current_span("tracefence.node.activate") as span:
            span.set_attribute("tracefence.node.id", node_id)
        return activated

    async def heartbeat(self, node_id: str, node_token: str) -> Node:
        now = utcnow()
        denial_code: str | None = None
        node: Node
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                node = await authenticate_node(session, node_id, node_token)
                authenticated_rate_limiter.check(
                    "heartbeat",
                    f"{node.run_id}:{node.id}",
                )
                run = session.get(Run, node.run_id)
                if run is None:
                    raise NotFoundError(f"Run {node.run_id} was not found")
                if run.status != RunStatus.RUNNING:
                    denial_code = "RUN_NOT_ACTIVE"
                elif node.status not in {NodeStatus.ACTIVE, NodeStatus.WAITING}:
                    denial_code = "NODE_NOT_ACTIVE"
                elif node.lease_expires_at is None or node.lease_expires_at <= now:
                    node.status = NodeStatus.LEASE_EXPIRED
                    await self._record_lease_expiry_ack(session, node, now)
                    record_runtime_event(
                        session,
                        run_id=node.run_id,
                        event_type="LEASE_EXPIRED",
                        occurred_at=now,
                        node_id=node.id,
                        parent_node_id=node.parent_id,
                    )
                    denial_code = "LEASE_EXPIRED"
                else:
                    evaluation = await evaluate_scopes(session, node)
                    if not evaluation.allowed:
                        commands = await commands_for_scope_mismatches(
                            session,
                            evaluation.mismatches,
                            run_id=node.run_id,
                        )
                        for command in commands:
                            self._record_ack(
                                session,
                                node.run_id,
                                command.id,
                                node.id,
                                AckType.COOPERATIVE,
                                command.to_version,
                                now,
                            )
                        node.status = evaluation.effective_status
                        denial_code = evaluation.primary_reason or "SCOPE_INVALID"
                    else:
                        node.last_heartbeat_at = now
                        node.lease_expires_at = now + timedelta(
                            seconds=settings.lease_ttl_seconds
                        )
                        record_runtime_event(
                            session,
                            run_id=node.run_id,
                            event_type="LEASE_RENEWED",
                            occurred_at=now,
                            node_id=node.id,
                            parent_node_id=node.parent_id,
                            metadata={
                                "lease_expires_at": node.lease_expires_at.isoformat(
                                    timespec="microseconds"
                                )
                                + "Z"
                            },
                        )
                session.commit()
            except Exception:
                session.rollback()
                raise

        if denial_code is not None:
            if denial_code == "LEASE_EXPIRED":
                telemetry.leases_expired_total.add(1)
            raise ConflictError(
                f"Heartbeat denied: {denial_code}",
                code=denial_code,
            )
        return node

    async def checkpoint(
        self, node_id: str, node_token: str, stage: str
    ) -> CheckpointResponse:
        with self.session_factory() as session, session.begin():
            node = await authenticate_node(session, node_id, node_token)
            authenticated_rate_limiter.check(
                "heartbeat",
                f"{node.run_id}:{node.id}",
            )
            allowed, reason, evaluation = await validate_node_runtime_state(session, node)
            if allowed:
                node.status = NodeStatus.WAITING
                now = utcnow()
                record_runtime_event(
                    session,
                    run_id=node.run_id,
                    event_type="NODE_WAITING",
                    occurred_at=now,
                    node_id=node.id,
                    parent_node_id=node.parent_id,
                    command_id=node.caused_by_command_id,
                    metadata={"stage": stage},
                )
                logger.info(
                    "checkpoint_allowed node_id=%s stage=%s", node.id, stage
                )
                return CheckpointResponse(allowed=True, effective_status=NodeStatus.WAITING)

            commands = await commands_for_scope_mismatches(
                session, evaluation.mismatches, run_id=node.run_id
            )
            command = commands[-1] if commands else None
            effective_status = evaluation.effective_status
            if reason == "LEASE_EXPIRED":
                # A checkpoint is itself an authoritative runtime boundary. Persist
                # lease expiry immediately instead of reporting an expired node as
                # effectively ACTIVE until the background scanner happens to run.
                node.status = NodeStatus.LEASE_EXPIRED
                effective_status = NodeStatus.LEASE_EXPIRED
                await self._record_lease_expiry_ack(session, node, utcnow())
                telemetry.leases_expired_total.add(1)
            elif commands:
                observed_at = utcnow()
                for applicable_command in commands:
                    self._record_ack(
                        session,
                        node.run_id,
                        applicable_command.id,
                        node.id,
                        AckType.COOPERATIVE,
                        applicable_command.to_version,
                        observed_at,
                    )
                    latency_ms = max(
                        0.0,
                        (observed_at - applicable_command.created_at).total_seconds() * 1000,
                    )
                    telemetry.control_ack_latency_ms.record(latency_ms)
                node.status = evaluation.effective_status

            logger.info(
                "checkpoint_denied node_id=%s stage=%s reason_code=%s command_id=%s",
                node.id,
                stage,
                reason,
                command.id if command else None,
            )
            return CheckpointResponse(
                allowed=False,
                effective_status=effective_status,
                command_id=command.id if command else None,
                reason_code=reason,
            )

    async def complete(self, node_id: str, node_token: str) -> None:
        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                node = await authenticate_node(session, node_id, node_token)
                authenticated_rate_limiter.check(
                    "heartbeat",
                    f"{node.run_id}:{node.id}",
                )
                allowed, reason, _ = await validate_node_runtime_state(session, node)
                if not allowed:
                    raise ConflictError(
                        f"Node cannot complete: {reason}",
                        code=reason or "COMPLETE_DENIED",
                    )

                run = session.get(Run, node.run_id)
                if run is None:
                    raise NotFoundError(f"Run {node.run_id} was not found")
                if run.root_node_id == node.id:
                    others = session.execute(
                        select(Node).where(
                            Node.run_id == node.run_id,
                            Node.id != node.id,
                        )
                    ).scalars().all()
                    live_nodes: list[str] = []
                    expired_count = 0
                    now = utcnow()
                    for other in others:
                        if other.status in {
                            NodeStatus.COMPLETED,
                            NodeStatus.CANCELLED,
                            NodeStatus.SUPERSEDED,
                            NodeStatus.LEASE_EXPIRED,
                        }:
                            continue

                        expired = False
                        if other.status in {
                            NodeStatus.ACTIVE,
                            NodeStatus.WAITING,
                        }:
                            expired = (
                                other.lease_expires_at is None
                                or other.lease_expires_at <= now
                            )
                        elif other.status == NodeStatus.PENDING:
                            intent = session.execute(
                                select(SpawnIntent).where(
                                    SpawnIntent.child_node_id == other.id,
                                    SpawnIntent.run_id == other.run_id,
                                )
                            ).scalar_one_or_none()
                            expired = (
                                intent is None
                                or intent.consumed_at is None
                                and intent.expires_at <= now
                            )

                        if expired:
                            other.status = NodeStatus.LEASE_EXPIRED
                            await self._record_lease_expiry_ack(
                                session,
                                other,
                                now,
                            )
                            expired_count += 1
                            continue

                        other_evaluation = await evaluate_scopes(session, other)
                        if other_evaluation.allowed:
                            live_nodes.append(other.id)
                    if expired_count:
                        telemetry.leases_expired_total.add(expired_count)
                    if live_nodes:
                        raise ConflictError(
                            "Root cannot complete while valid descendant nodes remain live",
                            code="RUN_HAS_LIVE_NODES",
                        )
                    transition_run(
                        session,
                        run,
                        RunStatus.COMPLETED,
                        finished_at=utcnow(),
                    )

                node.status = NodeStatus.COMPLETED
                completed_at = utcnow()
                node.completed_at = completed_at
                if node.caused_by_command_id is not None:
                    command = session.get(ControlCommand, node.caused_by_command_id)
                    if (
                        command is None
                        or command.replacement_node_id != node.id
                        or command.replacement_status != ReplacementStatus.ACTIVE
                    ):
                        raise ConflictError(
                            "Replacement completion lifecycle is inconsistent",
                            code="REPLACEMENT_LIFECYCLE_INVALID",
                        )
                    command.replacement_status = ReplacementStatus.COMPLETED
                record_runtime_event(
                    session,
                    run_id=node.run_id,
                    event_type="NODE_COMPLETED",
                    occurred_at=completed_at,
                    node_id=node.id,
                    parent_node_id=node.parent_id,
                    command_id=node.caused_by_command_id,
                )
                if node.caused_by_command_id is not None:
                    record_runtime_event(
                        session,
                        run_id=node.run_id,
                        event_type="RECOVERY_COMPLETED",
                        occurred_at=completed_at,
                        node_id=node.id,
                        parent_node_id=node.parent_id,
                        command_id=node.caused_by_command_id,
                    )
                session.commit()
            except Exception:
                session.rollback()
                raise

    async def create_replacement(
        self,
        parent_node_id: str,
        parent_token: str,
        correction_command_id: str,
        request: SpawnCreate,
    ) -> SpawnCreated:
        request_digest = recovery_request_digest(
            request,
            context=correction_command_id,
        )
        with telemetry.tracer.start_as_current_span(
            "tracefence.node.spawn_replacement"
        ) as span:
            carrier: dict[str, str] = {}
            inject(carrier)
            with self.session_factory() as session:
                session.execute(text("BEGIN IMMEDIATE"))
                try:
                    parent = await authenticate_node(session, parent_node_id, parent_token)
                    recovered = False
                    command: ControlCommand | None = None
                    if request.operation_key is not None:
                        envelope = find_envelope(
                            session,
                            operation_type="REPLACEMENT",
                            caller_node_id=parent.id,
                            operation_key=request.operation_key,
                            request_digest=request_digest,
                        )
                        if envelope is not None:
                            command = session.get(
                                ControlCommand,
                                correction_command_id,
                            )
                            if (
                                command is None
                                or command.replacement_node_id
                                != envelope.subject_node_id
                            ):
                                raise ConflictError(
                                    "Recovered replacement does not match the command",
                                    code="CREDENTIAL_RECOVERY_SUBJECT_MISMATCH",
                                )
                            created = self._recover_spawn_response(
                                session,
                                envelope,
                            )
                            recovered = True
                    if not recovered:
                        authenticated_rate_limiter.check(
                            "spawn",
                            f"{parent.run_id}:{parent.id}",
                        )
                        allowed, reason, _ = await validate_node_runtime_state(
                            session, parent
                        )
                        if not allowed:
                            raise ConflictError(
                                f"Replacement parent is not live: {reason}",
                                code=reason or "REPLACEMENT_PARENT_DENIED",
                            )
                        command = session.get(ControlCommand, correction_command_id)
                    if command is None:
                        raise NotFoundError(
                            f"Correction command {correction_command_id} was not found"
                        )
                    if command.command_type != CommandType.CORRECT_SUBTREE:
                        raise ConflictError(
                            "Replacement requires a CORRECT_SUBTREE command",
                            code="REPLACEMENT_COMMAND_INVALID",
                        )
                    if command.run_id != parent.run_id:
                        raise AuthorizationError("Cross-run replacement is not allowed")
                    if command.replacement_parent_id != parent.id:
                        raise AuthorizationError(
                            "Only the command-designated parent may create the replacement"
                        )
                    if not recovered and command.replacement_node_id is not None:
                        prior_replacement = session.get(
                            Node,
                            command.replacement_node_id,
                        )
                        retry_allowed = (
                            command.replacement_status
                            == ReplacementStatus.ACTIVATION_EXPIRED
                            and prior_replacement is not None
                            and prior_replacement.status == NodeStatus.LEASE_EXPIRED
                        )
                        if not retry_allowed:
                            raise ConflictError(
                                "Correction command already has a replacement node",
                                code="REPLACEMENT_ALREADY_CREATED",
                            )

                    if not recovered:
                        self._enforce_graph_budget(session, parent)

                    old = session.get(Node, command.target_node_id)
                    scope = session.get(ControlScope, command.target_scope_id)
                    if old is None or scope is None:
                        raise ConflictError(
                            "Correction lineage is incomplete",
                            code="CORRECTION_LINEAGE_INVALID",
                        )
                    run = session.get(Run, command.run_id)
                    root_fallback = (
                        run is not None
                        and parent.id == run.root_node_id
                        and command.replacement_parent_id == parent.id
                    )
                    if old.run_id != parent.run_id or (
                        old.parent_id != parent.id and not root_fallback
                    ):
                        raise ConflictError(
                            "Replacement must use the command-authorized parent",
                            code="REPLACEMENT_PARENT_MISMATCH",
                        )
                    if old.own_scope_id != command.target_scope_id:
                        raise ConflictError(
                            "Command does not target the corrected node's owned scope",
                            code="CORRECTION_SCOPE_MISMATCH",
                        )
                    if (
                        scope.status != ScopeStatus.SUPERSEDED
                        or scope.version != command.to_version
                    ):
                        raise ConflictError(
                            "Correction scope is not in the expected superseded state",
                            code="CORRECTION_SCOPE_NOT_SUPERSEDED",
                        )
                    if payload_digest(request.instruction) != payload_digest(
                        command.replacement_instruction_json
                    ):
                        raise ConflictError(
                            "Replacement instruction does not match the correction command",
                            code="REPLACEMENT_INSTRUCTION_MISMATCH",
                        )

                    manifest = command.replacement_manifest_json
                    if (
                        manifest is None
                        or command.replacement_manifest_digest != payload_digest(manifest)
                    ):
                        raise ConflictError(
                            "Correction replacement manifest is missing or corrupted",
                            code="REPLACEMENT_MANIFEST_INVALID",
                        )
                    try:
                        manifest_model = ReplacementManifest.model_validate(manifest)
                    except ValidationError as exc:
                        raise ConflictError(
                            "Correction replacement manifest violates its schema",
                            code="REPLACEMENT_MANIFEST_INVALID",
                        ) from exc
                    manifest = manifest_model.model_dump(mode="json")
                    expected_capabilities = manifest_model.capabilities_exact
                    manifest_matches = (
                        request.role == manifest.get("role")
                        and request.behavior == manifest.get("behavior")
                        and sorted(set(request.capabilities)) == expected_capabilities
                        and payload_digest(request.instruction) == manifest.get("instruction_digest")
                        and old.instruction_version + 1 == manifest.get("instruction_version")
                    )
                    if not manifest_matches:
                        raise ConflictError(
                            "Replacement does not exactly match the authorized manifest",
                            code="REPLACEMENT_MANIFEST_MISMATCH",
                        )
                    self._validate_capability_delegation(parent, request)

                    if not recovered:
                        created = self._create_spawn_locked(
                            session,
                            parent,
                            request,
                            supersedes_node_id=old.id,
                            caused_by_command_id=command.id,
                            instruction_version=old.instruction_version + 1,
                            trace_context=carrier,
                        )
                        # The command's replacement FK points at the newly inserted
                        # node. Flush the node/scope/intent first so SQLite can validate
                        # the subsequent command update without relying on ORM ordering.
                        session.flush()
                        command.replacement_node_id = created.child_node_id
                        command.replacement_status = ReplacementStatus.PENDING
                        if request.operation_key is not None:
                            seal_envelope(
                                session,
                                existing=None,
                                run_id=parent.run_id,
                                operation_type="REPLACEMENT",
                                caller_node_id=parent.id,
                                subject_node_id=created.child_node_id,
                                operation_key=request.operation_key,
                                request_digest=request_digest,
                                response=created,
                            )
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
            span.set_attribute("tracefence.run.id", command.run_id)
            span.set_attribute("tracefence.command.id", command.id)
            span.set_attribute("tracefence.node.parent_id", parent_node_id)
            span.set_attribute("tracefence.node.id", created.child_node_id)
            span.set_attribute("tracefence.node.role", request.role)

        self._record_spawn(parent_node_id, created.child_node_id, request.role)
        return created

    @staticmethod
    def _recover_spawn_response(
        session: Session,
        envelope: CredentialRecoveryEnvelope,
    ) -> SpawnCreated:
        now = utcnow()
        node = session.get(Node, envelope.subject_node_id)
        intent = session.execute(
            select(SpawnIntent).where(
                SpawnIntent.child_node_id == envelope.subject_node_id
            )
        ).scalar_one_or_none()
        if (
            node is None
            or intent is None
            or node.status != NodeStatus.PENDING
            or intent.consumed_at is not None
            or intent.expires_at <= now
        ):
            raise ConflictError(
                "Spawn credential is no longer recoverable",
                code="CREDENTIAL_RECOVERY_EXPIRED",
            )
        if envelope.expires_at > now:
            recovered = open_envelope(envelope, SpawnCreated)
            return SpawnCreated.model_validate(recovered)

        activation_token = generate_token()
        intent.activation_token_hash = hash_token(activation_token)
        intent.expires_at = utcnow() + timedelta(
            seconds=settings.spawn_intent_ttl_seconds
        )
        recovered = SpawnCreated(
            child_node_id=node.id,
            activation_token=activation_token,
            expires_at=intent.expires_at,
            trace_context=dict(intent.trace_context_json or {}),
        )
        seal_envelope(
            session,
            existing=envelope,
            run_id=envelope.run_id,
            operation_type=envelope.operation_type,
            caller_node_id=envelope.caller_node_id,
            subject_node_id=envelope.subject_node_id,
            operation_key=envelope.operation_key,
            request_digest=envelope.request_payload_digest,
            response=recovered,
        )
        return recovered

    def _create_spawn_locked(
        self,
        session: Session,
        parent: Node,
        request: SpawnCreate,
        *,
        supersedes_node_id: str | None = None,
        caused_by_command_id: str | None = None,
        instruction_version: int = 1,
        trace_context: dict[str, str] | None = None,
    ) -> SpawnCreated:
        child_id = str(uuid4())
        child_scope_id = str(uuid4())
        activation_token = generate_token()
        expires_at = utcnow() + timedelta(
            seconds=settings.spawn_intent_ttl_seconds
        )
        now = utcnow()

        session.add(
            ControlScope(
                id=child_scope_id,
                run_id=parent.run_id,
                owner_node_id=child_id,
                version=1,
                status=ScopeStatus.ACTIVE,
                updated_at=now,
            )
        )
        snapshot = [
            *list(parent.scope_snapshot_json),
            {"scope_id": child_scope_id, "version": 1},
        ]
        session.add(
            Node(
                id=child_id,
                run_id=parent.run_id,
                parent_id=parent.id,
                supersedes_node_id=supersedes_node_id,
                caused_by_command_id=caused_by_command_id,
                role=request.role,
                behavior=request.behavior,
                generation=parent.generation + 1,
                lineage_path=f"{parent.lineage_path}{parent.id}/",
                status=NodeStatus.PENDING,
                own_scope_id=child_scope_id,
                scope_snapshot_json=snapshot,
                instruction_version=instruction_version,
                instruction_json=request.instruction,
                capabilities_json=sorted(set(request.capabilities)),
                token_hash=None,
                registered_at=now,
            )
        )
        session.add(
            SpawnIntent(
                id=str(uuid4()),
                run_id=parent.run_id,
                parent_node_id=parent.id,
                child_node_id=child_id,
                activation_token_hash=hash_token(activation_token),
                requested_role=request.role,
                instruction_json=request.instruction,
                requested_capabilities_json=sorted(set(request.capabilities)),
                trace_context_json=dict(trace_context or {}),
                expires_at=expires_at,
            )
        )
        record_runtime_event(
            session,
            run_id=parent.run_id,
            event_type=(
                "REPLACEMENT_CREATED"
                if caused_by_command_id is not None
                else "NODE_REGISTERED"
            ),
            occurred_at=now,
            node_id=child_id,
            parent_node_id=parent.id,
            command_id=caused_by_command_id,
            scope_id=child_scope_id,
            snapshot_version=1,
            authoritative_version=1,
            metadata={
                "role": request.role,
                "generation": parent.generation + 1,
                "supersedes_node_id": supersedes_node_id,
            },
        )
        return SpawnCreated(
            child_node_id=child_id,
            activation_token=activation_token,
            expires_at=expires_at,
            trace_context=dict(trace_context or {}),
        )

    @staticmethod
    def _enforce_graph_budget(session: Session, parent: Node) -> None:
        if parent.generation + 1 > settings.max_graph_depth:
            raise ConflictError(
                "Maximum graph depth exceeded", code="GRAPH_DEPTH_QUOTA_EXCEEDED"
            )
        node_count = session.scalar(
            select(func.count(Node.id)).where(Node.run_id == parent.run_id)
        ) or 0
        if node_count >= settings.max_nodes_per_run:
            raise ConflictError(
                "Maximum nodes per run exceeded", code="RUN_NODE_QUOTA_EXCEEDED"
            )
        child_count = session.scalar(
            select(func.count(Node.id)).where(
                Node.run_id == parent.run_id, Node.parent_id == parent.id
            )
        ) or 0
        if child_count >= settings.max_children_per_node:
            raise ConflictError(
                "Maximum children per node exceeded",
                code="NODE_CHILD_QUOTA_EXCEEDED",
            )

    @staticmethod
    def _enforce_parent_child_budget(session: Session, parent: Node) -> None:
        if parent.caused_by_command_id is None:
            return
        command = session.get(ControlCommand, parent.caused_by_command_id)
        manifest = command.replacement_manifest_json if command is not None else None
        if manifest is None:
            raise ConflictError(
                "Replacement parent has no authoritative manifest",
                code="REPLACEMENT_MANIFEST_MISSING",
            )
        try:
            manifest_model = ReplacementManifest.model_validate(manifest)
        except ValidationError as exc:
            raise ConflictError(
                "Replacement parent manifest violates its schema",
                code="REPLACEMENT_MANIFEST_INVALID",
            ) from exc
        max_children = manifest_model.max_children
        existing_children = session.scalar(
            select(func.count(Node.id)).where(
                Node.run_id == parent.run_id,
                Node.parent_id == parent.id,
            )
        ) or 0
        if existing_children >= max_children:
            raise ConflictError(
                "Replacement child budget is exhausted",
                code="REPLACEMENT_CHILD_BUDGET_EXCEEDED",
            )

    @staticmethod
    def _validate_capability_delegation(parent: Node, request: SpawnCreate) -> None:
        parent_caps = set(parent.capabilities_json or [])
        requested_caps = set(request.capabilities)
        if not requested_caps.issubset(parent_caps):
            raise AuthorizationError("Requested capabilities are not delegable by parent")

    async def _record_lease_expiry_ack(
        self, session: Session, node: Node, now: datetime
    ) -> None:
        evaluation = await evaluate_scopes(session, node)
        commands = await commands_for_scope_mismatches(
            session, evaluation.mismatches, run_id=node.run_id
        )
        for command in commands:
            self._record_ack(
                session,
                node.run_id,
                command.id,
                node.id,
                AckType.LEASE_EXPIRED,
                command.to_version,
                now,
            )

    @staticmethod
    def _record_ack(
        session: Session,
        run_id: str,
        command_id: str,
        node_id: str,
        ack_type: AckType,
        observed_version: int,
        observed_at: datetime,
    ) -> None:
        existing = session.execute(
            select(CommandAcknowledgement).where(
                CommandAcknowledgement.command_id == command_id,
                CommandAcknowledgement.node_id == node_id,
                CommandAcknowledgement.ack_type == ack_type,
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                CommandAcknowledgement(
                    id=str(uuid4()),
                    run_id=run_id,
                    command_id=command_id,
                    node_id=node_id,
                    ack_type=ack_type,
                    observed_at=observed_at,
                    observed_scope_version=observed_version,
                )
            )

    @staticmethod
    def _record_spawn(parent_id: str, child_id: str, role: str) -> None:
        telemetry.nodes_spawned_total.add(1, {"node_role": role})
        logger.info(
            "node_spawn_authorized parent_node_id=%s child_node_id=%s role=%s",
            parent_id,
            child_id,
            role,
        )
