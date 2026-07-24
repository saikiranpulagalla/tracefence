from __future__ import annotations

import logging
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from tracefence.config import settings
from tracefence.db.models import ControlCommand, ControlScope, CorrectionProposal, Node
from tracefence.domain.enums import (
    CommandType,
    IssuerType,
    ProposalStatus,
    ProposalType,
    ReplacementStatus,
    RunStatus,
    ScopeStatus,
)
from tracefence.domain.errors import AuthorizationError, ConflictError
from tracefence.domain.schemas import (
    CommandCreate,
    CommandIssued,
    Principal,
    RecoveryContract,
    ReplacementManifest,
    command_authorization_payload,
)
from tracefence.rate_limits import authenticated_rate_limiter
from tracefence.security import payload_digest
from tracefence.services.authority_service import AuthorityService
from tracefence.services.common import (
    authenticate_node,
    get_node,
    get_run,
    is_descendant,
    utcnow,
    validate_node_runtime_state,
)
from tracefence.services.proposal_service import proposal_payload
from tracefence.services.run_lifecycle import transition_run
from tracefence.services.tool_registry import get_tool_spec
from tracefence.telemetry.instruments import telemetry

logger = logging.getLogger(__name__)


class ControlService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory
        self.authority = AuthorityService()

    async def issue_command(
        self,
        request: CommandCreate,
        principal: Principal,
        node_token: str | None = None,
    ) -> CommandIssued:
        request_digest = payload_digest(request.model_dump(mode="json"))
        command: ControlCommand
        scope_status: ScopeStatus
        duplicate = False

        with self.session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                target = await get_node(session, request.target_node_id)
                run = await get_run(session, target.run_id)
                issuer_node: Node | None = None

                if principal.issuer_type == IssuerType.AGENT:
                    if principal.node_id is None or node_token is None:
                        raise AuthorizationError("Agent principal requires a node token")
                    issuer_node = await authenticate_node(session, principal.node_id, node_token)
                    issuer_fingerprint = f"agent:{issuer_node.id}"
                else:
                    issuer_fingerprint = principal.principal_id or "human:operator"

                target_is_descendant = False
                if issuer_node is not None and issuer_node.id != run.root_node_id:
                    target_is_descendant = await is_descendant(
                        session,
                        run_id=run.id,
                        ancestor_node_id=issuer_node.id,
                        target_node_id=target.id,
                    )
                decision = self.authority.may_issue_command(
                    principal,
                    issuer_node,
                    target,
                    run,
                    request.command_type,
                    target_is_descendant=target_is_descendant,
                )
                if not decision.allowed:
                    raise AuthorizationError(f"Command denied: {decision.reason_code}")

                if target.id == run.root_node_id and request.command_type != CommandType.CANCEL_RUN:
                    raise ConflictError(
                        "Root control changes must use CANCEL_RUN in the MVP",
                        code="ROOT_SUBTREE_CONTROL_UNSUPPORTED",
                    )

                existing = session.execute(
                    select(ControlCommand).where(
                        ControlCommand.run_id == run.id,
                        ControlCommand.issuer_fingerprint == issuer_fingerprint,
                        ControlCommand.idempotency_key == request.idempotency_key,
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    if existing.request_payload_digest != request_digest:
                        raise ConflictError(
                            "Idempotency key was reused with a different command payload",
                            code="IDEMPOTENCY_PAYLOAD_MISMATCH",
                        )
                    session.commit()
                    return self._to_response(existing, duplicate=True)

                authenticated_rate_limiter.check(
                    "command",
                    (
                        f"{issuer_node.run_id}:{issuer_node.id}"
                        if issuer_node is not None
                        else issuer_fingerprint
                    ),
                )
                if issuer_node is not None:
                    allowed, reason, _ = await validate_node_runtime_state(
                        session,
                        issuer_node,
                    )
                    if not allowed:
                        raise AuthorizationError(f"Issuer is not live: {reason}")

                if run.status != RunStatus.RUNNING:
                    raise ConflictError(
                        "Terminal runs cannot accept new commands",
                        code="RUN_TERMINAL_STATE",
                    )

                command_count = session.scalar(
                    select(func.count(ControlCommand.id)).where(
                        ControlCommand.run_id == run.id
                    )
                ) or 0
                if command_count >= settings.max_commands_per_run:
                    raise ConflictError(
                        "Command quota exceeded for run",
                        code="RUN_COMMAND_QUOTA_EXCEEDED",
                    )

                source_proposal: CorrectionProposal | None = None
                if request.source_proposal_id is not None:
                    source_proposal = session.get(
                        CorrectionProposal, request.source_proposal_id
                    )
                    if source_proposal is None or source_proposal.run_id != run.id:
                        raise ConflictError(
                            "Source proposal was not found in the target run",
                            code="SOURCE_PROPOSAL_NOT_FOUND",
                        )
                    if source_proposal.status != ProposalStatus.ACCEPTED:
                        raise ConflictError(
                            "Source proposal is not accepted",
                            code="SOURCE_PROPOSAL_NOT_ACCEPTED",
                        )
                    if source_proposal.resulting_command_id is not None:
                        raise ConflictError(
                            "Source proposal already produced a command",
                            code="SOURCE_PROPOSAL_ALREADY_USED",
                        )
                    if source_proposal.target_node_id != target.id:
                        raise ConflictError(
                            "Source proposal targets a different node",
                            code="SOURCE_PROPOSAL_TARGET_MISMATCH",
                        )
                    expected_types = (
                        {CommandType.CORRECT_SUBTREE}
                        if source_proposal.proposal_type == ProposalType.CORRECT
                        else {CommandType.CANCEL_SUBTREE}
                    )
                    if request.command_type not in expected_types:
                        raise ConflictError(
                            "Command type does not match the accepted proposal",
                            code="SOURCE_PROPOSAL_TYPE_MISMATCH",
                        )
                    if source_proposal.accepted_payload_digest != payload_digest(
                        proposal_payload(source_proposal)
                    ):
                        raise ConflictError(
                            "Accepted proposal payload was modified after review",
                            code="SOURCE_PROPOSAL_DIGEST_MISMATCH",
                        )
                    authorized_payload = source_proposal.authorized_command_json
                    if (
                        authorized_payload is None
                        or source_proposal.authorized_command_digest is None
                        or source_proposal.authorized_command_digest
                        != payload_digest(authorized_payload)
                    ):
                        raise ConflictError(
                            "Accepted proposal command authorization is missing or corrupt",
                            code="SOURCE_PROPOSAL_AUTHORIZATION_CORRUPT",
                        )
                    if payload_digest(command_authorization_payload(request)) != (
                        source_proposal.authorized_command_digest
                    ):
                        raise ConflictError(
                            "Command differs from the exact operator-authorized proposal command",
                            code="SOURCE_PROPOSAL_COMMAND_MISMATCH",
                        )

                replacement_manifest: dict | None = None
                if request.command_type == CommandType.CORRECT_SUBTREE:
                    spec = (
                        get_tool_spec(request.replacement_expected_tool)
                        if request.replacement_expected_tool is not None
                        else None
                    )
                    expected_role = (
                        spec.recommended_replacement_role
                        if spec is not None and spec.recommended_replacement_role
                        else f"{target.role}_replacement"
                    )
                    if request.replacement_role not in {None, expected_role}:
                        raise ConflictError(
                            f"Replacement role must be {expected_role}",
                            code="REPLACEMENT_ROLE_POLICY_VIOLATION",
                        )
                    behavior = request.replacement_behavior or "cooperative"
                    if behavior != "cooperative":
                        raise ConflictError(
                            "Correction replacements must use cooperative behavior",
                            code="REPLACEMENT_BEHAVIOR_POLICY_VIOLATION",
                        )
                    exact_capabilities = [spec.capability] if spec is not None else []
                    requested_capabilities = sorted(set(request.replacement_capabilities or exact_capabilities))
                    if requested_capabilities != sorted(exact_capabilities):
                        raise ConflictError(
                            "Replacement capabilities must exactly match the recovery policy",
                            code="REPLACEMENT_CAPABILITY_POLICY_VIOLATION",
                        )
                    expected_arguments = dict(request.replacement_arguments or {})
                    if spec is not None:
                        spec.validate_arguments(expected_arguments)
                        recovery_contract = spec.build_recovery_contract(
                            session,
                            run.id,
                            expected_arguments,
                            request.recovery_stability_seconds,
                        )
                    else:
                        if expected_arguments:
                            raise ConflictError(
                                "Replacement arguments require replacement_expected_tool",
                                code="REPLACEMENT_ARGUMENTS_WITHOUT_TOOL",
                            )
                        recovery_contract = {
                            "schema_version": 1,
                            "expected_tool": None,
                            "expected_arguments_digest": payload_digest({}),
                            "allowed_environment": settings.environment,
                            "allowed_resources": [],
                            "max_committed_invocations": 0,
                            "stability_window_seconds": request.recovery_stability_seconds,
                            "postconditions": [],
                        }
                    max_children = request.replacement_max_children or 0
                    if max_children != 0:
                        raise ConflictError(
                            "Recovery replacements cannot spawn descendants in the current policy",
                            code="REPLACEMENT_CHILD_BUDGET_POLICY_VIOLATION",
                        )
                    replacement_manifest = ReplacementManifest(
                        schema_version=1,
                        policy_version="tracefence-replacement-v1",
                        role=expected_role,
                        behavior="cooperative",
                        instruction_digest=payload_digest(request.replacement_instruction),
                        instruction_version=target.instruction_version + 1,
                        capabilities_exact=requested_capabilities,
                        max_children=max_children,
                        recovery_contract=RecoveryContract.model_validate(
                            recovery_contract
                        ),
                    ).model_dump(mode="json")

                if request.command_type == CommandType.CANCEL_RUN:
                    target_scope_id = run.run_scope_id
                    replacement_parent_id = None
                else:
                    target_scope_id = target.own_scope_id
                    replacement_parent_id = None
                    if request.command_type == CommandType.CORRECT_SUBTREE:
                        intended_parent = (
                            session.get(Node, target.parent_id)
                            if target.parent_id is not None
                            else None
                        )
                        if intended_parent is not None:
                            intended_live, _, _ = await validate_node_runtime_state(
                                session, intended_parent
                            )
                            if intended_live:
                                replacement_parent_id = intended_parent.id
                        if replacement_parent_id is None:
                            root = session.get(Node, run.root_node_id)
                            root_live = False
                            if root is not None and root.id != target.id:
                                root_live, _, _ = await validate_node_runtime_state(
                                    session, root
                                )
                            if not root_live:
                                raise ConflictError(
                                    "No live authorized replacement parent is available",
                                    code="REPLACEMENT_PARENT_UNAVAILABLE",
                                )
                            replacement_parent_id = root.id

                scope = session.get(ControlScope, target_scope_id)
                if scope is None or scope.run_id != run.id:
                    raise ConflictError("Target control scope was not found", code="SCOPE_NOT_FOUND")
                if scope.status != ScopeStatus.ACTIVE:
                    raise ConflictError("Target scope is not active", code="SCOPE_NOT_ACTIVE")

                old_version = scope.version
                scope.version += 1
                scope.status = (
                    ScopeStatus.SUPERSEDED
                    if request.command_type == CommandType.CORRECT_SUBTREE
                    else ScopeStatus.CANCELLED
                )
                scope.updated_by_node_id = issuer_node.id if issuer_node else None
                scope.reason_code = request.reason_code
                scope.updated_at = utcnow()

                if request.command_type == CommandType.CANCEL_RUN:
                    transition_run(
                        session,
                        run,
                        RunStatus.CANCELLED,
                        finished_at=utcnow(),
                    )

                command = ControlCommand(
                    id=str(uuid4()),
                    idempotency_key=request.idempotency_key,
                    issuer_fingerprint=issuer_fingerprint,
                    request_payload_digest=request_digest,
                    run_id=run.id,
                    issuer_node_id=issuer_node.id if issuer_node else None,
                    issuer_type=principal.issuer_type,
                    command_type=request.command_type,
                    source_proposal_id=(source_proposal.id if source_proposal else None),
                    target_node_id=target.id,
                    target_scope_id=target_scope_id,
                    from_version=old_version,
                    to_version=scope.version,
                    reason_code=request.reason_code,
                    reason_text=request.reason_text,
                    replacement_parent_id=replacement_parent_id,
                    replacement_instruction_json=request.replacement_instruction,
                    replacement_expected_tool=request.replacement_expected_tool,
                    replacement_manifest_json=replacement_manifest,
                    replacement_manifest_digest=(
                        payload_digest(replacement_manifest)
                        if replacement_manifest is not None
                        else None
                    ),
                    replacement_node_id=None,
                    replacement_status=(
                        ReplacementStatus.PENDING
                        if request.command_type == CommandType.CORRECT_SUBTREE
                        else None
                    ),
                    created_at=utcnow(),
                )
                session.add(command)
                session.flush()
                if source_proposal is not None:
                    source_proposal.resulting_command_id = command.id
                session.commit()
                scope_status = ScopeStatus(scope.status)
            except IntegrityError as exc:
                session.rollback()
                # A concurrent exact replay may win the uniqueness race. Reload and
                # compare the immutable request digest before returning it.
                with self.session_factory() as replay_session:
                    replay = replay_session.execute(
                        select(ControlCommand).where(
                            ControlCommand.run_id == target.run_id,
                            ControlCommand.issuer_fingerprint == issuer_fingerprint,
                            ControlCommand.idempotency_key == request.idempotency_key,
                        )
                    ).scalar_one_or_none()
                    if replay is not None and replay.request_payload_digest == request_digest:
                        return self._to_response(replay, duplicate=True)
                raise ConflictError("Duplicate command idempotency key") from exc
            except Exception:
                session.rollback()
                raise

        telemetry.commands_total.add(1, {"command_type": request.command_type.value})
        with telemetry.tracer.start_as_current_span("tracefence.control.command_issue") as span:
            span.set_attribute("tracefence.run.id", command.run_id)
            span.set_attribute("tracefence.command.id", command.id)
            span.set_attribute("tracefence.command.type", command.command_type)
            span.set_attribute("tracefence.command.reason_code", command.reason_code)
            span.set_attribute("tracefence.scope.id", command.target_scope_id)
            span.set_attribute("tracefence.scope.snapshot_version", command.from_version)
            span.set_attribute("tracefence.scope.live_version", command.to_version)
            span.set_attribute("tracefence.scope.status", scope_status.value)
            logger.info(
                "command_issued run_id=%s command_id=%s command_type=%s target_node_id=%s "
                "target_scope_id=%s from_version=%s to_version=%s reason_code=%s",
                command.run_id,
                command.id,
                command.command_type,
                command.target_node_id,
                command.target_scope_id,
                command.from_version,
                command.to_version,
                command.reason_code,
                extra={
                    "event": "command_issued",
                    "run_id": command.run_id,
                    "command_id": command.id,
                    "command_type": command.command_type,
                    "target_node_id": command.target_node_id,
                    "target_scope_id": command.target_scope_id,
                    "reason_code": command.reason_code,
                },
            )

        return self._to_response(command, duplicate=duplicate)

    @staticmethod
    def _to_response(command: ControlCommand, *, duplicate: bool) -> CommandIssued:
        return CommandIssued(
            command_id=command.id,
            target_scope_id=command.target_scope_id,
            from_version=command.from_version,
            to_version=command.to_version,
            status=(
                ScopeStatus.SUPERSEDED
                if command.command_type == CommandType.CORRECT_SUBTREE
                else ScopeStatus.CANCELLED
            ),
            replacement_parent_id=command.replacement_parent_id,
            replacement_instruction=command.replacement_instruction_json,
            replacement_expected_tool=command.replacement_expected_tool,
            replacement_manifest=command.replacement_manifest_json,
            replacement_status=(
                ReplacementStatus(command.replacement_status)
                if command.replacement_status is not None
                else None
            ),
            duplicate=duplicate,
        )
