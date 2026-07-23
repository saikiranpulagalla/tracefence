from __future__ import annotations

from dataclasses import dataclass

from tracefence.db.models import Node, Run
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.schemas import Principal


@dataclass(frozen=True, slots=True)
class AuthorityDecision:
    allowed: bool
    reason_code: str


class AuthorityService:
    @staticmethod
    def may_issue_command(
        principal: Principal,
        issuer_node: Node | None,
        target: Node,
        run: Run,
        command_type: CommandType,
        *,
        target_is_descendant: bool = False,
    ) -> AuthorityDecision:
        if target.run_id != run.id:
            return AuthorityDecision(False, "CROSS_RUN_CONTROL_DENIED")

        # Command-shape constraints apply to every principal, including humans.
        # This prevents a run-wide mutation from carrying a misleading child target
        # that would later corrupt affected-node proof semantics.
        if command_type == CommandType.CANCEL_RUN and target.id != run.root_node_id:
            return AuthorityDecision(False, "RUN_CANCELLATION_TARGET_MUST_BE_ROOT")

        if principal.issuer_type == IssuerType.HUMAN:
            return AuthorityDecision(True, "HUMAN_OPERATOR")

        if issuer_node is None:
            return AuthorityDecision(False, "ISSUER_NODE_REQUIRED")
        if issuer_node.run_id != run.id:
            return AuthorityDecision(False, "CROSS_RUN_CONTROL_DENIED")

        is_root = issuer_node.id == run.root_node_id
        if command_type == CommandType.CANCEL_RUN:
            if not is_root:
                return AuthorityDecision(False, "RUN_CANCELLATION_REQUIRES_ROOT")
            return AuthorityDecision(True, "ROOT_COORDINATOR")

        if is_root:
            return AuthorityDecision(True, "ROOT_COORDINATOR")

        if "control:descendants" not in set(issuer_node.capabilities_json or []):
            return AuthorityDecision(False, "CONTROL_CAPABILITY_REQUIRED")

        if target_is_descendant:
            return AuthorityDecision(True, "AUTHORIZED_ANCESTOR")
        return AuthorityDecision(False, "NON_DESCENDANT_TARGET")
