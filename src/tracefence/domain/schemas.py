from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tracefence.domain.enums import (
    ActionDecision,
    CommandType,
    IssuerType,
    NodeStatus,
    ProofVerdict,
    ProposalStatus,
    ProposalType,
    ReplacementStatus,
    RunStatus,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


_ALLOWED_CAPABILITIES = {
    "control:descendants",
    "tool:read_metrics",
    "tool:propose_correction",
    "tool:restart_postgres",
    "tool:reset_redis_pool",
}


def _canonical_capabilities(values: list[str]) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError("Capabilities must be unique")
    unknown = sorted(set(values) - _ALLOWED_CAPABILITIES)
    if unknown:
        raise ValueError(f"Unsupported capabilities: {', '.join(unknown)}")
    return sorted(values)


class RunCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    root_role: str = Field(default="coordinator", min_length=1, max_length=80)
    root_instruction: dict[str, Any] = Field(default_factory=dict)
    root_capabilities: list[str] = Field(
        default_factory=lambda: [
            "control:descendants",
            "tool:read_metrics",
            "tool:propose_correction",
        ],
        max_length=32,
    )

    @model_validator(mode="after")
    def validate_root_capabilities(self) -> "RunCreate":
        self.root_capabilities = _canonical_capabilities(self.root_capabilities)
        return self


class RunCreated(BaseModel):
    run_id: str
    root_node_id: str
    root_token: str
    status: RunStatus


class SpawnCreate(StrictModel):
    operation_key: str | None = Field(default=None, min_length=4, max_length=160)
    role: str = Field(min_length=1, max_length=80)
    instruction: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    behavior: Literal["cooperative", "non_compliant"] = "cooperative"

    @model_validator(mode="after")
    def validate_capabilities(self) -> "SpawnCreate":
        self.capabilities = _canonical_capabilities(self.capabilities)
        return self


class SpawnCreated(BaseModel):
    child_node_id: str
    activation_token: str
    expires_at: datetime
    trace_context: dict[str, str] = Field(default_factory=dict)


class NodeActivate(StrictModel):
    operation_key: str | None = Field(default=None, min_length=4, max_length=160)
    activation_token: str = Field(min_length=16)
    process_id: int | None = Field(default=None, ge=1)


class NodeActivated(BaseModel):
    node_id: str
    run_id: str
    role: str
    node_token: str
    lease_expires_at: datetime


class HeartbeatRequest(StrictModel):
    worker_state: str = Field(default="RUNNING", max_length=40)
    current_operation: str | None = Field(default=None, max_length=120)


class CheckpointRequest(StrictModel):
    stage: str = Field(min_length=1, max_length=80)


class CheckpointResponse(BaseModel):
    allowed: bool
    effective_status: NodeStatus
    command_id: str | None = None
    reason_code: str | None = None


class ProposalCreate(StrictModel):
    target_node_id: str
    proposal_type: ProposalType
    reason: str = Field(min_length=1, max_length=1000)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ProposalCommandAuthorization(StrictModel):
    command_type: CommandType
    target_node_id: str
    reason_code: str = Field(min_length=1, max_length=80)
    reason_text: str = Field(min_length=1, max_length=1000)
    replacement_instruction: dict[str, Any] | None = None
    replacement_expected_tool: str | None = Field(default=None, min_length=1, max_length=100)
    replacement_role: str | None = Field(default=None, min_length=1, max_length=80)
    replacement_behavior: str | None = Field(default=None, min_length=1, max_length=80)
    replacement_capabilities: list[str] | None = Field(default=None, max_length=32)
    replacement_arguments: dict[str, Any] | None = None
    replacement_max_children: int | None = Field(default=None, ge=0, le=32)
    recovery_stability_seconds: int = Field(default=0, ge=0, le=300)

    @model_validator(mode="after")
    def validate_authorization_shape(self) -> "ProposalCommandAuthorization":
        if self.command_type == CommandType.CANCEL_RUN:
            raise ValueError("Proposals cannot authorize CANCEL_RUN")
        if self.command_type == CommandType.CORRECT_SUBTREE:
            if self.replacement_instruction is None:
                raise ValueError("CORRECT_SUBTREE requires replacement_instruction")
        elif any(
            value is not None
            for value in (
                self.replacement_instruction,
                self.replacement_expected_tool,
                self.replacement_role,
                self.replacement_behavior,
                self.replacement_capabilities,
                self.replacement_arguments,
                self.replacement_max_children,
            )
        ) or self.recovery_stability_seconds != 0:
            raise ValueError("Replacement fields are valid only for CORRECT_SUBTREE")
        if self.replacement_capabilities is not None:
            self.replacement_capabilities = _canonical_capabilities(
                self.replacement_capabilities
            )
        return self


class ProposalReview(StrictModel):
    status: ProposalStatus
    authorized_command: ProposalCommandAuthorization | None = None

    @model_validator(mode="after")
    def terminal_review_only(self) -> "ProposalReview":
        if self.status not in {ProposalStatus.ACCEPTED, ProposalStatus.REJECTED}:
            raise ValueError("Proposal review status must be ACCEPTED or REJECTED")
        if self.status == ProposalStatus.ACCEPTED and self.authorized_command is None:
            raise ValueError("Accepted proposals require an exact authorized command")
        if self.status == ProposalStatus.REJECTED and self.authorized_command is not None:
            raise ValueError("Rejected proposals cannot authorize a command")
        return self


class CommandCreate(StrictModel):
    idempotency_key: str = Field(min_length=4, max_length=160)
    command_type: CommandType
    source_proposal_id: str | None = None
    target_node_id: str
    reason_code: str = Field(min_length=1, max_length=80)
    reason_text: str = Field(min_length=1, max_length=1000)
    replacement_instruction: dict[str, Any] | None = None
    replacement_expected_tool: str | None = Field(default=None, min_length=1, max_length=100)
    replacement_role: str | None = Field(default=None, min_length=1, max_length=80)
    replacement_behavior: str | None = Field(default=None, min_length=1, max_length=80)
    replacement_capabilities: list[str] | None = Field(default=None, max_length=32)
    replacement_arguments: dict[str, Any] | None = None
    replacement_max_children: int | None = Field(default=None, ge=0, le=32)
    recovery_stability_seconds: int = Field(default=0, ge=0, le=300)

    @model_validator(mode="after")
    def validate_command_shape(self) -> "CommandCreate":
        if self.command_type == CommandType.CORRECT_SUBTREE:
            if self.replacement_instruction is None:
                raise ValueError("CORRECT_SUBTREE requires replacement_instruction")
        elif any(
            value is not None
            for value in (
                self.replacement_instruction,
                self.replacement_expected_tool,
                self.replacement_role,
                self.replacement_behavior,
                self.replacement_capabilities,
                self.replacement_arguments,
                self.replacement_max_children,
            )
        ) or self.recovery_stability_seconds != 0:
            raise ValueError("Replacement fields are valid only for CORRECT_SUBTREE")
        return self


def command_authorization_payload(request: CommandCreate) -> dict[str, Any]:
    """Return the exact operator-reviewed command body, excluding replay metadata."""

    value = request.model_dump(
        mode="json",
        exclude={"idempotency_key", "source_proposal_id"},
    )
    return ProposalCommandAuthorization.model_validate(value).model_dump(mode="json")


class RecoveryPostcondition(StrictModel):
    service_name: str = Field(min_length=1, max_length=80)
    field: Literal["status", "restart_count", "pool_reset_count"]
    operator: Literal["equals"] = "equals"
    expected: Any
    require_recovery_action: bool = True


class RecoveryContract(StrictModel):
    schema_version: Literal[1] = 1
    expected_tool: str | None = Field(default=None, max_length=100)
    expected_arguments_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_environment: str = Field(min_length=1, max_length=80)
    allowed_resources: list[str] = Field(default_factory=list, max_length=32)
    max_committed_invocations: int = Field(ge=0, le=16)
    stability_window_seconds: int = Field(ge=0, le=300)
    postconditions: list[RecoveryPostcondition] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_tool_shape(self) -> "RecoveryContract":
        if len(self.allowed_resources) != len(set(self.allowed_resources)):
            raise ValueError("Recovery resources must be unique")
        if self.allowed_resources != sorted(self.allowed_resources):
            raise ValueError("Recovery resources must be canonically sorted")
        if self.expected_tool is None:
            if (
                self.max_committed_invocations != 0
                or self.postconditions
                or self.allowed_resources
            ):
                raise ValueError(
                    "A recovery contract without a tool cannot require resources, "
                    "invocations or postconditions"
                )
        elif self.max_committed_invocations < 1:
            raise ValueError("A recovery tool requires at least one allowed committed invocation")
        return self


class ReplacementManifest(StrictModel):
    schema_version: Literal[1] = 1
    policy_version: Literal["tracefence-replacement-v1"]
    role: str = Field(min_length=1, max_length=80)
    behavior: Literal["cooperative"]
    instruction_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    instruction_version: int = Field(ge=1)
    capabilities_exact: list[str] = Field(default_factory=list, max_length=32)
    max_children: int = Field(ge=0, le=32)
    recovery_contract: RecoveryContract

    @model_validator(mode="after")
    def validate_capabilities(self) -> "ReplacementManifest":
        if len(self.capabilities_exact) != len(set(self.capabilities_exact)):
            raise ValueError("Replacement capabilities must be unique")
        if self.capabilities_exact != sorted(self.capabilities_exact):
            raise ValueError("Replacement capabilities must be canonically sorted")
        expected_tool = self.recovery_contract.expected_tool
        if expected_tool is None and self.capabilities_exact:
            raise ValueError("A replacement without a recovery tool cannot receive capabilities")
        return self


class CommandIssued(BaseModel):
    command_id: str
    target_scope_id: str
    from_version: int
    to_version: int
    status: str
    replacement_parent_id: str | None = None
    replacement_instruction: dict[str, Any] | None = None
    replacement_expected_tool: str | None = None
    replacement_manifest: dict[str, Any] | None = None
    replacement_status: ReplacementStatus | None = None
    duplicate: bool = False


class ActionExecute(StrictModel):
    idempotency_key: str = Field(min_length=4, max_length=160)
    tool_name: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ActionResult(BaseModel):
    action_id: str
    decision: ActionDecision
    denial_reason: str | None = None
    committed: bool
    result: dict[str, Any] | None = None
    duplicate: bool = False


class GraphNode(BaseModel):
    id: str
    parent_id: str | None
    supersedes_node_id: str | None
    caused_by_command_id: str | None
    role: str
    behavior: str
    capabilities: list[str]
    generation: int
    declared_status: NodeStatus
    effective_status: NodeStatus
    instruction_version: int
    lease_state: str
    own_scope_id: str
    own_scope_version: int
    own_scope_status: str
    inherited_scope_count: int
    blocking_scope_id: str | None = None
    blocking_reason: str | None = None


class GraphResponse(BaseModel):
    run_id: str
    status: RunStatus
    nodes: list[GraphNode]
    edges: list[dict[str, str]]
    commands: list[dict[str, Any]]


class ProofResponse(BaseModel):
    command_id: str
    command_type: CommandType
    affected_registered_nodes: int
    classifications: dict[str, int]
    stale_action_attempts: int
    stale_actions_committed: int
    unrelated_branches_interrupted: int
    control_convergence_verdict: ProofVerdict
    replacement_lineage_verdict: ProofVerdict
    recovery_action_verdict: ProofVerdict
    recovery_postcondition_verdict: ProofVerdict
    recovery_stability_verdict: ProofVerdict
    recovery_outcome_verdict: ProofVerdict
    runtime_verdict: ProofVerdict
    telemetry_verdict: ProofVerdict
    overall_verdict: ProofVerdict
    trace_ids: list[str]
    discrepancies: list[str]


class Principal(BaseModel):
    issuer_type: IssuerType
    node_id: str | None = None
    principal_id: str | None = None
