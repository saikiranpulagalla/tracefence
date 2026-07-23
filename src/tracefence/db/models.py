from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    # SQLite does not preserve timezone offsets. Store canonical naive UTC and
    # expose ISO timestamps with an explicit Z at API boundaries.
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class SchemaMetadata(Base):
    __tablename__ = "schema_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["id", "root_node_id"],
            ["nodes.run_id", "nodes.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_run_root_node",
        ),
        ForeignKeyConstraint(
            ["id", "run_scope_id"],
            ["control_scopes.run_id", "control_scopes.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_run_scope",
        ),
        CheckConstraint(
            "status IN ('CREATED','RUNNING','COMPLETED','CANCELLED','FAILED')",
            name="ck_run_status",
        ),
        CheckConstraint("root_node_id IS NOT NULL", name="ck_run_root_required"),
        CheckConstraint(
            "(status IN ('COMPLETED','CANCELLED','FAILED') AND finished_at IS NOT NULL) OR "
            "(status IN ('CREATED','RUNNING') AND finished_at IS NULL)",
            name="ck_run_finished_shape",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(24))
    root_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    run_scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    proof_revision: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )


class Node(Base):
    __tablename__ = "nodes"
    __table_args__ = (
        ForeignKeyConstraint(["run_id", "parent_id"], ["nodes.run_id", "nodes.id"]),
        ForeignKeyConstraint(
            ["run_id", "supersedes_node_id"], ["nodes.run_id", "nodes.id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "caused_by_command_id"],
            ["control_commands.run_id", "control_commands.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_node_correction_command",
        ),
        ForeignKeyConstraint(
            ["run_id", "own_scope_id", "id"],
            [
                "control_scopes.run_id",
                "control_scopes.id",
                "control_scopes.owner_node_id",
            ],
            ondelete="RESTRICT",
        ),
        UniqueConstraint("run_id", "id", name="uq_node_run_id"),
        CheckConstraint(
            "status IN ('PENDING','ACTIVE','WAITING','COMPLETED','CANCELLED','SUPERSEDED','LEASE_EXPIRED')",
            name="ck_node_status",
        ),
        CheckConstraint(
            "behavior IN ('cooperative','non_compliant')",
            name="ck_node_behavior",
        ),
        CheckConstraint("generation >= 0", name="ck_node_generation_nonnegative"),
        CheckConstraint("instruction_version >= 1", name="ck_node_instruction_version_positive"),
        CheckConstraint(
            "(generation = 0 AND parent_id IS NULL) OR "
            "(generation > 0 AND parent_id IS NOT NULL)",
            name="ck_node_generation_parent_shape",
        ),
        CheckConstraint(
            "status NOT IN ('ACTIVE','WAITING','COMPLETED') OR activated_at IS NOT NULL",
            name="ck_node_activation_shape",
        ),
        CheckConstraint(
            "status != 'COMPLETED' OR completed_at IS NOT NULL",
            name="ck_node_completion_shape",
        ),
        Index("ix_nodes_run", "run_id"),
        Index("ix_nodes_parent", "parent_id"),
        Index("ix_nodes_caused_by_command", "caused_by_command_id"),
        Index("ix_nodes_lineage", "lineage_path"),
        Index("ix_nodes_lease", "lease_expires_at"),
        Index("ix_nodes_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    parent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    supersedes_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    caused_by_command_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    role: Mapped[str] = mapped_column(String(80))
    behavior: Mapped[str] = mapped_column(String(80), default="cooperative")
    generation: Mapped[int] = mapped_column(Integer, default=0)
    lineage_path: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24))
    own_scope_id: Mapped[str] = mapped_column(String(36))
    scope_snapshot_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    instruction_version: Mapped[int] = mapped_column(Integer, default=1)
    instruction_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    capabilities_json: Mapped[list[str]] = mapped_column(JSON)
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ControlScope(Base):
    __tablename__ = "control_scopes"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "owner_node_id"],
            ["nodes.run_id", "nodes.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_scope_owner_node",
        ),
        ForeignKeyConstraint(
            ["run_id", "updated_by_node_id"],
            ["nodes.run_id", "nodes.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_scope_updated_by_node",
        ),
        UniqueConstraint("run_id", "id", name="uq_scope_run_id"),
        UniqueConstraint(
            "run_id", "id", "owner_node_id", name="uq_scope_run_owner"
        ),
        CheckConstraint("version >= 1", name="ck_scope_version_positive"),
        CheckConstraint(
            "status IN ('ACTIVE','CANCELLED','SUPERSEDED')",
            name="ck_scope_status",
        ),
        Index("ix_scopes_run", "run_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    owner_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(24))
    updated_by_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SpawnIntent(Base):
    __tablename__ = "spawn_intents"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "parent_node_id"], ["nodes.run_id", "nodes.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["run_id", "child_node_id"], ["nodes.run_id", "nodes.id"], ondelete="CASCADE"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    parent_node_id: Mapped[str] = mapped_column(String(36))
    child_node_id: Mapped[str] = mapped_column(String(36), unique=True)
    activation_token_hash: Mapped[str] = mapped_column(String(64))
    requested_role: Mapped[str] = mapped_column(String(80))
    instruction_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    requested_capabilities_json: Mapped[list[str]] = mapped_column(JSON)
    trace_context_json: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CredentialRecoveryEnvelope(Base):
    __tablename__ = "credential_recovery_envelopes"
    __table_args__ = (
        UniqueConstraint(
            "operation_type",
            "caller_node_id",
            "operation_key",
            name="uq_credential_recovery_operation",
        ),
        ForeignKeyConstraint(
            ["run_id", "caller_node_id"],
            ["nodes.run_id", "nodes.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["run_id", "subject_node_id"],
            ["nodes.run_id", "nodes.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "operation_type IN ('SPAWN','REPLACEMENT','ACTIVATION')",
            name="ck_credential_recovery_operation_type",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    operation_type: Mapped[str] = mapped_column(String(24))
    caller_node_id: Mapped[str] = mapped_column(String(36))
    subject_node_id: Mapped[str] = mapped_column(String(36))
    operation_key: Mapped[str] = mapped_column(String(160))
    request_payload_digest: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(24))
    ciphertext: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CorrectionProposal(Base):
    __tablename__ = "correction_proposals"
    __table_args__ = (
        UniqueConstraint("run_id", "id", name="uq_proposal_run_id"),
        ForeignKeyConstraint(
            ["run_id", "reporter_node_id"], ["nodes.run_id", "nodes.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["run_id", "target_node_id"], ["nodes.run_id", "nodes.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["run_id", "reviewed_by_node_id"], ["nodes.run_id", "nodes.id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "resulting_command_id"],
            ["control_commands.run_id", "control_commands.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_proposal_resulting_command",
        ),
        UniqueConstraint("resulting_command_id", name="uq_proposal_resulting_command"),
        CheckConstraint(
            "proposal_type IN ('CANCEL','CORRECT')", name="ck_proposal_type"
        ),
        CheckConstraint(
            "status IN ('PENDING','ACCEPTED','REJECTED')", name="ck_proposal_status"
        ),
        CheckConstraint(
            "(status = 'PENDING' AND reviewed_at IS NULL AND reviewed_by_principal IS NULL "
            "AND accepted_payload_digest IS NULL AND authorized_command_json IS NULL "
            "AND authorized_command_digest IS NULL AND resulting_command_id IS NULL) OR "
            "(status IN ('ACCEPTED','REJECTED') AND reviewed_at IS NOT NULL "
            "AND reviewed_by_principal IS NOT NULL AND accepted_payload_digest IS NOT NULL "
            "AND ((status = 'ACCEPTED' AND authorized_command_json IS NOT NULL "
            "AND authorized_command_digest IS NOT NULL) OR "
            "(status = 'REJECTED' AND authorized_command_json IS NULL "
            "AND authorized_command_digest IS NULL AND resulting_command_id IS NULL)))",
            name="ck_proposal_review_shape",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    reporter_node_id: Mapped[str] = mapped_column(String(36))
    target_node_id: Mapped[str] = mapped_column(String(36))
    proposal_type: Mapped[str] = mapped_column(String(24))
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24))
    reviewed_by_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_by_principal: Mapped[str | None] = mapped_column(String(120), nullable=True)
    accepted_payload_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    authorized_command_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    authorized_command_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    resulting_command_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ControlCommand(Base):
    __tablename__ = "control_commands"
    __table_args__ = (
        UniqueConstraint(
            "run_id", "issuer_fingerprint", "idempotency_key", name="uq_command_idempotency"
        ),
        ForeignKeyConstraint(
            ["run_id", "issuer_node_id"], ["nodes.run_id", "nodes.id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "target_node_id"], ["nodes.run_id", "nodes.id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "target_scope_id"], ["control_scopes.run_id", "control_scopes.id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "replacement_parent_id"], ["nodes.run_id", "nodes.id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "replacement_node_id"], ["nodes.run_id", "nodes.id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "source_proposal_id"],
            ["correction_proposals.run_id", "correction_proposals.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_command_source_proposal",
        ),
        UniqueConstraint("source_proposal_id", name="uq_command_source_proposal"),
        UniqueConstraint("run_id", "id", name="uq_command_run_id"),
        UniqueConstraint(
            "run_id",
            "id",
            "target_scope_id",
            "to_version",
            name="uq_command_exact_scope_version",
        ),
        UniqueConstraint(
            "run_id", "id", "to_version", name="uq_command_exact_version"
        ),
        CheckConstraint(
            "issuer_type IN ('HUMAN','AGENT')", name="ck_command_issuer_type"
        ),
        CheckConstraint(
            "command_type IN ('CANCEL_RUN','CANCEL_SUBTREE','CORRECT_SUBTREE')",
            name="ck_command_type",
        ),
        CheckConstraint("to_version = from_version + 1", name="ck_command_version_step"),
        CheckConstraint(
            "(issuer_type = 'HUMAN' AND issuer_node_id IS NULL) OR "
            "(issuer_type = 'AGENT' AND issuer_node_id IS NOT NULL)",
            name="ck_command_issuer_shape",
        ),
        CheckConstraint(
            "(command_type = 'CORRECT_SUBTREE' AND replacement_parent_id IS NOT NULL "
            "AND replacement_instruction_json IS NOT NULL "
            "AND replacement_manifest_json IS NOT NULL AND replacement_manifest_digest IS NOT NULL "
            "AND replacement_status IS NOT NULL) OR "
            "(command_type != 'CORRECT_SUBTREE' AND replacement_parent_id IS NULL "
            "AND replacement_instruction_json IS NULL AND replacement_expected_tool IS NULL "
            "AND replacement_manifest_json IS NULL AND replacement_manifest_digest IS NULL "
            "AND replacement_node_id IS NULL AND replacement_status IS NULL)",
            name="ck_command_replacement_shape",
        ),
        CheckConstraint(
            "replacement_status IS NULL OR replacement_status IN "
            "('PENDING','ACTIVATION_EXPIRED','ACTIVE','COMPLETED','FAILED')",
            name="ck_command_replacement_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(String(160))
    issuer_fingerprint: Mapped[str] = mapped_column(String(80))
    request_payload_digest: Mapped[str] = mapped_column(String(64))
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    issuer_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    issuer_type: Mapped[str] = mapped_column(String(16))
    command_type: Mapped[str] = mapped_column(String(32))
    source_proposal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target_node_id: Mapped[str] = mapped_column(String(36))
    target_scope_id: Mapped[str] = mapped_column(String(36))
    from_version: Mapped[int] = mapped_column(Integer)
    to_version: Mapped[int] = mapped_column(Integer)
    reason_code: Mapped[str] = mapped_column(String(80))
    reason_text: Mapped[str] = mapped_column(Text)
    replacement_parent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    replacement_instruction_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    replacement_expected_tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    replacement_manifest_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    replacement_manifest_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    replacement_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True)
    replacement_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CommandAcknowledgement(Base):
    __tablename__ = "command_acknowledgements"
    __table_args__ = (
        UniqueConstraint(
            "run_id", "command_id", "node_id", "ack_type", name="uq_command_ack"
        ),
        ForeignKeyConstraint(
            ["run_id", "command_id"],
            ["control_commands.run_id", "control_commands.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["run_id", "node_id"], ["nodes.run_id", "nodes.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["run_id", "command_id", "observed_scope_version"],
            ["control_commands.run_id", "control_commands.id", "control_commands.to_version"],
            ondelete="CASCADE",
            name="fk_ack_exact_command_version",
        ),
        CheckConstraint(
            "ack_type IN ('COOPERATIVE','GATEWAY_BLOCK','LEASE_EXPIRED')",
            name="ck_command_ack_type",
        ),
        CheckConstraint("observed_scope_version >= 1", name="ck_ack_version_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    command_id: Mapped[str] = mapped_column(String(36))
    node_id: Mapped[str] = mapped_column(String(36))
    ack_type: Mapped[str] = mapped_column(String(24))
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    observed_scope_version: Mapped[int] = mapped_column(Integer)


class ActionAttempt(Base):
    __tablename__ = "action_attempts"
    __table_args__ = (
        UniqueConstraint("node_id", "idempotency_key", name="uq_action_idempotency"),
        ForeignKeyConstraint(
            ["run_id", "node_id"], ["nodes.run_id", "nodes.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["run_id", "matched_scope_id"],
            ["control_scopes.run_id", "control_scopes.id"],
        ),
        ForeignKeyConstraint(
            ["run_id", "matched_command_id"],
            ["control_commands.run_id", "control_commands.id"],
        ),
        ForeignKeyConstraint(
            ["run_id", "matched_command_id", "matched_scope_id", "matched_live_version"],
            [
                "control_commands.run_id",
                "control_commands.id",
                "control_commands.target_scope_id",
                "control_commands.to_version",
            ],
            name="fk_action_exact_command_scope_version",
        ),
        UniqueConstraint("run_id", "id", name="uq_action_run_id"),
        CheckConstraint("decision IN ('ALLOW','DENY')", name="ck_action_decision"),
        CheckConstraint(
            "(decision = 'DENY' AND denial_reason IS NOT NULL "
            "AND committed_at IS NULL AND result_json IS NULL AND result_digest IS NULL) OR "
            "(decision = 'ALLOW' AND denial_reason IS NULL AND committed_at IS NOT NULL "
            "AND result_json IS NOT NULL AND result_digest IS NOT NULL)",
            name="ck_action_result_shape",
        ),
        CheckConstraint(
            "(matched_command_id IS NULL AND matched_scope_id IS NULL "
            "AND matched_snapshot_version IS NULL AND matched_live_version IS NULL "
            "AND matched_live_status IS NULL) OR "
            "(matched_command_id IS NOT NULL AND matched_scope_id IS NOT NULL "
            "AND matched_snapshot_version IS NOT NULL AND matched_live_version IS NOT NULL "
            "AND matched_live_status IS NOT NULL)",
            name="ck_action_match_shape",
        ),
        Index("ix_actions_run", "run_id"),
        Index("ix_actions_node", "node_id"),
        Index("ix_actions_command", "matched_command_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    node_id: Mapped[str] = mapped_column(String(36))
    tool_name: Mapped[str] = mapped_column(String(100))
    side_effecting: Mapped[bool] = mapped_column(Boolean, default=True)
    idempotency_key: Mapped[str] = mapped_column(String(160))
    decision: Mapped[str] = mapped_column(String(16))
    denial_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    matched_command_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    matched_scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    matched_snapshot_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    matched_live_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    matched_live_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    scope_evaluation_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    request_payload_digest: Mapped[str] = mapped_column(String(64))
    arguments_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    arguments_digest: Mapped[str] = mapped_column(String(64))
    result_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    result_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ActionCommandMatch(Base):
    __tablename__ = "action_command_matches"
    __table_args__ = (
        PrimaryKeyConstraint("action_id", "command_id", name="pk_action_command_match"),
        ForeignKeyConstraint(
            ["run_id", "action_id"],
            ["action_attempts.run_id", "action_attempts.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["run_id", "command_id"],
            ["control_commands.run_id", "control_commands.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["run_id", "command_id", "scope_id", "live_version"],
            [
                "control_commands.run_id",
                "control_commands.id",
                "control_commands.target_scope_id",
                "control_commands.to_version",
            ],
            ondelete="CASCADE",
            name="fk_action_match_exact_command_scope_version",
        ),
        ForeignKeyConstraint(
            ["run_id", "scope_id"],
            ["control_scopes.run_id", "control_scopes.id"],
        ),
        CheckConstraint("snapshot_version >= 1", name="ck_action_match_snapshot_version"),
        CheckConstraint("live_version >= 1", name="ck_action_match_live_version"),
        CheckConstraint(
            "live_status IN ('ACTIVE','CANCELLED','SUPERSEDED')",
            name="ck_action_match_live_status",
        ),
        Index("ix_action_command_matches_command", "command_id"),
    )

    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    action_id: Mapped[str] = mapped_column(String(36))
    command_id: Mapped[str] = mapped_column(String(36))
    scope_id: Mapped[str] = mapped_column(String(36))
    snapshot_version: Mapped[int] = mapped_column(Integer)
    live_version: Mapped[int] = mapped_column(Integer)
    live_status: Mapped[str] = mapped_column(String(24))


class InvariantViolation(Base):
    __tablename__ = "invariant_violations"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "command_id",
            "action_id",
            "violation_type",
            name="uq_invariant_violation",
        ),
        ForeignKeyConstraint(
            ["run_id", "command_id"],
            ["control_commands.run_id", "control_commands.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["run_id", "action_id"],
            ["action_attempts.run_id", "action_attempts.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "violation_type IN ('STALE_ACTION_COMMITTED')",
            name="ck_invariant_violation_type",
        ),
        Index("ix_invariant_violations_run", "run_id"),
        Index("ix_invariant_violations_command", "command_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    command_id: Mapped[str] = mapped_column(String(36))
    action_id: Mapped[str] = mapped_column(String(36))
    violation_type: Mapped[str] = mapped_column(String(64))
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TelemetryOutbox(Base):
    __tablename__ = "telemetry_outbox"
    __table_args__ = (
        UniqueConstraint("event_key", name="uq_telemetry_outbox_event_key"),
        CheckConstraint("attempts >= 0", name="ck_outbox_attempts_nonnegative"),
        CheckConstraint(
            "event_type IN ('tracefence.stale_action_committed')",
            name="ck_outbox_event_type",
        ),
        CheckConstraint(
            "(delivered_at IS NULL) OR (attempts >= 1 AND last_error IS NULL)",
            name="ck_outbox_delivery_shape",
        ),
        Index("ix_telemetry_outbox_pending", "delivered_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_key: Mapped[str] = mapped_column(String(200))
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(80))
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ServiceState(Base):
    __tablename__ = "service_state"
    __table_args__ = (
        PrimaryKeyConstraint("run_id", "service_name", name="pk_service_state"),
        ForeignKeyConstraint(
            ["run_id", "last_action_id"], ["action_attempts.run_id", "action_attempts.id"]
        ),
        CheckConstraint("restart_count >= 0", name="ck_restart_count_nonnegative"),
        CheckConstraint("pool_reset_count >= 0", name="ck_pool_reset_count_nonnegative"),
        CheckConstraint(
            "status IN ('healthy','degraded','connection_pool_exhausted')",
            name="ck_service_state_status",
        ),
    )

    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    service_name: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(80))
    restart_count: Mapped[int] = mapped_column(Integer, default=0)
    pool_reset_count: Mapped[int] = mapped_column(Integer, default=0)
    last_action_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
