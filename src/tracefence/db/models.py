from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    DDL,
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
    event,
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
        CheckConstraint(
            "execution_protocol_version IN (1, 2)",
            name="ck_run_execution_protocol_version_allowed",
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
    execution_protocol_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
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
    current_worker_instance_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )


class WorkerInstance(Base):
    """One physical execution incarnation for a logical Node.

    Worker instances are intentionally not authority-bearing. They only record
    an observed physical lifecycle for a Node; Node remains the logical
    execution and control identity.
    """

    __tablename__ = "worker_instances"
    __table_args__ = (
        UniqueConstraint(
            "node_id",
            "incarnation",
            name="uq_worker_instance_node_incarnation",
        ),
        CheckConstraint(
            "incarnation >= 1",
            name="ck_worker_instance_incarnation_positive",
        ),
        CheckConstraint(
            "observed_state IN ('PENDING','ACTIVE','EXITED','FAILED')",
            name="ck_worker_instance_observed_state",
        ),
        CheckConstraint(
            "(observed_state = 'PENDING' AND activated_at IS NULL AND terminal_at IS NULL) "
            "OR (observed_state = 'ACTIVE' AND activated_at IS NOT NULL AND terminal_at IS NULL) "
            "OR (observed_state = 'EXITED' AND activated_at IS NOT NULL AND terminal_at IS NOT NULL) "
            "OR (observed_state = 'FAILED' AND terminal_at IS NOT NULL)",
            name="ck_worker_instance_lifecycle_timestamps",
        ),
        UniqueConstraint(
            "activation_intent_id",
            name="uq_worker_instance_activation_intent",
        ),
        CheckConstraint(
            "activated_revision IS NULL OR activated_revision >= 0",
            name="ck_worker_instance_activated_revision_nonnegative",
        ),
        CheckConstraint(
            "terminal_revision IS NULL OR terminal_revision >= 0",
            name="ck_worker_instance_terminal_revision_nonnegative",
        ),
        CheckConstraint(
            "terminal_revision IS NULL OR activated_revision IS NULL "
            "OR terminal_revision > activated_revision",
            name="ck_worker_instance_revision_order",
        ),
        Index("ix_worker_instances_node", "node_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    node_id: Mapped[str] = mapped_column(
        ForeignKey("nodes.id", ondelete="CASCADE"),
        nullable=False,
    )
    incarnation: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_state: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    activation_intent_id: Mapped[str | None] = mapped_column(
        ForeignKey("spawn_intents.id"),
        nullable=True,
    )
    credential_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    credential_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    reported_process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    activated_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    terminal_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)



SCHEMA_INTEGRITY_TRIGGER_DDL = {
    "trg_runs_execution_protocol_version_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_runs_execution_protocol_version_immutable
        BEFORE UPDATE OF execution_protocol_version ON runs
        WHEN NEW.execution_protocol_version IS NOT OLD.execution_protocol_version
        BEGIN
            SELECT RAISE(ABORT, 'RUN_EXECUTION_PROTOCOL_VERSION_IMMUTABLE');
        END
    """,
    "trg_nodes_current_worker_instance_owned_insert": """
        CREATE TRIGGER IF NOT EXISTS trg_nodes_current_worker_instance_owned_insert
        BEFORE INSERT ON nodes
        WHEN NEW.current_worker_instance_id IS NOT NULL
         AND NOT EXISTS (
            SELECT 1 FROM worker_instances
            WHERE worker_instances.id = NEW.current_worker_instance_id
              AND worker_instances.node_id = NEW.id
         )
        BEGIN
            SELECT RAISE(ABORT, 'NODE_CURRENT_WORKER_INSTANCE_NODE_MISMATCH');
        END
    """,
    "trg_nodes_current_worker_instance_owned_update": """
        CREATE TRIGGER IF NOT EXISTS trg_nodes_current_worker_instance_owned_update
        BEFORE UPDATE OF current_worker_instance_id ON nodes
        WHEN NEW.current_worker_instance_id IS NOT NULL
         AND NOT EXISTS (
            SELECT 1 FROM worker_instances
            WHERE worker_instances.id = NEW.current_worker_instance_id
              AND worker_instances.node_id = NEW.id
         )
        BEGIN
            SELECT RAISE(ABORT, 'NODE_CURRENT_WORKER_INSTANCE_NODE_MISMATCH');
        END
    """,
    "trg_worker_instances_delete_prohibited": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_delete_prohibited
        BEFORE DELETE ON worker_instances
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_DELETE_PROHIBITED');
        END
    """,
    "trg_worker_instances_id_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_id_immutable
        BEFORE UPDATE OF id ON worker_instances
        WHEN NEW.id IS NOT OLD.id
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_ID_IMMUTABLE');
        END
    """,
    "trg_worker_instances_node_id_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_node_id_immutable
        BEFORE UPDATE OF node_id ON worker_instances
        WHEN NEW.node_id IS NOT OLD.node_id
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_NODE_ID_IMMUTABLE');
        END
    """,
    "trg_worker_instances_incarnation_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_incarnation_immutable
        BEFORE UPDATE OF incarnation ON worker_instances
        WHEN NEW.incarnation IS NOT OLD.incarnation
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_INCARNATION_IMMUTABLE');
        END
    """,
    "trg_worker_instances_activation_intent_id_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_activation_intent_id_immutable
        BEFORE UPDATE OF activation_intent_id ON worker_instances
        WHEN NEW.activation_intent_id IS NOT OLD.activation_intent_id
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_ACTIVATION_INTENT_ID_IMMUTABLE');
        END
    """,
    "trg_worker_instances_observed_state_transition": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_observed_state_transition
        BEFORE UPDATE OF observed_state ON worker_instances
        WHEN NEW.observed_state IS NOT OLD.observed_state
         AND NOT (
            (OLD.observed_state = 'PENDING' AND NEW.observed_state IN ('ACTIVE', 'FAILED'))
            OR (OLD.observed_state = 'ACTIVE' AND NEW.observed_state IN ('EXITED', 'FAILED'))
         )
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_STATE_TRANSITION_INVALID');
        END
    """,
    "trg_worker_instances_activated_at_once_set": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_activated_at_once_set
        BEFORE UPDATE OF activated_at ON worker_instances
        WHEN OLD.activated_at IS NOT NULL AND NEW.activated_at IS NOT OLD.activated_at
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_ACTIVATED_AT_IMMUTABLE');
        END
    """,
    "trg_worker_instances_terminal_at_once_set": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_terminal_at_once_set
        BEFORE UPDATE OF terminal_at ON worker_instances
        WHEN OLD.terminal_at IS NOT NULL AND NEW.terminal_at IS NOT OLD.terminal_at
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_TERMINAL_AT_IMMUTABLE');
        END
    """,
    "trg_worker_instances_activated_revision_once_set": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_activated_revision_once_set
        BEFORE UPDATE OF activated_revision ON worker_instances
        WHEN OLD.activated_revision IS NOT NULL AND NEW.activated_revision IS NOT OLD.activated_revision
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_ACTIVATED_REVISION_IMMUTABLE');
        END
    """,
    "trg_worker_instances_terminal_revision_once_set": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_terminal_revision_once_set
        BEFORE UPDATE OF terminal_revision ON worker_instances
        WHEN OLD.terminal_revision IS NOT NULL AND NEW.terminal_revision IS NOT OLD.terminal_revision
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_TERMINAL_REVISION_IMMUTABLE');
        END
    """,
    "trg_worker_instances_credential_confirmed_at_once_set": """
        CREATE TRIGGER IF NOT EXISTS trg_worker_instances_credential_confirmed_at_once_set
        BEFORE UPDATE OF credential_confirmed_at ON worker_instances
        WHEN OLD.credential_confirmed_at IS NOT NULL AND NEW.credential_confirmed_at IS NOT OLD.credential_confirmed_at
        BEGIN
            SELECT RAISE(ABORT, 'WORKER_INSTANCE_CREDENTIAL_CONFIRMED_AT_IMMUTABLE');
        END
    """,
}


_WORKER_INSTANCE_SCHEMA_INTEGRITY_TRIGGER_DDL = dict(SCHEMA_INTEGRITY_TRIGGER_DDL)


for _trigger_ddl in _WORKER_INSTANCE_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
    event.listen(
        WorkerInstance.__table__,
        "after_create",
        DDL(_trigger_ddl).execute_if(dialect="sqlite"),
    )


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
        ForeignKeyConstraint(
            ["subject_worker_instance_id"],
            ["worker_instances.id"],
            name="fk_credential_recovery_subject_worker_instance",
        ),
        ForeignKeyConstraint(
            ["spawn_intent_id"],
            ["spawn_intents.id"],
            name="fk_credential_recovery_spawn_intent",
        ),
        CheckConstraint(
            "operation_type IN ('SPAWN','REPLACEMENT','ACTIVATION')",
            name="ck_credential_recovery_operation_type",
        ),
        CheckConstraint(
            "binding_version IN (1, 2)",
            name="ck_credential_recovery_binding_version_allowed",
        ),
        CheckConstraint(
            "(binding_version = 1 AND binding_kind = 'V1_NODE' "
            "AND subject_worker_instance_id IS NULL AND spawn_intent_id IS NULL) "
            "OR (binding_version = 2 AND binding_kind = 'V2_CHILD_ACTIVATION' "
            "AND operation_type = 'ACTIVATION' "
            "AND subject_worker_instance_id IS NOT NULL AND spawn_intent_id IS NOT NULL)",
            name="ck_credential_recovery_binding_shape",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    operation_type: Mapped[str] = mapped_column(String(24))
    caller_node_id: Mapped[str] = mapped_column(String(36))
    subject_node_id: Mapped[str] = mapped_column(String(36))
    operation_key: Mapped[str] = mapped_column(String(160))
    request_payload_digest: Mapped[str] = mapped_column(String(64))
    binding_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
    )
    binding_kind: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default="V1_NODE",
        server_default="V1_NODE",
    )
    subject_worker_instance_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    spawn_intent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    nonce: Mapped[str] = mapped_column(String(24))
    ciphertext: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


V21_SCHEMA_INTEGRITY_TRIGGER_DDL = {
    "trg_credential_recovery_envelopes_causal_identity_immutable": """
        CREATE TRIGGER IF NOT EXISTS
            trg_credential_recovery_envelopes_causal_identity_immutable
        BEFORE UPDATE OF run_id, operation_type, caller_node_id, subject_node_id,
            operation_key, request_payload_digest ON credential_recovery_envelopes
        WHEN NEW.run_id IS NOT OLD.run_id
          OR NEW.operation_type IS NOT OLD.operation_type
          OR NEW.caller_node_id IS NOT OLD.caller_node_id
          OR NEW.subject_node_id IS NOT OLD.subject_node_id
          OR NEW.operation_key IS NOT OLD.operation_key
          OR NEW.request_payload_digest IS NOT OLD.request_payload_digest
        BEGIN
            SELECT RAISE(ABORT, 'CREDENTIAL_RECOVERY_CAUSAL_IDENTITY_IMMUTABLE');
        END
    """,
    "trg_credential_recovery_envelopes_binding_immutable": """
        CREATE TRIGGER IF NOT EXISTS
            trg_credential_recovery_envelopes_binding_immutable
        BEFORE UPDATE OF binding_version, binding_kind, subject_worker_instance_id,
            spawn_intent_id ON credential_recovery_envelopes
        WHEN NEW.binding_version IS NOT OLD.binding_version
          OR NEW.binding_kind IS NOT OLD.binding_kind
          OR NEW.subject_worker_instance_id IS NOT OLD.subject_worker_instance_id
          OR NEW.spawn_intent_id IS NOT OLD.spawn_intent_id
        BEGIN
            SELECT RAISE(ABORT, 'CREDENTIAL_RECOVERY_BINDING_IMMUTABLE');
        END
    """,
    "trg_credential_recovery_envelopes_v2_child_binding_insert": """
        CREATE TRIGGER IF NOT EXISTS
            trg_credential_recovery_envelopes_v2_child_binding_insert
        BEFORE INSERT ON credential_recovery_envelopes
        WHEN NEW.binding_version = 2
         AND NOT EXISTS (
            SELECT 1
            FROM runs
            JOIN worker_instances
              ON worker_instances.id = NEW.subject_worker_instance_id
            JOIN spawn_intents
              ON spawn_intents.id = NEW.spawn_intent_id
            WHERE runs.id = NEW.run_id
              AND runs.execution_protocol_version = 2
              AND worker_instances.node_id = NEW.subject_node_id
              AND worker_instances.activation_intent_id = NEW.spawn_intent_id
              AND spawn_intents.child_node_id = NEW.subject_node_id
         )
        BEGIN
            SELECT RAISE(ABORT, 'V2_CHILD_ACTIVATION_BINDING_CAUSAL_MISMATCH');
        END
    """,
    "trg_spawn_intents_v2_recovery_binding_delete_prohibited": """
        CREATE TRIGGER IF NOT EXISTS
            trg_spawn_intents_v2_recovery_binding_delete_prohibited
        BEFORE DELETE ON spawn_intents
        WHEN EXISTS (
            SELECT 1
            FROM credential_recovery_envelopes
            WHERE binding_version = 2
              AND spawn_intent_id = OLD.id
        )
        BEGIN
            SELECT RAISE(ABORT, 'SPAWN_INTENT_V2_RECOVERY_BINDING_DELETE_PROHIBITED');
        END
    """,
    "trg_spawn_intents_v2_recovery_binding_causality_immutable": """
        CREATE TRIGGER IF NOT EXISTS
            trg_spawn_intents_v2_recovery_binding_causality_immutable
        BEFORE UPDATE OF id, run_id, child_node_id ON spawn_intents
        WHEN EXISTS (
            SELECT 1
            FROM credential_recovery_envelopes
            WHERE binding_version = 2
              AND spawn_intent_id = OLD.id
        )
         AND (NEW.id IS NOT OLD.id
              OR NEW.run_id IS NOT OLD.run_id
              OR NEW.child_node_id IS NOT OLD.child_node_id)
        BEGIN
            SELECT RAISE(ABORT, 'SPAWN_INTENT_V2_RECOVERY_BINDING_CAUSALITY_IMMUTABLE');
        END
    """,
}



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
    decision_explanation_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
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
        CheckConstraint(
            "(claim_owner IS NULL AND claim_expires_at IS NULL) OR "
            "(claim_owner IS NOT NULL AND claim_expires_at IS NOT NULL)",
            name="ck_outbox_claim_shape",
        ),
        Index("ix_telemetry_outbox_pending", "delivered_at", "created_at"),
        Index("ix_telemetry_outbox_claim", "delivered_at", "next_attempt_at", "claim_expires_at"),
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
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    claim_owner: Mapped[str | None] = mapped_column(String(80), nullable=True)
    claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


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


class RuntimeEvent(Base):
    """Append-only, transactional projection of committed runtime transitions.

    Runtime events never participate in authority decisions. Their sequence is
    suitable for timeline ordering and SSE replay; the authoritative entity
    rows and Action Gateway remain the sole safety boundary.
    """

    __tablename__ = "runtime_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "node_id"],
            ["nodes.run_id", "nodes.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_runtime_event_node",
        ),
        ForeignKeyConstraint(
            ["run_id", "parent_node_id"],
            ["nodes.run_id", "nodes.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_runtime_event_parent",
        ),
        ForeignKeyConstraint(
            ["run_id", "command_id"],
            ["control_commands.run_id", "control_commands.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_runtime_event_command",
        ),
        ForeignKeyConstraint(
            ["run_id", "action_id"],
            ["action_attempts.run_id", "action_attempts.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_runtime_event_action",
        ),
        ForeignKeyConstraint(
            ["run_id", "scope_id"],
            ["control_scopes.run_id", "control_scopes.id"],
            deferrable=True,
            initially="DEFERRED",
            name="fk_runtime_event_scope",
        ),
        CheckConstraint(
            "event_type IN ("
            "'RUN_CREATED','NODE_REGISTERED','NODE_ACTIVATED','NODE_WAITING',"
            "'NODE_COMPLETED','LEASE_GRANTED','LEASE_RENEWED','LEASE_EXPIRED',"
            "'COMMAND_ISSUED','SCOPE_CANCELLED','SCOPE_SUPERSEDED',"
            "'ACTION_REQUESTED','ACTION_DENIED','ACTION_COMMITTED',"
            "'REPLACEMENT_CREATED','RECOVERY_COMPLETED','DEMO_WORKER_RELEASED')",
            name="ck_runtime_event_type",
        ),
        CheckConstraint(
            "decision IS NULL OR decision IN ('ALLOW','DENY')",
            name="ck_runtime_event_decision",
        ),
        CheckConstraint(
            "snapshot_version IS NULL OR snapshot_version >= 1",
            name="ck_runtime_event_snapshot_version",
        ),
        CheckConstraint(
            "authoritative_version IS NULL OR authoritative_version >= 1",
            name="ck_runtime_event_authoritative_version",
        ),
        Index("ix_runtime_events_run_sequence", "run_id", "sequence"),
        Index("ix_runtime_events_action", "action_id"),
    )

    sequence: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(40))
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    parent_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    command_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    snapshot_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authoritative_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


for _operation in ("UPDATE", "DELETE"):
    event.listen(
        RuntimeEvent.__table__,
        "after_create",
        DDL(
            f"""
            CREATE TRIGGER trg_runtime_events_no_{_operation.lower()}
            BEFORE {_operation} ON runtime_events
            BEGIN
                SELECT RAISE(ABORT, 'RUNTIME_EVENTS_APPEND_ONLY');
            END
            """
        ).execute_if(dialect="sqlite"),
    )
class RuntimeStopIntent(Base):
    """Immutable causal record for later physical-stop convergence."""

    __tablename__ = "runtime_stop_intents"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "source_command_id"],
            ["control_commands.run_id", "control_commands.id"],
            name="fk_runtime_stop_intent_source_command",
        ),
        ForeignKeyConstraint(
            ["run_id", "source_scope_id"],
            ["control_scopes.run_id", "control_scopes.id"],
            name="fk_runtime_stop_intent_source_scope",
        ),
        ForeignKeyConstraint(
            ["run_id", "source_node_id"],
            ["nodes.run_id", "nodes.id"],
            name="fk_runtime_stop_intent_source_node",
        ),
        CheckConstraint(
            "cause_type IN ('COMMAND_CANCEL_RUN','COMMAND_CANCEL_SUBTREE',"
            "'COMMAND_CORRECT_SUBTREE','LEASE_EXPIRED','LOGICAL_COMPLETION')",
            name="ck_runtime_stop_intent_cause_type",
        ),
        CheckConstraint(
            "target_domain IN ('RUN','SCOPE','NODE')",
            name="ck_runtime_stop_intent_target_domain",
        ),
        CheckConstraint(
            "source_revision >= 0",
            name="ck_runtime_stop_intent_source_revision_nonnegative",
        ),
        CheckConstraint(
            "(target_domain = 'RUN' AND source_scope_id IS NULL) OR "
            "(target_domain = 'SCOPE' AND source_scope_id IS NOT NULL) OR "
            "(target_domain = 'NODE' AND source_node_id IS NOT NULL)",
            name="ck_runtime_stop_intent_domain_shape",
        ),
        CheckConstraint(
            "(cause_type IN ('COMMAND_CANCEL_RUN','COMMAND_CANCEL_SUBTREE',"
            "'COMMAND_CORRECT_SUBTREE') AND source_command_id IS NOT NULL) OR "
            "(cause_type IN ('LEASE_EXPIRED','LOGICAL_COMPLETION') "
            "AND source_command_id IS NULL)",
            name="ck_runtime_stop_intent_cause_source_shape",
        ),
        UniqueConstraint(
            "run_id", "cause_type", "source_node_id", "source_revision",
            name="uq_runtime_stop_intent_autonomous_cause",
        ),
        Index("ix_runtime_stop_intents_run_revision", "run_id", "source_revision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="RESTRICT"))
    cause_type: Mapped[str] = mapped_column(String(40))
    target_domain: Mapped[str] = mapped_column(String(12))
    source_revision: Mapped[int] = mapped_column(Integer)
    source_command_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RuntimeStopTarget(Base):
    """Append-only, conservative causal candidate for one WorkerInstance."""

    __tablename__ = "runtime_stop_targets"
    __table_args__ = (
        UniqueConstraint(
            "stop_intent_id", "worker_instance_id",
            name="uq_runtime_stop_target_intent_worker",
        ),
        Index("ix_runtime_stop_targets_worker", "worker_instance_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    stop_intent_id: Mapped[str] = mapped_column(
        ForeignKey("runtime_stop_intents.id", ondelete="RESTRICT")
    )
    worker_instance_id: Mapped[str] = mapped_column(
        ForeignKey("worker_instances.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


V22_SCHEMA_INTEGRITY_TRIGGER_DDL = {
    "trg_nodes_runtime_stop_selector_identity_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_nodes_runtime_stop_selector_identity_immutable
        BEFORE UPDATE OF id, run_id, scope_snapshot_json ON nodes
        WHEN NEW.id IS NOT OLD.id
          OR NEW.run_id IS NOT OLD.run_id
          OR NEW.scope_snapshot_json IS NOT OLD.scope_snapshot_json
        BEGIN
            SELECT RAISE(ABORT, 'NODE_RUNTIME_STOP_SELECTOR_IDENTITY_IMMUTABLE');
        END
    """,
    "trg_control_scopes_runtime_stop_selector_identity_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_control_scopes_runtime_stop_selector_identity_immutable
        BEFORE UPDATE OF id, run_id ON control_scopes
        WHEN NEW.id IS NOT OLD.id OR NEW.run_id IS NOT OLD.run_id
        BEGIN
            SELECT RAISE(ABORT, 'CONTROL_SCOPE_RUNTIME_STOP_SELECTOR_IDENTITY_IMMUTABLE');
        END
    """,
    "trg_runtime_stop_intents_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_runtime_stop_intents_immutable
        BEFORE UPDATE ON runtime_stop_intents
        BEGIN
            SELECT RAISE(ABORT, 'RUNTIME_STOP_INTENT_IMMUTABLE');
        END
    """,
    "trg_runtime_stop_intents_delete_prohibited": """
        CREATE TRIGGER IF NOT EXISTS trg_runtime_stop_intents_delete_prohibited
        BEFORE DELETE ON runtime_stop_intents
        BEGIN
            SELECT RAISE(ABORT, 'RUNTIME_STOP_INTENT_DELETE_PROHIBITED');
        END
    """,
    "trg_runtime_stop_targets_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_runtime_stop_targets_immutable
        BEFORE UPDATE ON runtime_stop_targets
        BEGIN
            SELECT RAISE(ABORT, 'RUNTIME_STOP_TARGET_IMMUTABLE');
        END
    """,
    "trg_runtime_stop_targets_delete_prohibited": """
        CREATE TRIGGER IF NOT EXISTS trg_runtime_stop_targets_delete_prohibited
        BEFORE DELETE ON runtime_stop_targets
        BEGIN
            SELECT RAISE(ABORT, 'RUNTIME_STOP_TARGET_DELETE_PROHIBITED');
        END
    """,
    "trg_runtime_stop_targets_historical_selector": """
        CREATE TRIGGER IF NOT EXISTS trg_runtime_stop_targets_historical_selector
        BEFORE INSERT ON runtime_stop_targets
        WHEN NOT EXISTS (
            SELECT 1
            FROM runtime_stop_intents AS intent
            JOIN worker_instances AS worker
              ON worker.id = NEW.worker_instance_id
            JOIN nodes AS node ON node.id = worker.node_id
            WHERE intent.id = NEW.stop_intent_id
              AND node.run_id = intent.run_id
              AND worker.activated_at IS NOT NULL
              AND (
                    worker.activated_revision IS NULL
                    OR worker.activated_revision <= intent.source_revision
              )
              AND (
                    intent.target_domain = 'RUN'
                    OR (
                        intent.target_domain = 'SCOPE'
                        AND EXISTS (
                            SELECT 1
                            FROM json_each(node.scope_snapshot_json) AS snapshot
                            WHERE json_extract(snapshot.value, '$.scope_id')
                                  = intent.source_scope_id
                        )
                    )
                    OR (
                        intent.target_domain = 'NODE'
                        AND node.id = intent.source_node_id
                    )
              )
        )
        BEGIN
            SELECT RAISE(ABORT, 'RUNTIME_STOP_TARGET_HISTORICAL_SELECTOR_MISMATCH');
        END
    """,
}


V22_PARTIAL_UNIQUE_INDEX_DDL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_runtime_stop_intent_source_command "
    "ON runtime_stop_intents (source_command_id) "
    "WHERE source_command_id IS NOT NULL",
)
