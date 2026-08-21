"""Add protocol-v2 child activation recovery bindings.

Revision ID: 005_schema_v21_v2_recovery_binding
Revises: 004_schema_v20_execution_protocol_activation
"""

from alembic import op
from sqlalchemy import Column, Integer, String, inspect, text

revision = "005_schema_v21_v2_recovery_binding"
down_revision = "004_schema_v20_execution_protocol_activation"
branch_labels = None
depends_on = None

SCHEMA_VERSION = 21

_V21_SCHEMA_INTEGRITY_TRIGGER_DDL = {
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

_V21_PARTIAL_UNIQUE_INDEX_DDL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_credential_recovery_v2_spawn_intent "
    "ON credential_recovery_envelopes (spawn_intent_id) "
    "WHERE binding_version = 2 AND binding_kind = 'V2_CHILD_ACTIVATION'",
    "CREATE UNIQUE INDEX IF NOT EXISTS "
    "uq_credential_recovery_v2_subject_worker_instance "
    "ON credential_recovery_envelopes (subject_worker_instance_id) "
    "WHERE binding_version = 2 AND binding_kind = 'V2_CHILD_ACTIVATION'",
)


def _install_v21_integrity_triggers() -> None:
    connection = op.get_bind()
    for trigger_ddl in _V21_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(trigger_ddl)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")

    columns = {
        column["name"]
        for column in inspect(connection).get_columns("credential_recovery_envelopes")
    }
    if "binding_version" not in columns:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        with op.batch_alter_table(
            "credential_recovery_envelopes",
            recreate="always",
        ) as batch_op:
            batch_op.add_column(
                Column(
                    "binding_version",
                    Integer,
                    nullable=False,
                    server_default="1",
                )
            )
            batch_op.add_column(
                Column(
                    "binding_kind",
                    String(24),
                    nullable=False,
                    server_default="V1_NODE",
                )
            )
            batch_op.add_column(Column("subject_worker_instance_id", String(36), nullable=True))
            batch_op.add_column(Column("spawn_intent_id", String(36), nullable=True))
            batch_op.create_foreign_key(
                "fk_credential_recovery_subject_worker_instance",
                "worker_instances",
                ["subject_worker_instance_id"],
                ["id"],
            )
            batch_op.create_foreign_key(
                "fk_credential_recovery_spawn_intent",
                "spawn_intents",
                ["spawn_intent_id"],
                ["id"],
            )
            batch_op.create_check_constraint(
                "ck_credential_recovery_binding_version_allowed",
                "binding_version IN (1, 2)",
            )
            batch_op.create_check_constraint(
                "ck_credential_recovery_binding_shape",
                "(binding_version = 1 AND binding_kind = 'V1_NODE' "
                "AND subject_worker_instance_id IS NULL AND spawn_intent_id IS NULL) "
                "OR (binding_version = 2 AND binding_kind = 'V2_CHILD_ACTIVATION' "
                "AND operation_type = 'ACTIVATION' "
                "AND subject_worker_instance_id IS NOT NULL AND spawn_intent_id IS NOT NULL)",
            )
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")

    connection.execute(
        text(
            "UPDATE credential_recovery_envelopes "
            "SET binding_version = 1, binding_kind = 'V1_NODE', "
            "subject_worker_instance_id = NULL, spawn_intent_id = NULL "
            "WHERE binding_version IS NULL OR binding_kind IS NULL"
        )
    )
    for index_ddl in _V21_PARTIAL_UNIQUE_INDEX_DDL:
        connection.exec_driver_sql(index_ddl)
    _install_v21_integrity_triggers()
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The v2 recovery binding migration downgrade is destructive; "
        "restore a verified backup instead"
    )
