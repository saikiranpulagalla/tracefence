"""Add execution-protocol-v2 activation storage.

Revision ID: 004_schema_v20_execution_protocol_activation
Revises: 003_schema_v19_worker_instances
"""

from alembic import op
from sqlalchemy import Column, DateTime, Integer, String, inspect, text

revision = "004_schema_v20_execution_protocol_activation"
down_revision = "003_schema_v19_worker_instances"
branch_labels = None
depends_on = None

SCHEMA_VERSION = 20

_V20_SCHEMA_INTEGRITY_TRIGGER_DDL = {
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

_PROOF_RELEVANT_RUN_TABLES = (
    "nodes",
    "control_scopes",
    "spawn_intents",
    "correction_proposals",
    "control_commands",
    "command_acknowledgements",
    "action_attempts",
    "action_command_matches",
    "invariant_violations",
    "telemetry_outbox",
    "service_state",
)


def _drop_proof_revision_triggers() -> None:
    connection = op.get_bind()
    for table_name in _PROOF_RELEVANT_RUN_TABLES:
        for operation in ("insert", "update", "delete"):
            connection.exec_driver_sql(
                f"DROP TRIGGER IF EXISTS trg_{table_name}_{operation}_proof_revision"
            )
    connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_runs_update_proof_revision")


def _install_proof_revision_triggers() -> None:
    connection = op.get_bind()
    for table_name in _PROOF_RELEVANT_RUN_TABLES:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            row = "OLD" if operation == "DELETE" else "NEW"
            connection.exec_driver_sql(
                f"""
                CREATE TRIGGER IF NOT EXISTS
                    trg_{table_name}_{operation.lower()}_proof_revision
                AFTER {operation} ON {table_name}
                BEGIN
                    UPDATE runs
                    SET proof_revision = proof_revision + 1
                    WHERE id = {row}.run_id;
                END
                """
            )
    connection.exec_driver_sql(
        """
        CREATE TRIGGER IF NOT EXISTS trg_runs_update_proof_revision
        AFTER UPDATE OF status, root_node_id, run_scope_id, finished_at ON runs
        WHEN NEW.proof_revision = OLD.proof_revision
        BEGIN
            UPDATE runs
            SET proof_revision = proof_revision + 1
            WHERE id = NEW.id;
        END
        """
    )


def _install_integrity_triggers() -> None:
    connection = op.get_bind()
    for trigger_ddl in _V20_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(trigger_ddl)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")

    _drop_proof_revision_triggers()
    connection.exec_driver_sql("PRAGMA foreign_keys=OFF")

    for trigger_name in _V20_SCHEMA_INTEGRITY_TRIGGER_DDL:
        connection.exec_driver_sql(f"DROP TRIGGER IF EXISTS {trigger_name}")

    run_columns = {column["name"] for column in inspect(connection).get_columns("runs")}
    if "execution_protocol_version" not in run_columns:
        with op.batch_alter_table("runs", recreate="always") as batch_op:
            batch_op.add_column(
                Column(
                    "execution_protocol_version",
                    Integer,
                    nullable=False,
                    server_default="1",
                )
            )
            batch_op.create_check_constraint(
                "ck_run_execution_protocol_version_allowed",
                "execution_protocol_version IN (1, 2)",
            )
    connection.execute(
        text(
            "UPDATE runs SET execution_protocol_version = 1 "
            "WHERE execution_protocol_version IS NULL"
        )
    )

    node_columns = {column["name"] for column in inspect(connection).get_columns("nodes")}
    if "current_worker_instance_id" not in node_columns:
        op.add_column(
            "nodes",
            Column("current_worker_instance_id", String(36), nullable=True),
        )

    worker_columns = {
        column["name"] for column in inspect(connection).get_columns("worker_instances")
    }
    if "activation_intent_id" not in worker_columns:
        with op.batch_alter_table("worker_instances", recreate="always") as batch_op:
            batch_op.add_column(Column("activation_intent_id", String(36), nullable=True))
            batch_op.add_column(Column("credential_hash", String(64), nullable=True))
            batch_op.add_column(Column("credential_confirmed_at", DateTime, nullable=True))
            batch_op.add_column(Column("reported_process_id", Integer, nullable=True))
            batch_op.add_column(Column("activated_revision", Integer, nullable=True))
            batch_op.add_column(Column("terminal_revision", Integer, nullable=True))
            batch_op.create_foreign_key(
                "fk_worker_instance_activation_intent",
                "spawn_intents",
                ["activation_intent_id"],
                ["id"],
            )
            batch_op.create_unique_constraint(
                "uq_worker_instance_activation_intent",
                ["activation_intent_id"],
            )
            batch_op.create_check_constraint(
                "ck_worker_instance_activated_revision_nonnegative",
                "activated_revision IS NULL OR activated_revision >= 0",
            )
            batch_op.create_check_constraint(
                "ck_worker_instance_terminal_revision_nonnegative",
                "terminal_revision IS NULL OR terminal_revision >= 0",
            )
            batch_op.create_check_constraint(
                "ck_worker_instance_revision_order",
                "terminal_revision IS NULL OR activated_revision IS NULL "
                "OR terminal_revision > activated_revision",
            )

    connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    _install_integrity_triggers()
    _install_proof_revision_triggers()
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The execution-protocol activation migration downgrade is destructive; "
        "restore a verified backup instead"
    )
