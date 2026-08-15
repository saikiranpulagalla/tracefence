"""Add execution-protocol-v2 activation storage.

Revision ID: 004_schema_v20_execution_protocol_activation
Revises: 003_schema_v19_worker_instances
"""

from alembic import op
from sqlalchemy import Column, DateTime, Integer, String, inspect, text

from tracefence.db.models import SCHEMA_INTEGRITY_TRIGGER_DDL

revision = "004_schema_v20_execution_protocol_activation"
down_revision = "003_schema_v19_worker_instances"
branch_labels = None
depends_on = None

SCHEMA_VERSION = 20

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
    for trigger_ddl in SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(trigger_ddl)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")

    _drop_proof_revision_triggers()
    connection.exec_driver_sql("PRAGMA foreign_keys=OFF")

    for trigger_name in SCHEMA_INTEGRITY_TRIGGER_DDL:
        connection.exec_driver_sql(f"DROP TRIGGER IF EXISTS {trigger_name}")

    run_columns = {
        column["name"] for column in inspect(connection).get_columns("runs")
    }
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

    node_columns = {
        column["name"] for column in inspect(connection).get_columns("nodes")
    }
    if "current_worker_instance_id" not in node_columns:
        op.add_column(
            "nodes",
            Column("current_worker_instance_id", String(36), nullable=True),
        )

    worker_columns = {
        column["name"]
        for column in inspect(connection).get_columns("worker_instances")
    }
    if "activation_intent_id" not in worker_columns:
        with op.batch_alter_table("worker_instances", recreate="always") as batch_op:
            batch_op.add_column(
                Column("activation_intent_id", String(36), nullable=True)
            )
            batch_op.add_column(
                Column("credential_hash", String(64), nullable=True)
            )
            batch_op.add_column(
                Column("credential_confirmed_at", DateTime, nullable=True)
            )
            batch_op.add_column(
                Column("reported_process_id", Integer, nullable=True)
            )
            batch_op.add_column(
                Column("activated_revision", Integer, nullable=True)
            )
            batch_op.add_column(
                Column("terminal_revision", Integer, nullable=True)
            )
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
