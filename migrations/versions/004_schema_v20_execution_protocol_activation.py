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


_INTEGRITY_TRIGGER_DDL = (
    """
    CREATE TRIGGER IF NOT EXISTS trg_runs_execution_protocol_version_valid
    BEFORE INSERT ON runs
    WHEN NEW.execution_protocol_version NOT IN (1, 2)
    BEGIN
        SELECT RAISE(ABORT, 'RUN_EXECUTION_PROTOCOL_VERSION_INVALID');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_runs_execution_protocol_version_immutable
    BEFORE UPDATE OF execution_protocol_version ON runs
    WHEN NEW.execution_protocol_version != OLD.execution_protocol_version
    BEGIN
        SELECT RAISE(ABORT, 'RUN_EXECUTION_PROTOCOL_VERSION_IMMUTABLE');
    END
    """,
    """
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
    """
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
    """
    CREATE TRIGGER IF NOT EXISTS trg_worker_instances_id_immutable
    BEFORE UPDATE OF id ON worker_instances
    WHEN NEW.id != OLD.id
    BEGIN
        SELECT RAISE(ABORT, 'WORKER_INSTANCE_ID_IMMUTABLE');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_worker_instances_current_pointer_node_guard
    BEFORE UPDATE OF node_id ON worker_instances
    WHEN EXISTS (
        SELECT 1 FROM nodes
        WHERE nodes.current_worker_instance_id = OLD.id
          AND nodes.id != NEW.node_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'NODE_CURRENT_WORKER_INSTANCE_NODE_MISMATCH');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_worker_instances_current_pointer_clear_on_delete
    BEFORE DELETE ON worker_instances
    BEGIN
        UPDATE nodes
        SET current_worker_instance_id = NULL
        WHERE current_worker_instance_id = OLD.id;
    END
    """,
)


def _install_integrity_triggers() -> None:
    connection = op.get_bind()
    for trigger_ddl in _INTEGRITY_TRIGGER_DDL:
        connection.exec_driver_sql(trigger_ddl)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")

    run_columns = {
        column["name"] for column in inspect(connection).get_columns("runs")
    }
    if "execution_protocol_version" not in run_columns:
        op.add_column(
            "runs",
            Column(
                "execution_protocol_version",
                Integer,
                nullable=False,
                server_default="1",
            ),
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
                Column("created_revision", Integer, nullable=True)
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
                "ck_worker_instance_created_revision_nonnegative",
                "created_revision IS NULL OR created_revision >= 0",
            )
            batch_op.create_check_constraint(
                "ck_worker_instance_terminal_revision_nonnegative",
                "terminal_revision IS NULL OR terminal_revision >= 0",
            )
            batch_op.create_check_constraint(
                "ck_worker_instance_revision_order",
                "terminal_revision IS NULL OR created_revision IS NULL "
                "OR terminal_revision >= created_revision",
            )

    _install_integrity_triggers()
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The execution-protocol activation migration downgrade is destructive; "
        "restore a verified backup instead"
    )
