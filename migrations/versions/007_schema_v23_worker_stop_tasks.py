"""Add durable worker-stop controller tasks.

Revision ID: 007_schema_v23_worker_stop_tasks
Revises: 006_schema_v22_runtime_stop_causality
"""

from alembic import op
from sqlalchemy import inspect, text

from migrations.schema_baselines.v23 import V23_SCHEMA_INTEGRITY_TRIGGER_DDL, V23_WORKER_STOP_TASK

revision = "007_schema_v23_worker_stop_tasks"
down_revision = "006_schema_v22_runtime_stop_causality"
branch_labels = None
depends_on = None

SCHEMA_VERSION = 23


def _install_v23_integrity_triggers() -> None:
    connection = op.get_bind()
    connection.exec_driver_sql(
        "DROP TRIGGER IF EXISTS trg_runtime_stop_targets_historical_selector"
    )
    for trigger_ddl in V23_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(trigger_ddl)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")
    if "worker_stop_tasks" not in set(inspect(connection).get_table_names()):
        V23_WORKER_STOP_TASK.create(connection)
    _install_v23_integrity_triggers()
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The worker-stop task migration downgrade is destructive; restore a verified backup instead"
    )
