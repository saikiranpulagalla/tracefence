"""Add durable runtime-stop causal persistence.

Revision ID: 006_schema_v22_runtime_stop_causality
Revises: 005_schema_v21_v2_recovery_binding
"""

from alembic import op
from sqlalchemy import inspect, text

from migrations.schema_baselines.v22 import (
    V22_PARTIAL_UNIQUE_INDEX_DDL,
    V22_RUNTIME_STOP_INTENT,
    V22_RUNTIME_STOP_TARGET,
    V22_SCHEMA_INTEGRITY_TRIGGER_DDL,
)

revision = "006_schema_v22_runtime_stop_causality"
down_revision = "005_schema_v21_v2_recovery_binding"
branch_labels = None
depends_on = None

SCHEMA_VERSION = 22


def _install_v22_integrity_triggers() -> None:
    connection = op.get_bind()
    for index_ddl in V22_PARTIAL_UNIQUE_INDEX_DDL:
        connection.exec_driver_sql(index_ddl)
    for trigger_ddl in V22_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(trigger_ddl)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")

    tables = set(inspect(connection).get_table_names())
    if "runtime_stop_intents" not in tables:
        V22_RUNTIME_STOP_INTENT.create(connection)
    if "runtime_stop_targets" not in tables:
        V22_RUNTIME_STOP_TARGET.create(connection)
    _install_v22_integrity_triggers()
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The runtime-stop causality migration downgrade is destructive; "
        "restore a verified backup instead"
    )
