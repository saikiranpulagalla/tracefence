"""Add immutable explicit action-recovery lineage.

Revision ID: 010_schema_v26_action_recovery
Revises: 009_schema_v25_action_reconciliation
"""

from alembic import op
from sqlalchemy import inspect, text

from migrations.schema_baselines.v26 import (
    V26_RECOVERY_LINK_DDL,
    V26_SCHEMA_INTEGRITY_TRIGGER_DDL,
)

revision = "010_schema_v26_action_recovery"
down_revision = "009_schema_v25_action_reconciliation"
branch_labels = None
depends_on = None
SCHEMA_VERSION = 26


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")
    if "action_recovery_links" not in set(inspect(connection).get_table_names()):
        connection.exec_driver_sql(V26_RECOVERY_LINK_DDL)
    for operation, row in (("insert", "NEW"), ("update", "NEW"), ("delete", "OLD")):
        connection.exec_driver_sql(
            f"""CREATE TRIGGER IF NOT EXISTS trg_action_recovery_links_{operation}_proof_revision
            AFTER {operation.upper()} ON action_recovery_links
            BEGIN UPDATE runs SET proof_revision = proof_revision + 1
            WHERE id = {row}.source_run_id; END"""
        )
    for ddl in V26_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(ddl)
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The action recovery migration downgrade is destructive; restore a verified backup instead"
    )
