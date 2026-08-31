"""Add provider-neutral durable execution intents.

Revision ID: 011_schema_v27_provider_execution_intents
Revises: 010_schema_v26_action_recovery
"""

from alembic import op
from sqlalchemy import inspect, text

from migrations.schema_baselines.v27 import (
    V27_PROVIDER_EXECUTION_INTENT_DDL,
    V27_PROVIDER_HANDLE_UNIQUE_INDEX_DDL,
    V27_SCHEMA_INTEGRITY_TRIGGER_DDL,
)

revision = "011_schema_v27_provider_execution_intents"
down_revision = "010_schema_v26_action_recovery"
branch_labels = None
depends_on = None
SCHEMA_VERSION = 27


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")
    if "provider_execution_intents" not in set(inspect(connection).get_table_names()):
        connection.exec_driver_sql(V27_PROVIDER_EXECUTION_INTENT_DDL)
    connection.exec_driver_sql(V27_PROVIDER_HANDLE_UNIQUE_INDEX_DDL)
    connection.exec_driver_sql(
        """CREATE TRIGGER IF NOT EXISTS trg_provider_execution_intents_insert_proof_revision
        AFTER INSERT ON provider_execution_intents
        BEGIN UPDATE runs SET proof_revision = proof_revision + 1
        WHERE id = NEW.run_id; END"""
    )
    for ddl in V27_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(ddl)
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The provider execution intent migration downgrade is destructive; restore a verified backup instead"
    )
