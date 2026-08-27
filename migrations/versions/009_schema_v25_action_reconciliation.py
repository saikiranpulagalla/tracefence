"""Add durable external-operation reconciliation identity and evidence.

Revision ID: 009_schema_v25_action_reconciliation
Revises: 008_schema_v24_action_lifecycle
"""

from alembic import op
from sqlalchemy import inspect, text

from migrations.schema_baselines.v25 import (
    V25_EXTERNAL_OPERATION_BINDING_DDL,
    V25_RECONCILIATION_EVIDENCE_DDL,
    V25_RECONCILIATION_INDEX_DDL,
    V25_SCHEMA_INTEGRITY_TRIGGER_DDL,
)

revision = "009_schema_v25_action_reconciliation"
down_revision = "008_schema_v24_action_lifecycle"
branch_labels = None
depends_on = None
SCHEMA_VERSION = 25


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")
    tables = set(inspect(connection).get_table_names())
    if "action_external_operation_bindings" not in tables:
        connection.exec_driver_sql(V25_EXTERNAL_OPERATION_BINDING_DDL)
    if "action_reconciliation_evidence" not in tables:
        connection.exec_driver_sql(V25_RECONCILIATION_EVIDENCE_DDL)
        for ddl in V25_RECONCILIATION_INDEX_DDL:
            connection.exec_driver_sql(ddl)
    for table in ("action_external_operation_bindings", "action_reconciliation_evidence"):
        for operation, row in (("insert", "NEW"), ("update", "NEW"), ("delete", "OLD")):
            connection.exec_driver_sql(f"""CREATE TRIGGER IF NOT EXISTS trg_{table}_{operation}_proof_revision AFTER {operation.upper()} ON {table} BEGIN UPDATE runs SET proof_revision = proof_revision + 1 WHERE id = {row}.run_id; END""")
    for ddl in V25_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(ddl)
    connection.execute(text("UPDATE schema_metadata SET version = :version WHERE id = 1"), {"version": SCHEMA_VERSION})


def downgrade() -> None:
    raise RuntimeError("The action reconciliation migration downgrade is destructive; restore a verified backup instead")
