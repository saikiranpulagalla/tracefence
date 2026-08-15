"""Add durable WorkerInstance persistence.

Revision ID: 003_schema_v19_worker_instances
Revises: 002_schema_v18_runtime_inspector
"""

from alembic import op
from sqlalchemy import inspect, text

from tracefence.db.models import WorkerInstance

revision = "003_schema_v19_worker_instances"
down_revision = "002_schema_v18_runtime_inspector"
branch_labels = None
depends_on = None

SCHEMA_VERSION = 19


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")
    if "worker_instances" not in set(inspect(connection).get_table_names()):
        WorkerInstance.__table__.create(connection)
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The WorkerInstance migration downgrade is destructive; "
        "restore a verified backup instead"
    )
