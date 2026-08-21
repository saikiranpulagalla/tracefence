"""Add the transactional Runtime Inspector projection.

Revision ID: 002_schema_v18_runtime_inspector
Revises: 001_schema_v17
"""

from alembic import op
from sqlalchemy import JSON, Column, inspect, text

from migrations.schema_baselines.v18 import V18_RUNTIME_EVENT

revision = "002_schema_v18_runtime_inspector"
down_revision = "001_schema_v17"
branch_labels = None
depends_on = None

SCHEMA_VERSION = 18


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")
    inspector = inspect(connection)
    if "runtime_events" not in set(inspector.get_table_names()):
        V18_RUNTIME_EVENT.create(connection)
    action_columns = {
        column["name"] for column in inspect(connection).get_columns("action_attempts")
    }
    if "decision_explanation_json" not in action_columns:
        op.add_column(
            "action_attempts",
            Column(
                "decision_explanation_json",
                JSON(none_as_null=True),
                nullable=True,
            ),
        )
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )


def downgrade() -> None:
    raise RuntimeError(
        "The Runtime Inspector migration downgrade is destructive; "
        "restore a verified backup instead"
    )
