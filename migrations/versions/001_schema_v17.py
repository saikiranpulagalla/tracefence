"""Create the hardened TraceFence SQLite schema.

Revision ID: 001_schema_v17
Revises:
"""

from alembic import op
from sqlalchemy import insert

from tracefence.db.models import Base, SchemaMetadata

revision = "001_schema_v17"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA_VERSION = 17
_PROOF_TABLES = (
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


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")
    Base.metadata.create_all(connection)
    for table in _PROOF_TABLES:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            row = "OLD" if operation == "DELETE" else "NEW"
            connection.exec_driver_sql(
                f"""
                CREATE TRIGGER IF NOT EXISTS
                    trg_{table}_{operation.lower()}_proof_revision
                AFTER {operation} ON {table}
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
    connection.execute(
        insert(SchemaMetadata).values(id=1, version=SCHEMA_VERSION)
    )


def downgrade() -> None:
    raise RuntimeError(
        "The initial TraceFence schema downgrade is destructive; "
        "restore a verified backup instead"
    )
