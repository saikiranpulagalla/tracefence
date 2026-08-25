"""Add durable ActionAttempt lifecycle and authority bindings.

Revision ID: 008_schema_v24_action_lifecycle
Revises: 007_schema_v23_worker_stop_tasks
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect, text

from migrations.schema_baselines.v24 import (
    V24_ACTION_AUTHORITY_BINDING_DDL,
    V24_ACTION_AUTHORITY_BINDING_INDEX_DDL,
    V24_SCHEMA_INTEGRITY_TRIGGER_DDL,
)

revision = "008_schema_v24_action_lifecycle"
down_revision = "007_schema_v23_worker_stop_tasks"
branch_labels = None
depends_on = None
SCHEMA_VERSION = 24

_RESULT_SHAPE = """
(lifecycle_version = 0 AND ((decision = 'DENY' AND denial_reason IS NOT NULL
 AND committed_at IS NULL AND result_json IS NULL AND result_digest IS NULL) OR
 (decision = 'ALLOW' AND denial_reason IS NULL AND committed_at IS NOT NULL
 AND result_json IS NOT NULL AND result_digest IS NOT NULL))) OR
(lifecycle_version = 1 AND ((decision = 'DENY' AND execution_state = 'DENIED'
 AND denial_reason IS NOT NULL AND committed_at IS NULL AND result_json IS NULL
 AND result_digest IS NULL AND stale_result_digest IS NULL AND stale_reason_code IS NULL) OR
 (decision = 'ALLOW' AND denial_reason IS NULL AND execution_state IN ('AUTHORIZED','DISPATCHED','AMBIGUOUS')
 AND committed_at IS NULL AND result_json IS NULL AND result_digest IS NULL
 AND stale_result_digest IS NULL AND stale_reason_code IS NULL) OR
 (decision = 'ALLOW' AND denial_reason IS NULL AND execution_state IN ('SUCCEEDED','FAILED')
 AND committed_at IS NOT NULL AND result_json IS NOT NULL AND result_digest IS NOT NULL
 AND stale_result_digest IS NULL AND stale_reason_code IS NULL) OR
 (decision = 'ALLOW' AND denial_reason IS NULL AND execution_state = 'STALE'
 AND committed_at IS NULL AND result_json IS NULL AND result_digest IS NULL
 AND stale_result_digest IS NOT NULL AND stale_reason_code IS NOT NULL AND stale_observed_at IS NOT NULL)))
"""

def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("TraceFence migrations support only SQLite")
    columns = {column["name"] for column in inspect(connection).get_columns("action_attempts")}
    if "lifecycle_version" not in columns:
        with op.batch_alter_table("action_attempts", recreate="always") as batch:
            batch.add_column(sa.Column("lifecycle_version", sa.Integer(), nullable=False, server_default="0"))
            batch.add_column(sa.Column("execution_state", sa.String(length=16), nullable=True))
            batch.add_column(sa.Column("worker_instance_id", sa.String(length=36), nullable=True))
            batch.add_column(sa.Column("worker_incarnation", sa.Integer(), nullable=True))
            batch.add_column(sa.Column("authority_vector_digest", sa.String(length=64), nullable=True))
            batch.add_column(sa.Column("authorization_proof_revision", sa.Integer(), nullable=True))
            batch.add_column(sa.Column("dispatched_at", sa.DateTime(), nullable=True))
            batch.add_column(sa.Column("stale_result_digest", sa.String(length=64), nullable=True))
            batch.add_column(sa.Column("stale_reason_code", sa.String(length=80), nullable=True))
            batch.add_column(sa.Column("stale_observed_at", sa.DateTime(), nullable=True))
            batch.drop_constraint("ck_action_result_shape", type_="check")
            batch.create_check_constraint("ck_action_result_shape", _RESULT_SHAPE)
            batch.create_check_constraint("ck_action_lifecycle_version", "lifecycle_version IN (0, 1)")
            batch.create_check_constraint(
                "ck_action_execution_state",
                "execution_state IS NULL OR execution_state IN ('DENIED','AUTHORIZED','DISPATCHED','SUCCEEDED','FAILED','STALE','AMBIGUOUS')",
            )
            batch.create_foreign_key(
                "fk_action_bound_worker", "worker_instances", ["worker_instance_id"], ["id"], ondelete="RESTRICT"
            )
            batch.create_index("ix_actions_worker_state", ["worker_instance_id", "execution_state"], unique=False)
    if "action_authority_bindings" not in set(inspect(connection).get_table_names()):
        connection.exec_driver_sql(V24_ACTION_AUTHORITY_BINDING_DDL)
        for index_ddl in V24_ACTION_AUTHORITY_BINDING_INDEX_DDL:
            connection.exec_driver_sql(index_ddl)
    for ddl in V24_SCHEMA_INTEGRITY_TRIGGER_DDL.values():
        connection.exec_driver_sql(ddl)
    connection.execute(
        text("UPDATE schema_metadata SET version = :version WHERE id = 1"),
        {"version": SCHEMA_VERSION},
    )

def downgrade() -> None:
    raise RuntimeError("The action lifecycle migration downgrade is destructive; restore a verified backup instead")
