from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from tests.helpers import create_seeded_run, create_v2_run
from tracefence.db.engine import (
    ALEMBIC_HEAD,
    SCHEMA_VERSION,
    _validate_required_triggers,
    build_engine,
    init_db,
)
from tracefence.db.models import Node, RuntimeStopIntent, RuntimeStopTarget, WorkerInstance
from tracefence.domain.enums import CommandType, IssuerType
from tracefence.domain.schemas import CommandCreate, Principal
from tracefence.services.control_service import ControlService
from tracefence.services.runtime_stop_service import RuntimeStopService


def _alembic_config(database_path: Path):
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")
    return config


def _cancel_run(node_id: str, key: str) -> CommandCreate:
    return CommandCreate(
        idempotency_key=key,
        command_type=CommandType.CANCEL_RUN,
        target_node_id=node_id,
        reason_code="TEST",
        reason_text="runtime-stop schema test",
    )


def test_v22_fresh_and_historical_migration_lifecycle(tmp_path):
    from alembic import command

    path = tmp_path / "runtime-stop-v22.db"
    config = _alembic_config(path)
    command.upgrade(config, "005_schema_v21_v2_recovery_binding")
    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        v21_names = set(
            connection.exec_driver_sql("SELECT name FROM sqlite_master").scalars()
        )
    # The historical v17 bootstrap imports current ORM metadata, so tables
    # may exist before their owning migration.  v22-only integrity DDL must
    # nevertheless remain absent until migration 006 runs.
    assert "trg_runtime_stop_targets_historical_selector" not in v21_names
    assert "uq_runtime_stop_intent_source_command" not in v21_names
    engine.dispose()

    command.upgrade(config, "head")
    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT version FROM schema_metadata WHERE id = 1")
        ).scalar_one() == SCHEMA_VERSION
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == ALEMBIC_HEAD
        names = set(connection.exec_driver_sql("SELECT name FROM sqlite_master").scalars())
    assert {"runtime_stop_intents", "runtime_stop_targets", "trg_runtime_stop_targets_historical_selector"} <= names
    _validate_required_triggers(engine)
    engine.dispose()

    fresh = build_engine(f"sqlite+pysqlite:///{tmp_path / 'runtime-stop-fresh.db'}")
    init_db(fresh)
    _validate_required_triggers(fresh)
    fresh.dispose()


def test_v22_schema_guard_rejects_same_name_wrong_trigger_body(tmp_path):
    engine = build_engine(f"sqlite+pysqlite:///{tmp_path / 'runtime-stop-guard.db'}")
    init_db(engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TRIGGER trg_runtime_stop_targets_historical_selector"))
        connection.execute(
            text(
                "CREATE TRIGGER trg_runtime_stop_targets_historical_selector "
                "BEFORE INSERT ON runtime_stop_targets BEGIN SELECT 1; END"
            )
        )
    with pytest.raises(RuntimeError, match="trg_runtime_stop_targets_historical_selector"):
        _validate_required_triggers(engine)
    engine.dispose()


async def test_v22_direct_sql_preserves_immutable_causal_history_and_cross_run_targets(
    session_factory,
):
    first = await create_v2_run(session_factory, "runtime-stop-schema-first")
    second = await create_v2_run(session_factory, "runtime-stop-schema-second")
    command = await ControlService(session_factory).issue_command(
        _cancel_run(first.root_node_id, "runtime-stop-schema-command"),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        ).scalar_one()
        intent_id = intent.id
        second_worker_id = session.scalar(
            select(WorkerInstance.id).where(WorkerInstance.node_id == second.root_node_id)
        )
        assert second_worker_id is not None
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO runtime_stop_targets "
                    "(id, stop_intent_id, worker_instance_id, created_at) "
                    "VALUES (:id, :intent, :worker, CURRENT_TIMESTAMP)"
                ),
                {"id": str(uuid4()), "intent": intent.id, "worker": second_worker_id},
            )
            session.commit()
        session.rollback()

        for column, value in (
            ("run_id", second.run_id),
            ("cause_type", "LEASE_EXPIRED"),
            ("target_domain", "NODE"),
            ("source_revision", 0),
            ("source_command_id", None),
            ("source_scope_id", None),
            ("source_node_id", second.root_node_id),
            ("created_at", "2020-01-01 00:00:00"),
        ):
            with pytest.raises(IntegrityError):
                session.execute(
                    text(f"UPDATE runtime_stop_intents SET {column} = :value WHERE id = :id"),
                    {"value": value, "id": intent.id},
                )
                session.commit()
            session.rollback()

    await RuntimeStopService(session_factory).materialize_targets(
        intent_id=intent_id, batch_size=10
    )
    with session_factory() as session:
        target = session.execute(
            select(RuntimeStopTarget).where(RuntimeStopTarget.stop_intent_id == intent_id)
        ).scalar_one()
        with pytest.raises(IntegrityError, match="RUNTIME_STOP_TARGET_IMMUTABLE"):
            session.execute(
                text("UPDATE runtime_stop_targets SET worker_instance_id = :worker WHERE id = :id"),
                {"worker": second_worker_id, "id": target.id},
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError, match="RUNTIME_STOP_TARGET_DELETE_PROHIBITED"):
            session.execute(text("DELETE FROM runtime_stop_targets WHERE id = :id"), {"id": target.id})
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError, match="RUNTIME_STOP_INTENT_DELETE_PROHIBITED"):
            session.execute(text("DELETE FROM runtime_stop_intents WHERE id = :id"), {"id": intent_id})
            session.commit()
        session.rollback()
        first_node = session.get(Node, first.root_node_id)
        assert first_node is not None
        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE control_scopes SET run_id = :run WHERE id = :scope"),
                {"run": second.run_id, "scope": first_node.own_scope_id},
            )
            session.commit()


async def test_v1_intent_can_have_no_physical_targets(session_factory):
    run = await create_seeded_run(session_factory, "runtime-stop-v1-no-workers")
    command = await ControlService(session_factory).issue_command(
        _cancel_run(run.root_node_id, "runtime-stop-v1-no-workers-command"),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with session_factory() as session:
        intent = session.execute(
            select(RuntimeStopIntent).where(
                RuntimeStopIntent.source_command_id == command.command_id
            )
        ).scalar_one()
    planner = RuntimeStopService(session_factory)
    result = await planner.materialize_targets(intent_id=intent.id, batch_size=10)
    assert result.inserted == 0
    assert await planner.pending_intent_ids(limit=10) == []
