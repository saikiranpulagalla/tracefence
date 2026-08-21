"""Regression coverage for historical Alembic schema ownership.

Every target is built independently from a blank database.  Historical
migrations must remain self-contained and must not observe current ORM
metadata; clean revision N creates only objects owned through N.
"""

from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from tracefence.db.engine import build_engine
from tracefence.db.models import Base

ROOT = Path(__file__).parents[2]

REVISIONS = (
    ("001_schema_v17", 17),
    ("002_schema_v18_runtime_inspector", 18),
    ("003_schema_v19_worker_instances", 19),
    ("004_schema_v20_execution_protocol_activation", 20),
    ("005_schema_v21_v2_recovery_binding", 21),
    ("006_schema_v22_runtime_stop_causality", 22),
    ("007_schema_v23_worker_stop_tasks", 23),
)

V17_TABLES = {
    "schema_metadata",
    "runs",
    "nodes",
    "control_scopes",
    "spawn_intents",
    "credential_recovery_envelopes",
    "correction_proposals",
    "control_commands",
    "command_acknowledgements",
    "action_attempts",
    "action_command_matches",
    "invariant_violations",
    "telemetry_outbox",
    "service_state",
}

V20_WORKER_FIELDS = {
    "activation_intent_id",
    "credential_hash",
    "credential_confirmed_at",
    "reported_process_id",
    "activated_revision",
    "terminal_revision",
}


def _config(path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path}")
    return config


def _upgrade(path: Path, revision: str) -> sqlite3.Connection:
    command.upgrade(_config(path), revision)
    return sqlite3.connect(path)


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        name
        for (name,) in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name != 'alembic_version'"
        )
    }


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _objects(connection: sqlite3.Connection, kind: str) -> dict[str, str]:
    return {
        name: sql or ""
        for name, sql in connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = ?", (kind,)
        )
    }


@pytest.mark.parametrize(("revision", "version"), REVISIONS)
def test_blank_database_has_exact_historical_table_and_column_boundaries(
    tmp_path: Path, revision: str, version: int
) -> None:
    connection = _upgrade(tmp_path / f"{version}.sqlite", revision)
    try:
        expected_tables = set(V17_TABLES)
        if version >= 18:
            expected_tables.add("runtime_events")
        if version >= 19:
            expected_tables.add("worker_instances")
        if version >= 22:
            expected_tables.update({"runtime_stop_intents", "runtime_stop_targets"})
        if version >= 23:
            expected_tables.add("worker_stop_tasks")
        assert _tables(connection) == expected_tables

        run_columns = _columns(connection, "runs")
        node_columns = _columns(connection, "nodes")
        recovery_columns = _columns(connection, "credential_recovery_envelopes")
        assert ("execution_protocol_version" in run_columns) is (version >= 20)
        assert ("current_worker_instance_id" in node_columns) is (version >= 20)
        assert (
            {"binding_version", "binding_kind", "subject_worker_instance_id", "spawn_intent_id"}
            <= recovery_columns
        ) is (version >= 21)

        if version == 19:
            worker_columns = _columns(connection, "worker_instances")
            assert V20_WORKER_FIELDS.isdisjoint(worker_columns)
            assert worker_columns == {
                "id",
                "node_id",
                "incarnation",
                "observed_state",
                "created_at",
                "activated_at",
                "terminal_at",
            }
        if version >= 20:
            assert V20_WORKER_FIELDS <= _columns(connection, "worker_instances")
        if version >= 22:
            assert _columns(connection, "runtime_stop_intents") == {
                "id",
                "run_id",
                "cause_type",
                "target_domain",
                "source_revision",
                "source_command_id",
                "source_scope_id",
                "source_node_id",
                "created_at",
            }
            assert _columns(connection, "runtime_stop_targets") == {
                "id",
                "stop_intent_id",
                "worker_instance_id",
                "created_at",
            }
        if version == 22:
            assert "worker_stop_tasks" not in _tables(connection)
        if version == 23:
            assert _columns(connection, "worker_stop_tasks") == {
                "id",
                "worker_instance_id",
                "state",
                "attempt_count",
                "next_attempt_at",
                "last_attempt_at",
                "last_error_code",
                "last_error_at",
                "created_at",
                "updated_at",
            }
    finally:
        connection.close()


@pytest.mark.parametrize(("revision", "version"), REVISIONS)
def test_historical_trigger_and_index_ownership(
    tmp_path: Path, revision: str, version: int
) -> None:
    connection = _upgrade(tmp_path / f"objects-{version}.sqlite", revision)
    try:
        triggers = _objects(connection, "trigger")
        indexes = _objects(connection, "index")
        assert ("trg_runtime_events_no_update" in triggers) is (version >= 18)
        assert ("trg_worker_instances_id_immutable" in triggers) is (version >= 19)
        assert ("trg_runs_execution_protocol_version_immutable" in triggers) is (version >= 20)
        assert ("trg_credential_recovery_envelopes_binding_immutable" in triggers) is (
            version >= 21
        )
        assert ("trg_runtime_stop_targets_historical_selector" in triggers) is (version >= 22)
        assert ("trg_worker_stop_tasks_state_transition" in triggers) is (version >= 23)
        assert ("uq_runtime_stop_intent_source_command" in indexes) is (version >= 22)
        assert ("ix_worker_stop_tasks_due" in indexes) is (version >= 23)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("old_revision", "next_revision"),
    (
        ("003_schema_v19_worker_instances", "004_schema_v20_execution_protocol_activation"),
        ("004_schema_v20_execution_protocol_activation", "005_schema_v21_v2_recovery_binding"),
        ("005_schema_v21_v2_recovery_binding", "006_schema_v22_runtime_stop_causality"),
        ("006_schema_v22_runtime_stop_causality", "007_schema_v23_worker_stop_tasks"),
    ),
)
def test_legacy_current_metadata_contamination_remains_upgradeable(
    tmp_path: Path, old_revision: str, next_revision: str
) -> None:
    """A pre-repair database with compatible future objects upgrades without loss."""

    path = tmp_path / f"contaminated-{old_revision}.sqlite"
    engine = build_engine(f"sqlite+pysqlite:///{path}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM schema_metadata"))
        connection.execute(
            text(
                "INSERT INTO schema_metadata (id, version, updated_at) "
                "VALUES (1, 0, CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": old_revision},
        )
    engine.dispose()

    command.upgrade(_config(path), next_revision)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT version FROM schema_metadata WHERE id = 1").fetchone()
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            next_revision,
        )
        assert "worker_instances" in _tables(connection)
    finally:
        connection.close()


def test_historical_migrations_do_not_import_current_application_ddl() -> None:
    for path in sorted((ROOT / "migrations" / "versions").glob("*_schema_v*.py")):
        source = path.read_text()
        tree = ast.parse(source)
        imports = {
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        assert "tracefence.db.models" not in imports
        assert "tracefence.db.engine" not in imports
        assert "Base.metadata" not in source
        assert ".__table__" not in source
