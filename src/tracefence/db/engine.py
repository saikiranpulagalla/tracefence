from __future__ import annotations

from pathlib import Path
from string import Template

from sqlalchemy import (
    CheckConstraint,
    Engine,
    ForeignKeyConstraint,
    UniqueConstraint,
    create_engine,
    event,
    inspect,
    select,
)
from sqlalchemy.orm import Session, sessionmaker

from tracefence.config import settings
from tracefence.db.models import Base, SchemaMetadata

# SQLite triggers make the proof revision a database-owned consistency
# boundary. Service code cannot accidentally omit a bump when it mutates an
# existing proof input. Adding a new proof-relevant table still requires adding
# it here and to the trigger-presence schema check.
_PROOF_RELEVANT_RUN_TABLES = (
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
_PROOF_REVISION_TRIGGER_DDL = Template(
    """
    CREATE TRIGGER IF NOT EXISTS $trigger_name
    AFTER $operation ON $table
    BEGIN
        UPDATE runs
        SET proof_revision = proof_revision + 1
        WHERE id = $row.run_id;
    END
    """
)


def _proof_revision_trigger_names() -> set[str]:
    return {
        f"trg_{table}_{operation}_proof_revision"
        for table in _PROOF_RELEVANT_RUN_TABLES
        for operation in ("insert", "update", "delete")
    } | {"trg_runs_update_proof_revision"}


def _install_proof_revision_triggers(selected_engine: Engine) -> None:
    if selected_engine.dialect.name != "sqlite":
        return
    with selected_engine.begin() as connection:
        for table in _PROOF_RELEVANT_RUN_TABLES:
            for operation in ("insert", "update", "delete"):
                row = "OLD" if operation == "delete" else "NEW"
                # Identifiers come exclusively from the private constant tuple
                # above and the fixed operation tuple; no request/configuration
                # value can reach this schema-bootstrap DDL.
                trigger_ddl = _PROOF_REVISION_TRIGGER_DDL.substitute(
                    trigger_name=f"trg_{table}_{operation}_proof_revision",
                    operation=operation.upper(),
                    table=table,
                    row=row,
                )
                connection.exec_driver_sql(trigger_ddl)
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


def _validate_proof_revision_triggers(selected_engine: Engine) -> None:
    if selected_engine.dialect.name != "sqlite":
        return
    with selected_engine.connect() as connection:
        actual = set(
            connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ).scalars()
        )
    missing = sorted(_proof_revision_trigger_names() - actual)
    if missing:
        raise RuntimeError(
            "SCHEMA_MIGRATION_REQUIRED: proof revision triggers are missing: "
            + ", ".join(missing)
        )


def _normalize_url(database_url: str) -> str:
    return database_url.replace("sqlite+aiosqlite://", "sqlite+pysqlite://")


def _ensure_sqlite_parent(database_url: str) -> None:
    prefix = "sqlite+pysqlite:///"
    if database_url.startswith(prefix):
        path = database_url.removeprefix(prefix)
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)


def build_engine(database_url: str | None = None) -> Engine:
    url = _normalize_url(database_url or settings.database_url)
    _ensure_sqlite_parent(url)
    engine = create_engine(
        url,
        future=True,
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
    )

    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection: object, _connection_record: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    return engine


def _validate_schema_shape(selected_engine: Engine) -> None:
    inspector = inspect(selected_engine)
    actual_tables = set(inspector.get_table_names())
    expected_tables = set(Base.metadata.tables)
    missing_tables = sorted(expected_tables - actual_tables)
    if missing_tables:
        raise RuntimeError(
            "SCHEMA_MIGRATION_REQUIRED: schema version is current but tables are missing: "
            + ", ".join(missing_tables)
        )

    mismatches: list[str] = []
    for table_name, table in Base.metadata.tables.items():
        expected_columns = {column.name for column in table.columns}
        actual_columns = {column["name"] for column in inspector.get_columns(table_name)}
        missing_columns = sorted(expected_columns - actual_columns)
        if missing_columns:
            mismatches.append(f"{table_name}({', '.join(missing_columns)})")
    if mismatches:
        raise RuntimeError(
            "SCHEMA_MIGRATION_REQUIRED: schema version is current but columns are missing: "
            + "; ".join(mismatches)
        )

    # A version row plus matching columns is insufficient for an authoritative
    # control registry: a copied/partially migrated database could silently lose
    # the foreign keys and checks that enforce tenant and lineage isolation.
    constraint_mismatches: list[str] = []
    for table_name, table in Base.metadata.tables.items():
        expected_fk = {
            constraint.name
            for constraint in table.constraints
            if isinstance(constraint, ForeignKeyConstraint) and constraint.name
        }
        expected_uq = {
            constraint.name
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint) and constraint.name
        }
        expected_ck = {
            constraint.name
            for constraint in table.constraints
            if isinstance(constraint, CheckConstraint) and constraint.name
        }
        expected_ix = {index.name for index in table.indexes if index.name}

        actual_fk = {item.get("name") for item in inspector.get_foreign_keys(table_name)}
        actual_uq = {item.get("name") for item in inspector.get_unique_constraints(table_name)}
        actual_ck = {item.get("name") for item in inspector.get_check_constraints(table_name)}
        actual_ix = {item.get("name") for item in inspector.get_indexes(table_name)}

        missing = sorted(
            (expected_fk - actual_fk)
            | (expected_uq - actual_uq)
            | (expected_ck - actual_ck)
            | (expected_ix - actual_ix)
        )
        if missing:
            constraint_mismatches.append(f"{table_name}({', '.join(missing)})")
    if constraint_mismatches:
        raise RuntimeError(
            "SCHEMA_MIGRATION_REQUIRED: schema version is current but constraints or "
            "indexes are missing: " + "; ".join(constraint_mismatches)
        )


engine = build_engine()
SessionLocal = sessionmaker(engine, expire_on_commit=False, class_=Session)


SCHEMA_VERSION = 15


def init_db(target_engine: Engine | None = None) -> None:
    selected_engine = target_engine or engine
    existing_tables = set(inspect(selected_engine).get_table_names())

    if not existing_tables:
        Base.metadata.create_all(selected_engine)
        _install_proof_revision_triggers(selected_engine)
        with Session(selected_engine) as session:
            session.add(SchemaMetadata(id=1, version=SCHEMA_VERSION))
            session.commit()
        _validate_proof_revision_triggers(selected_engine)
        return

    if "schema_metadata" not in existing_tables:
        raise RuntimeError(
            "SCHEMA_MIGRATION_REQUIRED: this database predates the hardened TraceFence "
            "schema. Back it up, then reset it with scripts/reset_state.py --yes or run "
            "an explicit migration."
        )

    with Session(selected_engine) as session:
        metadata = session.scalar(select(SchemaMetadata).where(SchemaMetadata.id == 1))
        if metadata is None or metadata.version != SCHEMA_VERSION:
            found = metadata.version if metadata is not None else "missing"
            raise RuntimeError(
                f"SCHEMA_MIGRATION_REQUIRED: database schema version {found}; "
                f"application requires {SCHEMA_VERSION}."
            )

    _validate_schema_shape(selected_engine)
    _install_proof_revision_triggers(selected_engine)
    _validate_proof_revision_triggers(selected_engine)


def drop_db(target_engine: Engine | None = None) -> None:
    Base.metadata.drop_all(target_engine or engine)
