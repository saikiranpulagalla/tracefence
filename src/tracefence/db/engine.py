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
from sqlalchemy.engine import make_url
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
_RUNTIME_EVENT_TRIGGER_NAMES = {
    "trg_runtime_events_no_update",
    "trg_runtime_events_no_delete",
}

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


def _validate_required_triggers(selected_engine: Engine) -> None:
    if selected_engine.dialect.name != "sqlite":
        return
    with selected_engine.connect() as connection:
        actual = set(
            connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ).scalars()
        )
    required = _proof_revision_trigger_names() | _RUNTIME_EVENT_TRIGGER_NAMES
    missing = sorted(required - actual)
    if missing:
        raise RuntimeError(
            "SCHEMA_MIGRATION_REQUIRED: required database triggers are missing: "
            + ", ".join(missing)
        )


def _normalize_url(database_url: str) -> str:
    parsed = make_url(database_url)
    if parsed.get_backend_name() != "sqlite":
        raise RuntimeError(
            "UNSUPPORTED_DATABASE_DIALECT: TraceFence currently supports only SQLite"
        )
    if parsed.drivername == "sqlite+aiosqlite":
        parsed = parsed.set(drivername="sqlite+pysqlite")
    if parsed.drivername not in {"sqlite", "sqlite+pysqlite"}:
        raise RuntimeError(
            "UNSUPPORTED_DATABASE_DRIVER: TraceFence requires SQLite with pysqlite"
        )
    return parsed.render_as_string(hide_password=False)


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
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(
        dbapi_connection: object,
        _connection_record: object,
    ) -> None:
        # SQLAlchemy's connect hook intentionally receives the DBAPI protocol,
        # which has no public common type exposing cursor().
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=FULL")
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
        expected_pk = tuple(column.name for column in table.primary_key.columns)
        actual_pk = tuple(
            inspector.get_pk_constraint(table_name).get(
                "constrained_columns",
                (),
            )
            or ()
        )
        if expected_pk != actual_pk:
            constraint_mismatches.append(
                f"{table_name}(primary key {expected_pk!r})"
            )

        expected_fk = {
            (
                tuple(element.parent.name for element in constraint.elements),
                constraint.elements[0].column.table.name,
                tuple(element.column.name for element in constraint.elements),
            )
            for constraint in table.constraints
            if isinstance(constraint, ForeignKeyConstraint)
        }
        actual_fk = {
            (
                tuple(item.get("constrained_columns") or ()),
                str(item.get("referred_table")),
                tuple(item.get("referred_columns") or ()),
            )
            for item in inspector.get_foreign_keys(table_name)
        }
        missing_fk = sorted(expected_fk - actual_fk)
        if missing_fk:
            constraint_mismatches.append(
                f"{table_name}(foreign key {missing_fk!r})"
            )

        expected_uq = {
            tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        actual_uq = {
            tuple(item.get("column_names") or ())
            for item in inspector.get_unique_constraints(table_name)
        }
        missing_uq = sorted(expected_uq - actual_uq)
        if missing_uq:
            constraint_mismatches.append(
                f"{table_name}(unique constraint {missing_uq!r})"
            )

        expected_ck_names = {
            str(constraint.name)
            for constraint in table.constraints
            if isinstance(constraint, CheckConstraint) and constraint.name
        }
        actual_ck_names = {
            item.get("name")
            for item in inspector.get_check_constraints(table_name)
        }
        missing_ck = sorted(expected_ck_names - actual_ck_names)
        if missing_ck:
            constraint_mismatches.append(
                f"{table_name}(check constraint {missing_ck!r})"
            )

        expected_ix = {
            (
                bool(index.unique),
                tuple(column.name for column in index.columns),
            )
            for index in table.indexes
        }
        actual_ix = {
            (
                bool(item.get("unique")),
                tuple(
                    name if isinstance(name, str) else "<unknown>"
                    for name in (item.get("column_names") or ())
                ),
            )
            for item in inspector.get_indexes(table_name)
        }
        missing_ix = sorted(expected_ix - actual_ix)
        if missing_ix:
            constraint_mismatches.append(
                f"{table_name}(index {missing_ix!r})"
            )
    if constraint_mismatches:
        raise RuntimeError(
            "SCHEMA_MIGRATION_REQUIRED: schema version is current but constraints or "
            "indexes are missing: " + "; ".join(constraint_mismatches)
        )


engine = build_engine()
SessionLocal = sessionmaker(engine, expire_on_commit=False, class_=Session)


SCHEMA_VERSION = 18
ALEMBIC_HEAD = "002_schema_v18_runtime_inspector"


def _stamp_alembic_head(selected_engine: Engine) -> None:
    with selected_engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version "
            "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
        )
        versions = list(
            connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalars()
        )
        if not versions:
            connection.exec_driver_sql(
                "INSERT INTO alembic_version (version_num) VALUES (?)",
                (ALEMBIC_HEAD,),
            )
        elif versions != [ALEMBIC_HEAD]:
            raise RuntimeError(
                "SCHEMA_MIGRATION_REQUIRED: Alembic revision "
                f"{versions!r}; application requires {ALEMBIC_HEAD}."
            )


def _reset_failed_empty_bootstrap(selected_engine: Engine) -> None:
    with selected_engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        table_names = list(
            connection.exec_driver_sql(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).scalars()
        )
        for table_name in table_names:
            escaped = str(table_name).replace('"', '""')
            connection.exec_driver_sql(
                f'DROP TABLE IF EXISTS "{escaped}"'
            )
        connection.commit()


def init_db(target_engine: Engine | None = None) -> None:
    selected_engine = target_engine or engine
    if selected_engine.dialect.name != "sqlite":
        raise RuntimeError(
            "UNSUPPORTED_DATABASE_DIALECT: TraceFence currently supports only SQLite"
        )
    existing_tables = set(inspect(selected_engine).get_table_names())

    if not existing_tables:
        try:
            Base.metadata.create_all(selected_engine)
            _install_proof_revision_triggers(selected_engine)
            with Session(selected_engine) as session:
                session.add(SchemaMetadata(id=1, version=SCHEMA_VERSION))
                session.commit()
            _stamp_alembic_head(selected_engine)
            _validate_required_triggers(selected_engine)
        except BaseException as bootstrap_error:
            # This path started from a confirmed empty database. Removing the
            # newly created SQLite tables restores a retryable bootstrap without
            # risking pre-existing user data.
            try:
                _reset_failed_empty_bootstrap(selected_engine)
            except BaseException as cleanup_error:
                bootstrap_error.add_note(
                    "Failed to restore empty database after bootstrap error: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise
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
    _stamp_alembic_head(selected_engine)
    _install_proof_revision_triggers(selected_engine)
    _validate_required_triggers(selected_engine)


def drop_db(target_engine: Engine | None = None) -> None:
    Base.metadata.drop_all(target_engine or engine)
