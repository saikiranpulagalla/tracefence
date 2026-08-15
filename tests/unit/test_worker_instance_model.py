from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError, IntegrityError

from tests.helpers import create_seeded_run
from tracefence.db.engine import ALEMBIC_HEAD, SCHEMA_VERSION, build_engine, init_db
from tracefence.db.models import Node, Run, SpawnIntent, WorkerInstance
from tracefence.domain.errors import ConflictError, NotFoundError
from tracefence.domain.schemas import SpawnCreate
from tracefence.services.spawn_service import SpawnService
from tracefence.services.worker_instance_service import WorkerInstanceService


async def test_create_pending_worker_instance_and_list_by_node(session_factory):
    run = await create_seeded_run(session_factory, "worker-instance-create")
    service = WorkerInstanceService(session_factory)
    instance = await service.create_pending_instance(
        instance_id=str(uuid4()),
        node_id=run.root_node_id,
        incarnation=1,
    )

    assert instance.node_id == run.root_node_id
    assert instance.incarnation == 1
    assert instance.observed_state == "PENDING"
    assert instance.activated_at is None
    assert instance.terminal_at is None
    assert [row.id for row in await service.list_instances_for_node(run.root_node_id)] == [
        instance.id
    ]


async def test_worker_instance_rejects_duplicate_node_incarnation(session_factory):
    run = await create_seeded_run(session_factory, "worker-instance-duplicate")
    service = WorkerInstanceService(session_factory)
    await service.create_pending_instance(
        instance_id=str(uuid4()),
        node_id=run.root_node_id,
        incarnation=1,
    )

    with pytest.raises(IntegrityError):
        await service.create_pending_instance(
            instance_id=str(uuid4()),
            node_id=run.root_node_id,
            incarnation=1,
        )


@pytest.mark.parametrize("incarnation", [0, -1])
async def test_worker_instance_rejects_nonpositive_incarnation(
    session_factory,
    incarnation,
):
    run = await create_seeded_run(session_factory, "worker-instance-incarnation")
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.add(
                WorkerInstance(
                    id=str(uuid4()),
                    node_id=run.root_node_id,
                    incarnation=incarnation,
                    observed_state="PENDING",
                )
            )


async def test_worker_instance_rejects_unknown_node_and_foreign_key_is_enforced(
    session_factory,
):
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.add(
                WorkerInstance(
                    id=str(uuid4()),
                    node_id=str(uuid4()),
                    incarnation=1,
                    observed_state="PENDING",
                )
            )


@pytest.mark.parametrize(
    ("observed_state", "activated_at", "terminal_at"),
    [
        ("PENDING", None, None),
        ("ACTIVE", datetime(2026, 1, 1), None),
        ("EXITED", datetime(2026, 1, 1), datetime(2026, 1, 2)),
        ("FAILED", None, datetime(2026, 1, 2)),
    ],
)
async def test_worker_instance_accepts_valid_physical_states(
    session_factory,
    observed_state,
    activated_at,
    terminal_at,
):
    run = await create_seeded_run(session_factory, "worker-instance-valid-state")
    with session_factory.begin() as session:
        session.add(
            WorkerInstance(
                id=str(uuid4()),
                node_id=run.root_node_id,
                incarnation=1,
                observed_state=observed_state,
                activated_at=activated_at,
                terminal_at=terminal_at,
            )
        )


async def test_worker_instance_rejects_invalid_physical_state(session_factory):
    run = await create_seeded_run(session_factory, "worker-instance-invalid-state")
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.add(
                WorkerInstance(
                    id=str(uuid4()),
                    node_id=run.root_node_id,
                    incarnation=1,
                    observed_state="LOST",
                )
            )


async def test_worker_instance_transitions_are_physical_and_terminal_states_do_not_revive(
    session_factory,
):
    run = await create_seeded_run(session_factory, "worker-instance-transitions")
    service = WorkerInstanceService(session_factory)
    instance = await service.create_pending_instance(
        instance_id=str(uuid4()),
        node_id=run.root_node_id,
        incarnation=1,
        created_at=datetime(2026, 1, 1),
    )

    active = await service.transition_observed_state(
        instance.id,
        "ACTIVE",
        observed_at=datetime(2026, 1, 2),
    )
    exited = await service.transition_observed_state(
        instance.id,
        "EXITED",
        observed_at=datetime(2026, 1, 3),
    )

    assert active.activated_at == datetime(2026, 1, 2)
    assert exited.terminal_at == datetime(2026, 1, 3)
    with pytest.raises(ConflictError, match="invalid") as resurrection:
        await service.transition_observed_state(instance.id, "ACTIVE")
    assert resurrection.value.code == "WORKER_INSTANCE_TRANSITION_INVALID"



async def test_worker_instance_allows_both_failed_paths(session_factory):
    run = await create_seeded_run(session_factory, "worker-instance-failed-paths")
    service = WorkerInstanceService(session_factory)
    pending_failure = await service.create_pending_instance(
        instance_id=str(uuid4()),
        node_id=run.root_node_id,
        incarnation=1,
    )
    active_failure = await service.create_pending_instance(
        instance_id=str(uuid4()),
        node_id=run.root_node_id,
        incarnation=2,
    )

    failed_before_activation = await service.transition_observed_state(
        pending_failure.id,
        "FAILED",
        observed_at=datetime(2026, 1, 2),
    )
    await service.transition_observed_state(
        active_failure.id,
        "ACTIVE",
        observed_at=datetime(2026, 1, 2),
    )
    failed_after_activation = await service.transition_observed_state(
        active_failure.id,
        "FAILED",
        observed_at=datetime(2026, 1, 3),
    )

    assert failed_before_activation.activated_at is None
    assert failed_before_activation.terminal_at == datetime(2026, 1, 2)
    assert failed_after_activation.activated_at == datetime(2026, 1, 2)
    assert failed_after_activation.terminal_at == datetime(2026, 1, 3)


async def test_worker_instance_rejects_illegal_pending_transition(session_factory):
    run = await create_seeded_run(session_factory, "worker-instance-illegal-transition")
    service = WorkerInstanceService(session_factory)
    instance = await service.create_pending_instance(
        instance_id=str(uuid4()),
        node_id=run.root_node_id,
        incarnation=1,
    )

    with pytest.raises(ConflictError, match="invalid"):
        await service.transition_observed_state(instance.id, "EXITED")


async def test_worker_instance_id_is_immutable(session_factory):
    run = await create_seeded_run(session_factory, "worker-instance-id-immutable")
    service = WorkerInstanceService(session_factory)
    instance = await service.create_pending_instance(
        instance_id=str(uuid4()),
        node_id=run.root_node_id,
        incarnation=1,
    )

    with pytest.raises(DatabaseError, match="WORKER_INSTANCE_ID_IMMUTABLE"):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE worker_instances SET id = :new_id WHERE id = :instance_id"),
                {"new_id": str(uuid4()), "instance_id": instance.id},
            )


async def test_terminal_node_keeps_historical_worker_instances(session_factory):
    run = await create_seeded_run(session_factory, "worker-instance-terminal-node")
    service = WorkerInstanceService(session_factory)
    instance = await service.create_pending_instance(
        instance_id=str(uuid4()),
        node_id=run.root_node_id,
        incarnation=1,
    )
    with session_factory.begin() as session:
        session.execute(
            text(
                "UPDATE nodes SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP "
                "WHERE id = :node_id"
            ),
            {"node_id": run.root_node_id},
        )

    with session_factory() as session:
        assert session.scalar(
            select(WorkerInstance.id).where(WorkerInstance.id == instance.id)
        ) == instance.id


async def test_legacy_nodes_without_worker_instances_remain_valid(session_factory):
    run = await create_seeded_run(session_factory, "worker-instance-legacy")
    with session_factory() as session:
        assert session.scalars(
            select(WorkerInstance).where(WorkerInstance.node_id == run.root_node_id)
        ).all() == []


async def test_worker_instance_service_reports_missing_instance(session_factory):
    service = WorkerInstanceService(session_factory)
    with pytest.raises(NotFoundError):
        await service.get_instance(str(uuid4()))


def _alembic_config(database_path):
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")
    return config


def test_alembic_fresh_worker_instance_migration_and_repeat_behavior(tmp_path):
    from alembic import command

    path = tmp_path / "fresh-worker-instance.db"
    config = _alembic_config(path)
    command.upgrade(config, "head")
    command.upgrade(config, "head")

    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        tables = set(
            connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).scalars()
        )
        version = connection.execute(
            text("SELECT version FROM schema_metadata WHERE id = 1")
        ).scalar_one()
        revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
    assert "worker_instances" in tables
    assert version == SCHEMA_VERSION
    assert revision == ALEMBIC_HEAD
    engine.dispose()


def test_alembic_upgrade_from_previous_schema_adds_worker_instances(tmp_path):
    from alembic import command

    path = tmp_path / "upgrade-worker-instance.db"
    config = _alembic_config(path)
    command.upgrade(config, "002_schema_v18_runtime_inspector")

    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.begin() as connection:
        # The initial historical migration imports model metadata. Remove the
        # current-model table to faithfully represent the v18 deployed shape.
        connection.execute(text("DROP TABLE IF EXISTS worker_instances"))
    engine.dispose()

    command.upgrade(config, "head")

    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT version FROM schema_metadata WHERE id = 1")
        ).scalar_one() == SCHEMA_VERSION
        assert "worker_instances" in set(
            connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).scalars()
        )
    engine.dispose()


def test_schema_guard_rejects_missing_worker_instance_table(tmp_path):
    engine = build_engine(f"sqlite+pysqlite:///{tmp_path / 'missing-worker-instance.db'}")
    init_db(engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE worker_instances"))

    with pytest.raises(RuntimeError, match="worker_instances"):
        init_db(engine)
    engine.dispose()


async def test_current_behavior_creates_protocol_one_runs(session_factory):
    run = await create_seeded_run(session_factory, "protocol-one-default")

    with session_factory() as session:
        assert session.scalar(
            select(Run.execution_protocol_version).where(Run.id == run.run_id)
        ) == 1


async def test_execution_protocol_version_rejects_invalid_value(session_factory):
    with pytest.raises(IntegrityError, match="CHECK constraint failed"):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "INSERT INTO runs ("
                    "id, name, status, root_node_id, run_scope_id, created_at, "
                    "execution_protocol_version"
                    ") VALUES ("
                    "'invalid-protocol', 'invalid', 'CREATED', 'invalid-root', "
                    "'invalid-scope', '2026-01-01 00:00:00', 3"
                    ")"
                )
            )


async def test_execution_protocol_version_is_immutable(session_factory):
    run = await create_seeded_run(session_factory, "protocol-immutable")

    with pytest.raises(DatabaseError, match="RUN_EXECUTION_PROTOCOL_VERSION_IMMUTABLE"):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE runs SET execution_protocol_version = 2 "
                    "WHERE id = :run_id"
                ),
                {"run_id": run.run_id},
            )


async def test_node_current_worker_instance_pointer_allows_null_and_same_node(
    session_factory,
):
    run = await create_seeded_run(session_factory, "current-instance-same-node")
    instance_id = str(uuid4())

    with session_factory() as session:
        assert session.scalar(
            select(Node.current_worker_instance_id).where(
                Node.id == run.root_node_id
            )
        ) is None

    with session_factory.begin() as session:
        session.add(
            WorkerInstance(
                id=instance_id,
                node_id=run.root_node_id,
                incarnation=1,
                observed_state="PENDING",
            )
        )

    with session_factory.begin() as session:
        session.execute(
            text(
                "UPDATE nodes SET current_worker_instance_id = :instance_id "
                "WHERE id = :node_id"
            ),
            {"instance_id": instance_id, "node_id": run.root_node_id},
        )

    with session_factory() as session:
        assert session.scalar(
            select(Node.current_worker_instance_id).where(
                Node.id == run.root_node_id
            )
        ) == instance_id


async def test_node_current_worker_instance_pointer_rejects_cross_node(
    session_factory,
):
    run_a = await create_seeded_run(session_factory, "current-instance-a")
    run_b = await create_seeded_run(session_factory, "current-instance-b")
    foreign_instance_id = str(uuid4())

    with session_factory.begin() as session:
        session.add(
            WorkerInstance(
                id=foreign_instance_id,
                node_id=run_b.root_node_id,
                incarnation=1,
                observed_state="PENDING",
            )
        )

    with pytest.raises(DatabaseError, match="NODE_CURRENT_WORKER_INSTANCE_NODE_MISMATCH"):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE nodes SET current_worker_instance_id = :instance_id "
                    "WHERE id = :node_id"
                ),
                {
                    "instance_id": foreign_instance_id,
                    "node_id": run_a.root_node_id,
                },
            )


async def test_activation_intent_id_is_unique_but_allows_multiple_nulls(
    session_factory,
):
    run = await create_seeded_run(session_factory, "activation-intent-unique")
    spawns = SpawnService(session_factory)
    created = await spawns.create_spawn(
        run.root_node_id,
        run.root_token,
        SpawnCreate(role="intent-child", capabilities=[]),
    )
    with session_factory() as session:
        intent = session.scalar(
            select(SpawnIntent).where(
                SpawnIntent.child_node_id == created.child_node_id
            )
        )
        assert intent is not None
        intent_id = intent.id

    with session_factory.begin() as session:
        session.add_all(
            [
                WorkerInstance(
                    id=str(uuid4()),
                    node_id=run.root_node_id,
                    incarnation=1,
                    observed_state="PENDING",
                ),
                WorkerInstance(
                    id=str(uuid4()),
                    node_id=created.child_node_id,
                    incarnation=1,
                    observed_state="PENDING",
                ),
            ]
        )

    with session_factory.begin() as session:
        session.add(
            WorkerInstance(
                id=str(uuid4()),
                node_id=created.child_node_id,
                incarnation=2,
                observed_state="PENDING",
                activation_intent_id=intent_id,
            )
        )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.add(
                WorkerInstance(
                    id=str(uuid4()),
                    node_id=run.root_node_id,
                    incarnation=2,
                    observed_state="PENDING",
                    activation_intent_id=intent_id,
                )
            )


async def test_worker_instance_v2_storage_and_historical_revisions_are_nullable(
    session_factory,
):
    run = await create_seeded_run(session_factory, "worker-v2-storage-null")
    instance_id = str(uuid4())

    with session_factory.begin() as session:
        session.add(
            WorkerInstance(
                id=instance_id,
                node_id=run.root_node_id,
                incarnation=1,
                observed_state="PENDING",
            )
        )

    with session_factory() as session:
        instance = session.get(WorkerInstance, instance_id)
        assert instance is not None
        assert instance.credential_hash is None
        assert instance.credential_confirmed_at is None
        assert instance.activated_revision is None
        assert instance.terminal_revision is None


@pytest.mark.parametrize(
    ("activated_revision", "terminal_revision"),
    [(-1, None), (None, -1), (4, 4)],
)
async def test_worker_instance_rejects_invalid_revision_order(
    session_factory,
    activated_revision,
    terminal_revision,
):
    run = await create_seeded_run(session_factory, "worker-revision-constraints")

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.add(
                WorkerInstance(
                    id=str(uuid4()),
                    node_id=run.root_node_id,
                    incarnation=1,
                    observed_state="PENDING",
                    activated_revision=activated_revision,
                    terminal_revision=terminal_revision,
                )
            )


def test_phase1b1_schema_has_no_current_incarnation_and_guards_triggers(tmp_path):
    from sqlalchemy import inspect

    from tracefence.db.engine import _validate_required_triggers

    engine = build_engine(f"sqlite+pysqlite:///{tmp_path / 'phase1b1-schema.db'}")
    init_db(engine)

    assert {
        column["name"] for column in inspect(engine).get_columns("nodes")
    }.isdisjoint({"current_incarnation"})
    _validate_required_triggers(engine)
    with engine.begin() as connection:
        connection.execute(
            text("DROP TRIGGER trg_runs_execution_protocol_version_immutable")
        )
    with pytest.raises(RuntimeError, match="trg_runs_execution_protocol_version_immutable"):
        _validate_required_triggers(engine)
    engine.dispose()


def test_alembic_upgrade_from_phase1a_preserves_protocol_one_runs(tmp_path):
    from alembic import command

    path = tmp_path / "upgrade-phase1a.db"
    config = _alembic_config(path)
    command.upgrade(config, "003_schema_v19_worker_instances")

    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        object_names = set(
            connection.exec_driver_sql("SELECT name FROM sqlite_master").scalars()
        )
        assert (
            "trg_credential_recovery_envelopes_v2_child_binding_insert"
            not in object_names
        )
        assert "uq_credential_recovery_v2_spawn_intent" not in object_names
        assert (
            "uq_credential_recovery_v2_subject_worker_instance"
            not in object_names
        )
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(text("DROP TABLE runs"))
        connection.execute(
            text(
                "CREATE TABLE runs ("
                "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                "name VARCHAR(120) NOT NULL, status VARCHAR(24) NOT NULL, "
                "root_node_id VARCHAR(36) NOT NULL, run_scope_id VARCHAR(36) NOT NULL, "
                "created_at DATETIME NOT NULL, finished_at DATETIME, "
                "proof_revision INTEGER NOT NULL DEFAULT 0, "
                "CHECK (status IN ('CREATED','RUNNING','COMPLETED','CANCELLED','FAILED')), "
                "CHECK (root_node_id IS NOT NULL), "
                "CHECK ((status IN ('COMPLETED','CANCELLED','FAILED') "
                "AND finished_at IS NOT NULL) OR "
                "(status IN ('CREATED','RUNNING') AND finished_at IS NULL))"
                ")"
            )
        )
        connection.execute(
            text(
                "INSERT INTO runs "
                "(id, name, status, root_node_id, run_scope_id, created_at) "
                "VALUES ("
                "'legacy-run', 'legacy', 'CREATED', 'legacy-root', 'legacy-scope', "
                "'2026-01-01 00:00:00'"
                ")"
            )
        )
        connection.execute(text("DROP TABLE worker_instances"))
        connection.execute(
            text(
                "CREATE TABLE worker_instances ("
                "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                "node_id VARCHAR(36) NOT NULL, "
                "incarnation INTEGER NOT NULL, "
                "observed_state VARCHAR(16) NOT NULL, "
                "created_at DATETIME NOT NULL, "
                "activated_at DATETIME, terminal_at DATETIME, "
                "FOREIGN KEY(node_id) REFERENCES nodes (id) ON DELETE CASCADE, "
                "UNIQUE(node_id, incarnation), "
                "CHECK (incarnation >= 1), "
                "CHECK (observed_state IN ('PENDING','ACTIVE','EXITED','FAILED'))"
                ")"
            )
        )
        connection.execute(
            text(
                "INSERT INTO nodes ("
                "id, run_id, role, behavior, generation, lineage_path, status, "
                "own_scope_id, scope_snapshot_json, instruction_version, "
                "instruction_json, capabilities_json, registered_at"
                ") VALUES ("
                "'legacy-node', 'legacy-run', 'legacy', 'cooperative', 0, "
                "'legacy-node', 'PENDING', 'legacy-scope', '[]', 1, '{}', '[]', "
                "'2026-01-01 00:00:00'"
                ")"
            )
        )
        connection.execute(
            text(
                "INSERT INTO worker_instances "
                "(id, node_id, incarnation, observed_state, created_at) VALUES "
                "('legacy-worker', 'legacy-node', 1, 'PENDING', "
                "'2026-01-01 00:00:00')"
            )
        )
    engine.dispose()

    command.upgrade(config, "head")

    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT version FROM schema_metadata WHERE id = 1")
        ).scalar_one() == SCHEMA_VERSION
        assert connection.execute(
            text(
                "SELECT execution_protocol_version FROM runs "
                "WHERE id = 'legacy-run'"
            )
        ).scalar_one() == 1
        assert connection.execute(
            text(
                "SELECT activation_intent_id, credential_hash, "
                "credential_confirmed_at, activated_revision, terminal_revision "
                "FROM worker_instances WHERE id = 'legacy-worker'"
            )
        ).one() == (None, None, None, None, None)
        assert connection.execute(
            text(
                "SELECT current_worker_instance_id FROM nodes "
                "WHERE id = 'legacy-node'"
            )
        ).scalar_one() is None
    engine.dispose()


async def test_protocol_check_allows_v2_and_protocol_guards_are_narrow(session_factory):
    run = await create_seeded_run(session_factory, "protocol-guard-narrow")

    with session_factory.begin() as session:
        session.execute(
            text(
                "UPDATE runs SET execution_protocol_version = execution_protocol_version "
                "WHERE id = :run_id"
            ),
            {"run_id": run.run_id},
        )
        session.execute(
            text("UPDATE runs SET name = :name WHERE id = :run_id"),
            {"name": "ordinary update", "run_id": run.run_id},
        )

    with pytest.raises(DatabaseError, match="RUN_EXECUTION_PROTOCOL_VERSION_IMMUTABLE"):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE runs SET execution_protocol_version = 2 "
                    "WHERE id = :run_id"
                ),
                {"run_id": run.run_id},
            )


def test_protocol_check_allows_explicit_v2_insert(tmp_path):
    engine = build_engine(f"sqlite+pysqlite:///{tmp_path / 'protocol-v2.db'}")
    init_db(engine)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(
            text(
                "INSERT INTO runs "
                "(id, name, status, root_node_id, run_scope_id, created_at, "
                "execution_protocol_version) VALUES "
                "('protocol-v2', 'v2', 'CREATED', 'root', 'scope', "
                "'2026-01-01 00:00:00', 2)"
            )
        )
        connection.commit()
        assert connection.execute(
            text(
                "SELECT execution_protocol_version FROM runs "
                "WHERE id = 'protocol-v2'"
            )
        ).scalar_one() == 2
        with pytest.raises(
            DatabaseError, match="RUN_EXECUTION_PROTOCOL_VERSION_IMMUTABLE"
        ):
            connection.execute(
                text(
                    "UPDATE runs SET execution_protocol_version = 1 "
                    "WHERE id = 'protocol-v2'"
                )
            )
    engine.dispose()


async def test_current_worker_instance_pointer_rejects_missing_and_switches_with_proof_revision(
    session_factory,
):
    run = await create_seeded_run(session_factory, "current-pointer-switch")
    first_id, second_id = str(uuid4()), str(uuid4())
    with session_factory.begin() as session:
        session.add_all(
            [
                WorkerInstance(
                    id=first_id,
                    node_id=run.root_node_id,
                    incarnation=1,
                    observed_state="PENDING",
                ),
                WorkerInstance(
                    id=second_id,
                    node_id=run.root_node_id,
                    incarnation=2,
                    observed_state="PENDING",
                ),
            ]
        )

    with pytest.raises(DatabaseError, match="NODE_CURRENT_WORKER_INSTANCE_NODE_MISMATCH"):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE nodes SET current_worker_instance_id = :instance_id "
                    "WHERE id = :node_id"
                ),
                {"instance_id": str(uuid4()), "node_id": run.root_node_id},
            )

    with session_factory() as session:
        before = session.scalar(select(Run.proof_revision).where(Run.id == run.run_id))
    with session_factory.begin() as session:
        session.execute(
            text(
                "UPDATE nodes SET current_worker_instance_id = :instance_id "
                "WHERE id = :node_id"
            ),
            {"instance_id": first_id, "node_id": run.root_node_id},
        )
    with session_factory() as session:
        after_first = session.scalar(
            select(Run.proof_revision).where(Run.id == run.run_id)
        )
    with session_factory.begin() as session:
        session.execute(
            text(
                "UPDATE nodes SET current_worker_instance_id = :instance_id "
                "WHERE id = :node_id"
            ),
            {"instance_id": second_id, "node_id": run.root_node_id},
        )
    with session_factory() as session:
        after_switch = session.scalar(
            select(Run.proof_revision).where(Run.id == run.run_id)
        )
        assert session.scalar(
            select(Node.current_worker_instance_id).where(Node.id == run.root_node_id)
        ) == second_id
    assert after_first == before + 1
    assert after_switch == after_first + 1


async def test_worker_instance_direct_delete_and_physical_identity_rewrites_are_rejected(
    session_factory,
):
    run_a = await create_seeded_run(session_factory, "worker-delete-current")
    run_b = await create_seeded_run(session_factory, "worker-delete-noncurrent")
    first_id, second_id = str(uuid4()), str(uuid4())
    with session_factory.begin() as session:
        session.add_all(
            [
                WorkerInstance(
                    id=first_id,
                    node_id=run_a.root_node_id,
                    incarnation=1,
                    observed_state="PENDING",
                ),
                WorkerInstance(
                    id=second_id,
                    node_id=run_a.root_node_id,
                    incarnation=2,
                    observed_state="PENDING",
                ),
            ]
        )
        session.flush()
        session.execute(
            text(
                "UPDATE nodes SET current_worker_instance_id = :instance_id "
                "WHERE id = :node_id"
            ),
            {"instance_id": first_id, "node_id": run_a.root_node_id},
        )

    for instance_id in (first_id, second_id):
        with pytest.raises(DatabaseError, match="WORKER_INSTANCE_DELETE_PROHIBITED"):
            with session_factory.begin() as session:
                session.execute(
                    text("DELETE FROM worker_instances WHERE id = :instance_id"),
                    {"instance_id": instance_id},
                )

    with pytest.raises(DatabaseError, match="WORKER_INSTANCE_NODE_ID_IMMUTABLE"):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE worker_instances SET node_id = :node_id WHERE id = :id"),
                {"node_id": run_b.root_node_id, "id": first_id},
            )
    with pytest.raises(DatabaseError, match="WORKER_INSTANCE_INCARNATION_IMMUTABLE"):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE worker_instances SET incarnation = 9 "
                    "WHERE id = :id"
                ),
                {"id": first_id},
            )


async def test_activation_intent_identity_and_referenced_fk_are_immutable(session_factory):
    run = await create_seeded_run(session_factory, "activation-intent-identity")
    spawns = SpawnService(session_factory)
    first = await spawns.create_spawn(
        run.root_node_id, run.root_token, SpawnCreate(role="first", capabilities=[])
    )
    second = await spawns.create_spawn(
        run.root_node_id, run.root_token, SpawnCreate(role="second", capabilities=[])
    )
    with session_factory() as session:
        first_intent = session.scalar(
            select(SpawnIntent.id).where(SpawnIntent.child_node_id == first.child_node_id)
        )
        second_intent = session.scalar(
            select(SpawnIntent.id).where(SpawnIntent.child_node_id == second.child_node_id)
        )
    assert first_intent is not None
    assert second_intent is not None

    null_instance, bound_instance = str(uuid4()), str(uuid4())
    with session_factory.begin() as session:
        session.add_all(
            [
                WorkerInstance(
                    id=null_instance,
                    node_id=run.root_node_id,
                    incarnation=1,
                    observed_state="PENDING",
                ),
                WorkerInstance(
                    id=bound_instance,
                    node_id=first.child_node_id,
                    incarnation=1,
                    observed_state="PENDING",
                    activation_intent_id=first_intent,
                ),
            ]
        )

    statements = (
        (
            "UPDATE worker_instances SET activation_intent_id = :intent WHERE id = :id",
            {"intent": first_intent, "id": null_instance},
        ),
        (
            "UPDATE worker_instances SET activation_intent_id = NULL WHERE id = :id",
            {"id": bound_instance},
        ),
        (
            "UPDATE worker_instances SET activation_intent_id = :intent WHERE id = :id",
            {"intent": second_intent, "id": bound_instance},
        ),
    )
    for statement, params in statements:
        with pytest.raises(
            DatabaseError, match="WORKER_INSTANCE_ACTIVATION_INTENT_ID_IMMUTABLE"
        ):
            with session_factory.begin() as session:
                session.execute(text(statement), params)

    for statement, params in (
        ("DELETE FROM spawn_intents WHERE id = :id", {"id": first_intent}),
        (
            "UPDATE spawn_intents SET id = :replacement WHERE id = :id",
            {"replacement": str(uuid4()), "id": first_intent},
        ),
    ):
        with pytest.raises(IntegrityError):
            with session_factory.begin() as session:
                session.execute(text(statement), params)


async def test_direct_sql_lifecycle_and_once_set_facts_are_hardened(session_factory):
    run = await create_seeded_run(session_factory, "worker-lifecycle-db-guard")
    active_id, failed_id, pending_failed_id = str(uuid4()), str(uuid4()), str(uuid4())
    with session_factory.begin() as session:
        session.add_all(
            [
                WorkerInstance(
                    id=active_id,
                    node_id=run.root_node_id,
                    incarnation=1,
                    observed_state="PENDING",
                ),
                WorkerInstance(
                    id=failed_id,
                    node_id=run.root_node_id,
                    incarnation=2,
                    observed_state="PENDING",
                ),
                WorkerInstance(
                    id=pending_failed_id,
                    node_id=run.root_node_id,
                    incarnation=3,
                    observed_state="PENDING",
                ),
            ]
        )
        session.flush()
        session.execute(
            text(
                "UPDATE worker_instances SET observed_state = 'ACTIVE', "
                "activated_at = '2026-01-01 00:00:00' WHERE id = :id"
            ),
            {"id": active_id},
        )
        session.execute(
            text(
                "UPDATE worker_instances SET observed_state = 'FAILED', "
                "terminal_at = '2026-01-02 00:00:00' WHERE id = :id"
            ),
            {"id": pending_failed_id},
        )
        session.execute(
            text(
                "UPDATE worker_instances SET observed_state = 'ACTIVE', "
                "activated_at = '2026-01-01 00:00:00' WHERE id = :id"
            ),
            {"id": failed_id},
        )
        session.execute(
            text(
                "UPDATE worker_instances SET observed_state = 'FAILED', "
                "terminal_at = '2026-01-02 00:00:00' WHERE id = :id"
            ),
            {"id": failed_id},
        )
        session.execute(
            text(
                "UPDATE worker_instances SET observed_state = 'EXITED', "
                "terminal_at = '2026-01-03 00:00:00' WHERE id = :id"
            ),
            {"id": active_id},
        )
        session.execute(
            text(
                "UPDATE worker_instances SET activated_revision = 5, "
                "terminal_revision = 6, credential_confirmed_at = '2026-01-04 00:00:00' "
                "WHERE id = :id"
            ),
            {"id": active_id},
        )

    for state_id in (active_id, failed_id):
        with pytest.raises(DatabaseError):
            with session_factory.begin() as session:
                session.execute(
                    text(
                        "UPDATE worker_instances SET observed_state = 'ACTIVE' "
                        "WHERE id = :id"
                    ),
                    {"id": state_id},
                )

    for column, value, code in (
        ("activated_at", "'2026-01-05 00:00:00'", "ACTIVATED_AT"),
        ("terminal_at", "'2026-01-05 00:00:00'", "TERMINAL_AT"),
        ("activated_revision", "7", "ACTIVATED_REVISION"),
        ("terminal_revision", "7", "TERMINAL_REVISION"),
        ("credential_confirmed_at", "'2026-01-05 00:00:00'", "CREDENTIAL_CONFIRMED_AT"),
    ):
        with pytest.raises(DatabaseError, match=f"WORKER_INSTANCE_{code}_IMMUTABLE"):
            with session_factory.begin() as session:
                session.execute(
                    text(
                        f"UPDATE worker_instances SET {column} = {value} "
                        "WHERE id = :id"
                    ),
                    {"id": active_id},
                )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE worker_instances SET activated_revision = 8, "
                    "terminal_revision = 8 WHERE id = :id"
                ),
                {"id": pending_failed_id},
            )
