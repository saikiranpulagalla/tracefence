from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text

from tracefence.db.engine import SCHEMA_VERSION, build_engine, init_db


def test_init_db_records_current_schema_version(tmp_path):
    engine = build_engine(f"sqlite+pysqlite:///{tmp_path / 'fresh.db'}")
    init_db(engine)
    with engine.connect() as connection:
        version = connection.execute(
            text("SELECT version FROM schema_metadata WHERE id = 1")
        ).scalar_one()
    assert version == SCHEMA_VERSION
    engine.dispose()


def test_init_db_refuses_legacy_unversioned_database(tmp_path):
    path = tmp_path / "legacy.db"
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE runs (id TEXT PRIMARY KEY)"))
    with pytest.raises(RuntimeError, match="SCHEMA_MIGRATION_REQUIRED"):
        init_db(engine)
    engine.dispose()


def test_init_db_refuses_wrong_schema_version(tmp_path):
    engine = build_engine(f"sqlite+pysqlite:///{tmp_path / 'wrong.db'}")
    init_db(engine)
    with engine.begin() as connection:
        connection.execute(text("UPDATE schema_metadata SET version = 999 WHERE id = 1"))
    with pytest.raises(RuntimeError, match="schema version 999"):
        init_db(engine)
    engine.dispose()


def test_init_db_refuses_current_version_with_incomplete_shape(tmp_path):
    path = tmp_path / "incomplete.db"
    engine = build_engine(f"sqlite+pysqlite:///{path}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE schema_metadata "
                "(id INTEGER PRIMARY KEY, version INTEGER NOT NULL, updated_at DATETIME)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO schema_metadata (id, version) VALUES (1, :version)"
            ),
            {"version": SCHEMA_VERSION},
        )
        connection.execute(text("CREATE TABLE runs (id TEXT PRIMARY KEY)"))
    with pytest.raises(RuntimeError, match="tables are missing"):
        init_db(engine)
    engine.dispose()


async def test_database_rejects_cross_run_owned_scope_and_invalid_status(session_factory):
    from sqlalchemy.exc import IntegrityError

    from tracefence.db.models import Node
    from tracefence.domain.schemas import SpawnCreate
    from tracefence.services.spawn_service import SpawnService
    from tests.helpers import activate, create_seeded_run

    spawns = SpawnService(session_factory)
    run_a = await create_seeded_run(session_factory, "constraint-a")
    run_b = await create_seeded_run(session_factory, "constraint-b")
    node_a = await activate(
        spawns,
        await spawns.create_spawn(
            run_a.root_node_id,
            run_a.root_token,
            SpawnCreate(role="a", capabilities=[]),
        ),
    )
    node_b = await activate(
        spawns,
        await spawns.create_spawn(
            run_b.root_node_id,
            run_b.root_token,
            SpawnCreate(role="b", capabilities=[]),
        ),
    )

    same_run_node = await activate(
        spawns,
        await spawns.create_spawn(
            run_a.root_node_id,
            run_a.root_token,
            SpawnCreate(role="same-run-owner", capabilities=[]),
        ),
    )

    with session_factory() as read_session:
        foreign_scope = read_session.get(Node, node_b.node_id).own_scope_id
        same_run_foreign_scope = read_session.get(Node, same_run_node.node_id).own_scope_id

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE nodes SET own_scope_id = :scope WHERE id = :node"),
                {"scope": same_run_foreign_scope, "node": node_a.node_id},
            )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE nodes SET own_scope_id = :scope WHERE id = :node"),
                {"scope": foreign_scope, "node": node_a.node_id},
            )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE nodes SET status = 'ROGUE' WHERE id = :node"),
                {"node": node_a.node_id},
            )


async def test_database_rejects_cross_run_replacement_reference(session_factory):
    from sqlalchemy.exc import IntegrityError

    from tracefence.domain.enums import CommandType, IssuerType
    from tracefence.domain.schemas import CommandCreate, Principal, SpawnCreate
    from tracefence.services.control_service import ControlService
    from tracefence.services.spawn_service import SpawnService
    from tests.helpers import activate, create_seeded_run

    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run_a = await create_seeded_run(session_factory, "replacement-constraint-a")
    run_b = await create_seeded_run(session_factory, "replacement-constraint-b")
    target = await activate(
        spawns,
        await spawns.create_spawn(
            run_a.root_node_id,
            run_a.root_token,
            SpawnCreate(role="target", capabilities=[]),
        ),
    )
    foreign_node = await activate(
        spawns,
        await spawns.create_spawn(
            run_b.root_node_id,
            run_b.root_token,
            SpawnCreate(role="foreign", capabilities=[]),
        ),
    )
    command = await controls.issue_command(
        CommandCreate(
            idempotency_key="cross-run-replacement-constraint",
            command_type=CommandType.CORRECT_SUBTREE,
            target_node_id=target.node_id,
            reason_code="TEST",
            reason_text="Test database constraint",
            replacement_instruction={"task": "replace"},
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    with session_factory() as session:
        with pytest.raises(IntegrityError):
            with session.begin():
                session.execute(
                    text(
                        "UPDATE control_commands SET replacement_node_id = :replacement "
                        "WHERE id = :command"
                    ),
                    {
                        "replacement": foreign_node.node_id,
                        "command": command.command_id,
                    },
                )


async def test_database_rejects_cross_run_ack_and_action_command_attribution(session_factory):
    from sqlalchemy.exc import IntegrityError

    from tracefence.domain.enums import CommandType, IssuerType
    from tracefence.domain.schemas import (
        ActionExecute,
        CommandCreate,
        Principal,
        SpawnCreate,
    )
    from tracefence.services.action_gateway import ActionGateway
    from tracefence.services.control_service import ControlService
    from tracefence.services.spawn_service import SpawnService
    from tests.helpers import activate, create_seeded_run

    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    gateway = ActionGateway(session_factory)
    run_a = await create_seeded_run(session_factory, "attribution-constraint-a")
    run_b = await create_seeded_run(session_factory, "attribution-constraint-b")
    node_a = await activate(
        spawns,
        await spawns.create_spawn(
            run_a.root_node_id,
            run_a.root_token,
            SpawnCreate(role="a", capabilities=["tool:read_metrics"]),
        ),
    )
    node_b = await activate(
        spawns,
        await spawns.create_spawn(
            run_b.root_node_id,
            run_b.root_token,
            SpawnCreate(role="b", capabilities=[]),
        ),
    )
    command_a = await controls.issue_command(
        CommandCreate(
            idempotency_key="ack-command-a",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=node_a.node_id,
            reason_code="TEST",
            reason_text="command in run A",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    command_b = await controls.issue_command(
        CommandCreate(
            idempotency_key="action-command-b",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=node_b.node_id,
            reason_code="TEST",
            reason_text="command in run B",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "INSERT INTO command_acknowledgements "
                    "(id, run_id, command_id, node_id, ack_type, observed_at, observed_scope_version) "
                    "VALUES ('bad-ack', :run, :command, :node, 'COOPERATIVE', CURRENT_TIMESTAMP, 2)"
                ),
                {
                    "run": run_a.run_id,
                    "command": command_a.command_id,
                    "node": node_b.node_id,
                },
            )

    # Create a valid action in a fresh active node in run A, then prove direct
    # cross-run command attribution is rejected by the composite foreign key.
    active_a = await activate(
        spawns,
        await spawns.create_spawn(
            run_a.root_node_id,
            run_a.root_token,
            SpawnCreate(role="active-a", capabilities=["tool:read_metrics"]),
        ),
    )
    action = await gateway.execute(
        active_a.node_id,
        active_a.node_token,
        ActionExecute(
            idempotency_key="valid-read", tool_name="read_metrics", arguments={}
        ),
    )
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE action_attempts SET matched_command_id = :command "
                    "WHERE id = :action"
                ),
                {"command": command_b.command_id, "action": action.action_id},
            )


def test_init_db_refuses_current_version_with_missing_constraints(tmp_path):
    # Create the real schema, then replace one table with a column-compatible copy
    # that lacks its named safety constraints. Column-only validation would miss it.
    engine = build_engine(f"sqlite+pysqlite:///{tmp_path / 'constraintless.db'}")
    init_db(engine)
    with engine.begin() as connection:
        connection.execute(text("PRAGMA foreign_keys=OFF"))
        connection.execute(text("ALTER TABLE runs RENAME TO runs_safe"))
        connection.execute(
            text(
                "CREATE TABLE runs ("
                "id VARCHAR(36) PRIMARY KEY, name VARCHAR(120), status VARCHAR(24), "
                "root_node_id VARCHAR(36) NOT NULL, run_scope_id VARCHAR(36) NOT NULL, "
                "created_at DATETIME, finished_at DATETIME)"
            )
        )
        connection.execute(text("DROP TABLE runs_safe"))
        connection.execute(text("PRAGMA foreign_keys=ON"))
    with pytest.raises(RuntimeError, match="constraints or indexes are missing"):
        init_db(engine)
    engine.dispose()


async def test_database_rejects_cross_run_root_scope_owner_and_correction_links(session_factory):
    from sqlalchemy.exc import IntegrityError

    from tracefence.db.models import Node
    from tracefence.domain.enums import CommandType, IssuerType
    from tracefence.domain.schemas import CommandCreate, Principal, SpawnCreate
    from tracefence.services.control_service import ControlService
    from tracefence.services.spawn_service import SpawnService
    from tests.helpers import activate, create_seeded_run

    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    run_a = await create_seeded_run(session_factory, "deep-constraint-a")
    run_b = await create_seeded_run(session_factory, "deep-constraint-b")
    node_a = await activate(
        spawns,
        await spawns.create_spawn(
            run_a.root_node_id, run_a.root_token, SpawnCreate(role="a", capabilities=[])
        ),
    )
    node_b = await activate(
        spawns,
        await spawns.create_spawn(
            run_b.root_node_id, run_b.root_token, SpawnCreate(role="b", capabilities=[])
        ),
    )
    command_b = await controls.issue_command(
        CommandCreate(
            idempotency_key="foreign-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=node_b.node_id,
            reason_code="TEST",
            reason_text="foreign command",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )

    with session_factory() as session:
        foreign_scope = session.get(Node, node_b.node_id).own_scope_id

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE runs SET root_node_id = :node WHERE id = :run"),
                {"node": node_b.node_id, "run": run_a.run_id},
            )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE runs SET run_scope_id = :scope WHERE id = :run"),
                {"scope": foreign_scope, "run": run_a.run_id},
            )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            own_scope = session.get(Node, node_a.node_id).own_scope_id
            session.execute(
                text("UPDATE control_scopes SET owner_node_id = :owner WHERE id = :scope"),
                {"owner": node_b.node_id, "scope": own_scope},
            )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE nodes SET caused_by_command_id = :command WHERE id = :node"),
                {"command": command_b.command_id, "node": node_a.node_id},
            )


async def test_database_enforces_action_decision_shape(session_factory):
    from sqlalchemy.exc import IntegrityError

    from tracefence.domain.schemas import ActionExecute
    from tracefence.services.action_gateway import ActionGateway
    from tests.helpers import create_seeded_run

    run = await create_seeded_run(session_factory, "action-shape")
    action = await ActionGateway(session_factory).execute(
        run.root_node_id,
        run.root_token,
        ActionExecute(idempotency_key="read", tool_name="read_metrics", arguments={}),
    )
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE action_attempts SET denial_reason = 'IMPOSSIBLE' WHERE id = :id"),
                {"id": action.action_id},
            )


async def test_database_binds_acknowledgements_to_exact_command_version(session_factory):
    from sqlalchemy.exc import IntegrityError

    from tracefence.domain.enums import CommandType, IssuerType
    from tracefence.domain.schemas import CommandCreate, Principal, SpawnCreate
    from tracefence.services.control_service import ControlService
    from tracefence.services.spawn_service import SpawnService
    from tests.helpers import activate, create_seeded_run

    run = await create_seeded_run(session_factory, "ack-exact-version")
    spawns = SpawnService(session_factory)
    node = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="target", capabilities=[]),
        ),
    )
    command = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key="ack-exact-command",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=node.node_id,
            reason_code="TEST",
            reason_text="bind acknowledgement version",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "INSERT INTO command_acknowledgements "
                    "(id, run_id, command_id, node_id, ack_type, observed_at, observed_scope_version) "
                    "VALUES ('forged-version', :run, :command, :node, 'COOPERATIVE', "
                    "CURRENT_TIMESTAMP, :version)"
                ),
                {
                    "run": run.run_id,
                    "command": command.command_id,
                    "node": node.node_id,
                    "version": command.to_version + 1,
                },
            )


async def test_database_binds_action_match_to_exact_command_scope(session_factory):
    from sqlalchemy.exc import IntegrityError

    from tracefence.domain.enums import CommandType, IssuerType
    from tracefence.domain.schemas import ActionExecute, CommandCreate, Principal, SpawnCreate
    from tracefence.services.action_gateway import ActionGateway
    from tracefence.services.control_service import ControlService
    from tracefence.services.spawn_service import SpawnService
    from tests.helpers import activate, create_seeded_run

    run = await create_seeded_run(session_factory, "action-exact-scope")
    spawns = SpawnService(session_factory)
    controls = ControlService(session_factory)
    first = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="first", capabilities=["tool:restart_postgres"]),
        ),
    )
    second = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="second", capabilities=[]),
        ),
    )
    command_a = await controls.issue_command(
        CommandCreate(
            idempotency_key="scope-command-a",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=first.node_id,
            reason_code="TEST",
            reason_text="first scope",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    command_b = await controls.issue_command(
        CommandCreate(
            idempotency_key="scope-command-b",
            command_type=CommandType.CANCEL_SUBTREE,
            target_node_id=second.node_id,
            reason_code="TEST",
            reason_text="second scope",
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    action = await ActionGateway(session_factory).execute(
        first.node_id,
        first.node_token,
        ActionExecute(
            idempotency_key="blocked-action",
            tool_name="restart_postgres",
            arguments={},
        ),
    )
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE action_command_matches SET scope_id = :scope, live_version = :version "
                    "WHERE action_id = :action AND command_id = :command"
                ),
                {
                    "scope": command_b.target_scope_id,
                    "version": command_b.to_version,
                    "action": action.action_id,
                    "command": command_a.command_id,
                },
            )


async def test_database_rejects_incomplete_allowed_actions_and_invalid_node_shapes(
    session_factory,
):
    from sqlalchemy.exc import IntegrityError

    from tracefence.domain.schemas import ActionExecute, SpawnCreate
    from tracefence.services.action_gateway import ActionGateway
    from tracefence.services.spawn_service import SpawnService
    from tests.helpers import activate, create_seeded_run

    run = await create_seeded_run(session_factory, "lifecycle-constraints")
    action = await ActionGateway(session_factory).execute(
        run.root_node_id,
        run.root_token,
        ActionExecute(idempotency_key="valid-action", tool_name="read_metrics", arguments={}),
    )
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE action_attempts SET committed_at = NULL, result_json = NULL, "
                    "result_digest = NULL WHERE id = :id"
                ),
                {"id": action.action_id},
            )

    child = await activate(
        SpawnService(session_factory),
        await SpawnService(session_factory).create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(role="child", capabilities=[]),
        ),
    )
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE nodes SET generation = 0 WHERE id = :id"),
                {"id": child.node_id},
            )
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE runs SET finished_at = CURRENT_TIMESTAMP WHERE id = :id"),
                {"id": run.run_id},
            )
