from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DatabaseError, IntegrityError

from tests.helpers import create_seeded_run
from tracefence.db.models import (
    SCHEMA_INTEGRITY_TRIGGER_DDL,
    WorkerInstance,
    utcnow,
)
from tracefence.domain.schemas import SpawnCreate
from tracefence.services.spawn_service import SpawnService


def _envelope_params(**overrides):
    params = {
        "id": str(uuid4()),
        "operation_type": "ACTIVATION",
        "caller_node_id": None,
        "subject_node_id": None,
        "operation_key": str(uuid4()),
        "request_payload_digest": "a" * 64,
        "nonce": "a" * 24,
        "ciphertext": "ciphertext",
        "expires_at": utcnow() + timedelta(minutes=5),
        "binding_version": 1,
        "binding_kind": "V1_NODE",
        "subject_worker_instance_id": None,
        "spawn_intent_id": None,
        "created_at": utcnow(),
        "updated_at": utcnow(),
    }
    params.update(overrides)
    return params


def _insert_envelope(session, run_id: str, **overrides) -> None:
    params = _envelope_params(**overrides)
    session.execute(
        text(
            "INSERT INTO credential_recovery_envelopes ("
            "id, run_id, operation_type, caller_node_id, subject_node_id, "
            "operation_key, request_payload_digest, nonce, ciphertext, expires_at, "
            "binding_version, binding_kind, subject_worker_instance_id, spawn_intent_id, created_at, updated_at"
            ") VALUES ("
            ":id, :run_id, :operation_type, :caller_node_id, :subject_node_id, "
            ":operation_key, :request_payload_digest, :nonce, :ciphertext, :expires_at, "
            ":binding_version, :binding_kind, :subject_worker_instance_id, :spawn_intent_id, :created_at, :updated_at"
            ")"
        ),
        {**params, "run_id": run_id},
    )


async def _v2_binding(session_factory):
    run = await create_seeded_run(session_factory, "v2-recovery-binding")
    spawns = SpawnService(session_factory)
    created = await spawns.create_spawn(
        run.root_node_id, run.root_token, SpawnCreate(role="v2-child", capabilities=[])
    )
    with session_factory() as session:
        intent_id = session.scalar(
            text("SELECT id FROM spawn_intents WHERE child_node_id = :node"),
            {"node": created.child_node_id},
        )
    assert intent_id is not None

    # Test setup only: v20 deliberately makes the protocol version immutable.
    # The v2 envelope guard itself requires a v2 run.
    with session_factory.begin() as session:
        session.execute(text("DROP TRIGGER trg_runs_execution_protocol_version_immutable"))
        session.execute(
            text("UPDATE runs SET execution_protocol_version = 2 WHERE id = :run"),
            {"run": run.run_id},
        )
        session.execute(
            text(SCHEMA_INTEGRITY_TRIGGER_DDL["trg_runs_execution_protocol_version_immutable"])
        )
        worker_id = str(uuid4())
        session.add(
            WorkerInstance(
                id=worker_id,
                node_id=created.child_node_id,
                incarnation=1,
                observed_state="PENDING",
                activation_intent_id=intent_id,
            )
        )
    return run, created.child_node_id, intent_id, worker_id


async def test_v21_legacy_defaults_and_v1_shape(session_factory):
    run = await create_seeded_run(session_factory, "legacy-v1-binding")
    with session_factory.begin() as session:
        _insert_envelope(
            session,
            run.run_id,
            caller_node_id=run.root_node_id,
            subject_node_id=run.root_node_id,
        )
        _insert_envelope(
            session,
            run.run_id,
            caller_node_id=run.root_node_id,
            subject_node_id=run.root_node_id,
        )
    with session_factory() as session:
        rows = session.execute(
            text(
                "SELECT binding_version, binding_kind, subject_worker_instance_id, "
                "spawn_intent_id FROM credential_recovery_envelopes"
            )
        ).all()
    assert rows == [(1, "V1_NODE", None, None), (1, "V1_NODE", None, None)]


@pytest.mark.parametrize("field", ["subject_worker_instance_id", "spawn_intent_id"])
async def test_v21_rejects_v1_binding_ids(session_factory, field):
    run, subject_node, intent_id, worker_id = await _v2_binding(session_factory)
    values = {field: worker_id if field == "subject_worker_instance_id" else intent_id}
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            _insert_envelope(
                session,
                run.run_id,
                caller_node_id=run.root_node_id,
                subject_node_id=subject_node,
                **values,
            )


@pytest.mark.parametrize(
    "overrides",
    [
        {"subject_worker_instance_id": None},
        {"spawn_intent_id": None},
        {"operation_type": "SPAWN"},
    ],
)
async def test_v21_rejects_incomplete_or_non_activation_v2_binding(
    session_factory, overrides
):
    run, subject_node, intent_id, worker_id = await _v2_binding(session_factory)
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            _insert_envelope(
                session,
                run.run_id,
                caller_node_id=run.root_node_id,
                subject_node_id=subject_node,
                binding_version=2,
                binding_kind="V2_CHILD_ACTIVATION",
                **{
                    "subject_worker_instance_id": worker_id,
                    "spawn_intent_id": intent_id,
                    **overrides,
                },
            )


async def test_v21_v2_causality_uniqueness_and_immutability(session_factory):
    run, subject_node, intent_id, worker_id = await _v2_binding(session_factory)
    envelope_id = str(uuid4())
    with session_factory.begin() as session:
        _insert_envelope(
            session,
            run.run_id,
            id=envelope_id,
            caller_node_id=run.root_node_id,
            subject_node_id=subject_node,
            binding_version=2,
            binding_kind="V2_CHILD_ACTIVATION",
            subject_worker_instance_id=worker_id,
            spawn_intent_id=intent_id,
        )

    for column, value in (
        ("binding_version", 1),
        ("binding_kind", "V1_NODE"),
        ("subject_worker_instance_id", str(uuid4())),
        ("spawn_intent_id", str(uuid4())),
    ):
        with pytest.raises(DatabaseError, match="CREDENTIAL_RECOVERY_BINDING_IMMUTABLE"):
            with session_factory.begin() as session:
                session.execute(
                    text(f"UPDATE credential_recovery_envelopes SET {column} = :value WHERE id = :id"),
                    {"value": value, "id": envelope_id},
                )

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            _insert_envelope(
                session, run.run_id, caller_node_id=run.root_node_id,
                subject_node_id=subject_node, binding_version=2,
                binding_kind="V2_CHILD_ACTIVATION",
                subject_worker_instance_id=worker_id, spawn_intent_id=intent_id,
            )

    with pytest.raises(DatabaseError, match="WORKER_INSTANCE_DELETE_PROHIBITED"):
        with session_factory.begin() as session:
            session.execute(text("DELETE FROM worker_instances WHERE id = :id"), {"id": worker_id})
    with pytest.raises(DatabaseError, match="SPAWN_INTENT_V2_RECOVERY_BINDING_DELETE_PROHIBITED"):
        with session_factory.begin() as session:
            session.execute(text("DELETE FROM spawn_intents WHERE id = :id"), {"id": intent_id})
    with pytest.raises(DatabaseError, match="SPAWN_INTENT_V2_RECOVERY_BINDING_CAUSALITY_IMMUTABLE"):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE spawn_intents SET child_node_id = :node WHERE id = :id"),
                {"node": run.root_node_id, "id": intent_id},
            )

    # Reseal material remains deliberately mutable.
    with session_factory.begin() as session:
        session.execute(
            text(
                "UPDATE credential_recovery_envelopes "
                "SET nonce = 'b', ciphertext = 'resealed', expires_at = :expires WHERE id = :id"
            ),
            {"expires": utcnow() + timedelta(minutes=10), "id": envelope_id},
        )


async def test_v21_rejects_cross_node_worker_and_spawn_intent(session_factory):
    run, subject_node, intent_id, _ = await _v2_binding(session_factory)
    spawns = SpawnService(session_factory)
    other = await spawns.create_spawn(
        run.root_node_id, run.root_token, SpawnCreate(role="other-child", capabilities=[])
    )
    with session_factory() as session:
        other_intent = session.scalar(
            text("SELECT id FROM spawn_intents WHERE child_node_id = :node"),
            {"node": other.child_node_id},
        )
    assert other_intent is not None
    foreign_worker = str(uuid4())
    with session_factory.begin() as session:
        session.add(
            WorkerInstance(
                id=foreign_worker,
                node_id=other.child_node_id,
                incarnation=1,
                observed_state="PENDING",
                activation_intent_id=other_intent,
            )
        )
    for worker, intent in ((foreign_worker, intent_id), (foreign_worker, other_intent)):
        with pytest.raises(IntegrityError, match="V2_CHILD_ACTIVATION_BINDING_CAUSAL_MISMATCH"):
            with session_factory.begin() as session:
                _insert_envelope(
                    session, run.run_id, caller_node_id=run.root_node_id,
                    subject_node_id=subject_node, binding_version=2,
                    binding_kind="V2_CHILD_ACTIVATION",
                    subject_worker_instance_id=worker, spawn_intent_id=intent,
                )


def test_v20_to_v21_preserves_legacy_envelope_ciphertext(tmp_path):
    from alembic import command

    from tests.unit.test_worker_instance_model import _alembic_config

    path = tmp_path / "v20-to-v21.db"
    config = _alembic_config(path)
    command.upgrade(config, "004_schema_v20_execution_protocol_activation")
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    with engine.begin() as connection:
        connection.execute(text("PRAGMA foreign_keys=OFF"))
        connection.execute(
            text(
                "CREATE TABLE credential_recovery_envelopes_v20 ("
                "id VARCHAR(36) PRIMARY KEY, run_id VARCHAR(36) NOT NULL, "
                "operation_type VARCHAR(24) NOT NULL, caller_node_id VARCHAR(36) NOT NULL, "
                "subject_node_id VARCHAR(36) NOT NULL, operation_key VARCHAR(160) NOT NULL, "
                "request_payload_digest VARCHAR(64) NOT NULL, nonce VARCHAR(24) NOT NULL, "
                "ciphertext TEXT NOT NULL, expires_at DATETIME NOT NULL, "
                "created_at DATETIME, updated_at DATETIME, "
                "UNIQUE(operation_type, caller_node_id, operation_key), "
                "CHECK (operation_type IN ('SPAWN','REPLACEMENT','ACTIVATION'))"
                ")"
            )
        )
        connection.execute(text("DROP TABLE credential_recovery_envelopes"))
        connection.execute(
            text(
                "ALTER TABLE credential_recovery_envelopes_v20 "
                "RENAME TO credential_recovery_envelopes"
            )
        )
        connection.execute(
            text(
                "INSERT INTO credential_recovery_envelopes ("
                "id, run_id, operation_type, caller_node_id, subject_node_id, "
                "operation_key, request_payload_digest, nonce, ciphertext, expires_at"
                ") VALUES ('legacy-envelope', 'run', 'SPAWN', 'caller', 'subject', "
                "'key', :digest, 'nonce', 'unchanged-ciphertext', CURRENT_TIMESTAMP)"
            ),
            {"digest": "d" * 64},
        )
        connection.execute(text("PRAGMA foreign_keys=ON"))
    engine.dispose()
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    with engine.connect() as connection:
        assert connection.execute(
            text(
                "SELECT binding_version, binding_kind, subject_worker_instance_id, "
                "spawn_intent_id, ciphertext FROM credential_recovery_envelopes "
                "WHERE id = 'legacy-envelope'"
            )
        ).one() == (1, "V1_NODE", None, None, "unchanged-ciphertext")
    engine.dispose()
