from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

import tracefence.services.spawn_service as spawn_module
from tests.helpers import activate, create_seeded_run
from tracefence.config import settings
from tracefence.db.models import (
    ControlCommand,
    CredentialRecoveryEnvelope,
    Node,
    SpawnIntent,
)
from tracefence.domain.enums import CommandType, IssuerType, NodeStatus
from tracefence.domain.errors import AuthenticationError, ConflictError
from tracefence.domain.schemas import CommandCreate, NodeActivate, Principal, SpawnCreate
from tracefence.services.common import utcnow
from tracefence.services.control_service import ControlService
from tracefence.services.lease_service import LeaseService
from tracefence.services.spawn_service import SpawnService


def _spawn_request(operation_key: str, *, role: str = "worker") -> SpawnCreate:
    return SpawnCreate(
        operation_key=operation_key,
        role=role,
        instruction={"task": "inspect"},
        capabilities=["tool:read_metrics"],
    )


async def _correction(session_factory, key: str):
    run = await create_seeded_run(session_factory, key)
    spawns = SpawnService(session_factory)
    target = await activate(
        spawns,
        await spawns.create_spawn(
            run.root_node_id,
            run.root_token,
            SpawnCreate(
                operation_key=f"{key}-target",
                role="worker",
                instruction={"task": "old"},
                capabilities=["tool:reset_redis_pool"],
            ),
        ),
    )
    command = await ControlService(session_factory).issue_command(
        CommandCreate(
            idempotency_key=f"{key}-command",
            target_node_id=target.node_id,
            command_type=CommandType.CORRECT_SUBTREE,
            reason_code="RECOVER",
            reason_text="replace",
            replacement_role="redis_recovery",
            replacement_instruction={"task": "reset"},
            replacement_expected_tool="reset_redis_pool",
            replacement_capabilities=["tool:reset_redis_pool"],
        ),
        Principal(issuer_type=IssuerType.HUMAN),
    )
    return run, command


@pytest.mark.asyncio
async def test_lost_spawn_response_is_recovered_without_duplicate_node(session_factory):
    run = await create_seeded_run(session_factory, "lost-spawn")
    service = SpawnService(session_factory)
    request = _spawn_request("lost-spawn-operation")

    first = await service.create_spawn(run.root_node_id, run.root_token, request)
    with session_factory() as session, session.begin():
        root = session.get(Node, run.root_node_id)
        assert root is not None
        root.status = NodeStatus.LEASE_EXPIRED
    retried = await service.create_spawn(run.root_node_id, run.root_token, request)

    assert retried == first
    with session_factory() as session:
        assert session.scalar(select(func.count(Node.id)).where(Node.run_id == run.run_id)) == 2


@pytest.mark.asyncio
async def test_failure_before_commit_leaves_no_node_or_recovery_envelope(
    session_factory,
    monkeypatch,
):
    run = await create_seeded_run(session_factory, "recovery-before-commit")
    service = SpawnService(session_factory)

    def fail_seal(*_args, **_kwargs):
        raise RuntimeError("simulated crash before commit")

    monkeypatch.setattr(spawn_module, "seal_envelope", fail_seal)
    with pytest.raises(RuntimeError, match="simulated crash"):
        await service.create_spawn(
            run.root_node_id,
            run.root_token,
            _spawn_request("before-commit-operation"),
        )

    with session_factory() as session:
        assert session.scalar(select(func.count(Node.id)).where(Node.run_id == run.run_id)) == 1
        assert session.scalar(select(func.count(CredentialRecoveryEnvelope.id))) == 0


@pytest.mark.asyncio
async def test_lost_replacement_response_is_recovered_without_duplicate_node(
    session_factory,
):
    run, command = await _correction(session_factory, "lost-replacement")
    service = SpawnService(session_factory)
    request = SpawnCreate(
        operation_key="lost-replacement-operation",
        role="redis_recovery",
        behavior="cooperative",
        instruction={"task": "reset"},
        capabilities=["tool:reset_redis_pool"],
    )

    first = await service.create_replacement(
        run.root_node_id,
        run.root_token,
        command.command_id,
        request,
    )
    retried = await service.create_replacement(
        run.root_node_id,
        run.root_token,
        command.command_id,
        request,
    )

    assert retried == first
    with session_factory() as session:
        stored = session.get(ControlCommand, command.command_id)
        assert stored is not None
        assert stored.replacement_node_id == first.child_node_id


@pytest.mark.asyncio
async def test_expired_replacement_requires_new_policy_controlled_operation(
    session_factory,
):
    run, command = await _correction(session_factory, "expired-replacement-recovery")
    service = SpawnService(session_factory)

    def request(operation_key: str) -> SpawnCreate:
        return SpawnCreate(
            operation_key=operation_key,
            role="redis_recovery",
            behavior="cooperative",
            instruction={"task": "reset"},
            capabilities=["tool:reset_redis_pool"],
        )

    first = await service.create_replacement(
        run.root_node_id,
        run.root_token,
        command.command_id,
        request("expired-replacement-first"),
    )
    with session_factory() as session, session.begin():
        intent = session.execute(
            select(SpawnIntent).where(SpawnIntent.child_node_id == first.child_node_id)
        ).scalar_one()
        intent.expires_at = utcnow() - timedelta(seconds=1)
    assert await LeaseService(session_factory).expire_stale_nodes(run.run_id) == 1

    with pytest.raises(ConflictError) as exact_retry:
        await service.create_replacement(
            run.root_node_id,
            run.root_token,
            command.command_id,
            request("expired-replacement-first"),
        )
    assert exact_retry.value.code == "CREDENTIAL_RECOVERY_EXPIRED"

    recovered = await service.create_replacement(
        run.root_node_id,
        run.root_token,
        command.command_id,
        request("expired-replacement-second"),
    )
    assert recovered.child_node_id != first.child_node_id
    with session_factory() as session:
        stored = session.get(ControlCommand, command.command_id)
        assert stored is not None
        assert stored.replacement_node_id == recovered.child_node_id
        assert stored.replacement_status == "PENDING"


@pytest.mark.asyncio
async def test_lost_activation_response_recovers_same_node_credential(session_factory):
    run = await create_seeded_run(session_factory, "lost-activation")
    service = SpawnService(session_factory)
    created = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        _spawn_request("lost-activation-spawn"),
    )
    request = NodeActivate(
        operation_key="lost-activation-operation",
        activation_token=created.activation_token,
        process_id=4312,
    )

    first = await service.activate(created.child_node_id, request)
    retried = await service.activate(created.child_node_id, request)

    assert retried == first
    after_response = await service.activate(created.child_node_id, request)
    assert after_response == first


@pytest.mark.asyncio
async def test_operation_key_payload_mismatch_conflicts(session_factory):
    run = await create_seeded_run(session_factory, "recovery-payload-mismatch")
    service = SpawnService(session_factory)
    await service.create_spawn(
        run.root_node_id,
        run.root_token,
        _spawn_request("shared-operation", role="worker-a"),
    )

    with pytest.raises(ConflictError) as captured:
        await service.create_spawn(
            run.root_node_id,
            run.root_token,
            _spawn_request("shared-operation", role="worker-b"),
        )

    assert captured.value.code == "OPERATION_KEY_PAYLOAD_MISMATCH"


@pytest.mark.asyncio
async def test_expired_recovery_envelope_rotates_pending_activation_credential(
    session_factory,
):
    run = await create_seeded_run(session_factory, "expired-recovery-envelope")
    service = SpawnService(session_factory)
    request = _spawn_request("expiring-envelope")
    first = await service.create_spawn(run.root_node_id, run.root_token, request)

    with session_factory() as session, session.begin():
        envelope = session.execute(
            select(CredentialRecoveryEnvelope).where(
                CredentialRecoveryEnvelope.operation_key == "expiring-envelope"
            )
        ).scalar_one()
        envelope.expires_at = utcnow() - timedelta(seconds=1)

    retried = await service.create_spawn(run.root_node_id, run.root_token, request)

    assert retried.child_node_id == first.child_node_id
    assert retried.activation_token != first.activation_token
    with pytest.raises(ConflictError) as old_token:
        await service.activate(
            first.child_node_id,
            NodeActivate(
                operation_key="old-token-attempt",
                activation_token=first.activation_token,
            ),
        )
    assert old_token.value.code == "INVALID_ACTIVATION_TOKEN"
    activated = await service.activate(
        retried.child_node_id,
        NodeActivate(
            operation_key="rotated-token-attempt",
            activation_token=retried.activation_token,
        ),
    )
    assert activated.node_id == first.child_node_id


@pytest.mark.asyncio
async def test_expired_activation_envelope_rotates_node_credential(session_factory):
    run = await create_seeded_run(session_factory, "expired-activation-envelope")
    service = SpawnService(session_factory)
    created = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        _spawn_request("expired-activation-spawn"),
    )
    request = NodeActivate(
        operation_key="expired-activation-operation",
        activation_token=created.activation_token,
    )
    first = await service.activate(created.child_node_id, request)
    with session_factory() as session, session.begin():
        envelope = session.execute(
            select(CredentialRecoveryEnvelope).where(
                CredentialRecoveryEnvelope.operation_key
                == "expired-activation-operation"
            )
        ).scalar_one()
        envelope.expires_at = utcnow() - timedelta(seconds=1)

    rotated = await service.activate(created.child_node_id, request)

    assert rotated.node_id == first.node_id
    assert rotated.node_token != first.node_token
    with pytest.raises(AuthenticationError):
        await service.heartbeat(first.node_id, first.node_token)
    assert (await service.heartbeat(rotated.node_id, rotated.node_token)).id == first.node_id


@pytest.mark.asyncio
async def test_credentials_are_absent_from_logs_and_database_plaintext(
    session_factory,
    caplog,
):
    run = await create_seeded_run(session_factory, "credential-nonexposure")
    service = SpawnService(session_factory)
    created = await service.create_spawn(
        run.root_node_id,
        run.root_token,
        _spawn_request("nonexposure-spawn"),
    )
    activated = await service.activate(
        created.child_node_id,
        NodeActivate(
            operation_key="nonexposure-activate",
            activation_token=created.activation_token,
        ),
    )

    with session_factory() as session:
        envelopes = session.execute(select(CredentialRecoveryEnvelope)).scalars().all()
        stored_text = repr(
            [
                (
                    envelope.operation_type,
                    envelope.request_payload_digest,
                    envelope.nonce,
                    envelope.ciphertext,
                )
                for envelope in envelopes
            ]
        )
        database_path = Path(str(session.get_bind().url.database))
    logs = caplog.text
    for credential in (
        run.root_token,
        created.activation_token,
        activated.node_token,
    ):
        assert credential not in stored_text
        assert credential not in logs
        encoded = credential.encode()
        for path in (
            database_path,
            database_path.with_name(f"{database_path.name}-wal"),
        ):
            if path.exists():
                assert encoded not in path.read_bytes()


@pytest.mark.asyncio
async def test_recovery_envelope_authentication_failure_is_fail_closed(session_factory):
    run = await create_seeded_run(session_factory, "tampered-recovery-envelope")
    service = SpawnService(session_factory)
    request = _spawn_request("tampered-envelope-operation")
    await service.create_spawn(run.root_node_id, run.root_token, request)
    with session_factory() as session, session.begin():
        envelope = session.execute(
            select(CredentialRecoveryEnvelope).where(
                CredentialRecoveryEnvelope.operation_key
                == "tampered-envelope-operation"
            )
        ).scalar_one()
        replacement = "A" if envelope.ciphertext[-1] != "A" else "B"
        envelope.ciphertext = f"{envelope.ciphertext[:-1]}{replacement}"

    with pytest.raises(ConflictError) as captured:
        await service.create_spawn(run.root_node_id, run.root_token, request)

    assert captured.value.code == "CREDENTIAL_RECOVERY_ENVELOPE_INVALID"


def test_recovery_encryption_key_must_be_independent_and_ttl_is_bounded():
    secure = replace(
        settings,
        environment="development",
        operator_key="o" * 32,
        token_hash_secret="t" * 48,
        credential_recovery_key="r" * 48,
        evidence_signing_key="e" * 48,
    )
    secure.validate_security()

    with pytest.raises(RuntimeError, match="must be independent"):
        replace(
            secure,
            credential_recovery_key=secure.token_hash_secret,
        ).validate_security()
    with pytest.raises(RuntimeError, match="must be between 5 and 300"):
        replace(secure, credential_recovery_ttl_seconds=301).validate_security()
