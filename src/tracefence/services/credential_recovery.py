from __future__ import annotations

import base64
import hashlib
from datetime import timedelta

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracefence.config import settings
from tracefence.db.models import CredentialRecoveryEnvelope
from tracefence.domain.errors import ConflictError
from tracefence.services.common import utcnow


def recovery_request_digest(request: BaseModel, *, context: str = "") -> str:
    payload = request.model_dump(mode="json", exclude={"operation_key"})
    encoded = (
        request.__class__.__name__.encode()
        + b"\0"
        + context.encode()
        + b"\0"
        + _canonical_json(payload)
    )
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json(payload: object) -> bytes:
    import json

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def _key() -> bytes:
    return hashlib.sha256(settings.credential_recovery_key.encode()).digest()


def _aad(
    operation_type: str,
    caller_node_id: str,
    operation_key: str,
    request_digest: str,
    subject_node_id: str,
) -> bytes:
    return "\0".join(
        (
            operation_type,
            caller_node_id,
            operation_key,
            request_digest,
            subject_node_id,
        )
    ).encode()


def find_envelope(
    session: Session,
    *,
    operation_type: str,
    caller_node_id: str,
    operation_key: str,
    request_digest: str,
) -> CredentialRecoveryEnvelope | None:
    envelope = session.execute(
        select(CredentialRecoveryEnvelope).where(
            CredentialRecoveryEnvelope.operation_type == operation_type,
            CredentialRecoveryEnvelope.caller_node_id == caller_node_id,
            CredentialRecoveryEnvelope.operation_key == operation_key,
        )
    ).scalar_one_or_none()
    if (
        envelope is not None
        and envelope.request_payload_digest != request_digest
    ):
        raise ConflictError(
            "Operation key was already used with a different payload",
            code="OPERATION_KEY_PAYLOAD_MISMATCH",
        )
    return envelope


def open_envelope(
    envelope: CredentialRecoveryEnvelope,
    response_type: type[BaseModel],
) -> BaseModel:
    try:
        plaintext = AESGCM(_key()).decrypt(
            base64.urlsafe_b64decode(envelope.nonce),
            base64.urlsafe_b64decode(envelope.ciphertext),
            _aad(
                envelope.operation_type,
                envelope.caller_node_id,
                envelope.operation_key,
                envelope.request_payload_digest,
                envelope.subject_node_id,
            ),
        )
        return response_type.model_validate_json(plaintext)
    except (InvalidTag, ValueError) as exc:
        raise ConflictError(
            "Credential recovery envelope failed authentication",
            code="CREDENTIAL_RECOVERY_ENVELOPE_INVALID",
        ) from exc


def seal_envelope(
    session: Session,
    *,
    existing: CredentialRecoveryEnvelope | None,
    run_id: str,
    operation_type: str,
    caller_node_id: str,
    subject_node_id: str,
    operation_key: str,
    request_digest: str,
    response: BaseModel,
) -> CredentialRecoveryEnvelope:
    import secrets
    from uuid import uuid4

    now = utcnow()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_key()).encrypt(
        nonce,
        response.model_dump_json().encode(),
        _aad(
            operation_type,
            caller_node_id,
            operation_key,
            request_digest,
            subject_node_id,
        ),
    )
    envelope = existing or CredentialRecoveryEnvelope(
        id=str(uuid4()),
        run_id=run_id,
        operation_type=operation_type,
        caller_node_id=caller_node_id,
        subject_node_id=subject_node_id,
        operation_key=operation_key,
        request_payload_digest=request_digest,
        nonce="",
        ciphertext="",
        expires_at=now,
        created_at=now,
        updated_at=now,
    )
    envelope.subject_node_id = subject_node_id
    envelope.nonce = base64.urlsafe_b64encode(nonce).decode()
    envelope.ciphertext = base64.urlsafe_b64encode(ciphertext).decode()
    envelope.expires_at = now + timedelta(
        seconds=settings.credential_recovery_ttl_seconds
    )
    envelope.updated_at = now
    if existing is None:
        session.add(envelope)
    return envelope
