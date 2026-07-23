from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from tracefence.config import settings


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hmac.new(
        settings.token_hash_secret.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def token_matches(token: str, expected_hash: str | None) -> bool:
    if expected_hash is None:
        return False
    return hmac.compare_digest(hash_token(token), expected_hash)


def operator_fingerprint(operator_key: str) -> str:
    digest = hmac.new(
        settings.token_hash_secret.encode("utf-8"),
        operator_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:24]
    return f"human:{digest}"


def operator_key_matches(candidate: str | None) -> bool:
    if candidate is None or not settings.operator_key:
        return False
    return hmac.compare_digest(candidate, settings.operator_key)


def payload_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()
