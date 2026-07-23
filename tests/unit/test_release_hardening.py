from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.helpers import create_seeded_run
from tracefence.api.middleware import RateLimitMiddleware
from tracefence.domain.errors import NotFoundError
from tracefence.evidence import EvidenceIntegrityError, resolve_evidence_path, write_evidence_bundle
from tracefence.services.graph_service import GraphService
from tracefence.services.proposal_service import ProposalService


async def _asgi_request(
    app,
    *,
    path: str,
    headers: list[tuple[bytes, bytes]] | None = None,
    client_host: str = "127.0.0.1",
) -> list[dict]:
    sent: list[dict] = []
    messages = iter([{"type": "http.request", "body": b"", "more_body": False}])

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    await app(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": headers or [],
            "http_version": "1.1",
            "scheme": "http",
            "query_string": b"",
            "server": ("test", 80),
            "client": (client_host, 1234),
        },
        receive,
        send,
    )
    return sent


async def test_rate_limiter_is_principal_scoped_and_proof_specific(monkeypatch):
    calls = 0

    async def downstream(scope, receive, send):
        nonlocal calls
        calls += 1
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = RateLimitMiddleware(
        downstream,
        requests_per_minute=2,
        proof_requests_per_minute=1,
        max_buckets=100,
    )
    monkeypatch.setattr(
        "tracefence.api.middleware.operator_key_matches",
        lambda candidate: candidate == "a" * 32,
    )
    path = "/v1/commands/command-1/proof"
    operator_headers = [(b"x-operator-key", ("a" * 32).encode())]
    first = await _asgi_request(middleware, path=path, headers=operator_headers)
    second = await _asgi_request(middleware, path=path, headers=operator_headers)
    other_client = await _asgi_request(
        middleware,
        path=path,
        headers=[(b"x-operator-key", ("b" * 32).encode())],
        client_host="127.0.0.2",
    )

    assert first[0]["status"] == 204
    assert second[0]["status"] == 429
    assert dict(second[0]["headers"])[b"retry-after"]
    assert other_client[0]["status"] == 204
    assert calls == 2


async def test_rate_limiter_cannot_be_evaded_by_rotating_node_ids():
    calls = 0

    async def downstream(scope, receive, send):
        nonlocal calls
        calls += 1
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = RateLimitMiddleware(
        downstream,
        requests_per_minute=1,
        proof_requests_per_minute=1,
        max_buckets=100,
    )
    first = await _asgi_request(
        middleware,
        path="/v1/nodes/node-a/heartbeat",
        headers=[(b"x-node-id", b"node-a"), (b"x-node-token", b"fake-a")],
    )
    rotated = await _asgi_request(
        middleware,
        path="/v1/nodes/node-b/heartbeat",
        headers=[(b"x-node-id", b"node-b"), (b"x-node-token", b"fake-b")],
    )
    assert first[0]["status"] == 204
    assert rotated[0]["status"] == 429
    assert calls == 1


async def test_graph_exposes_authoritative_scope_and_behavior(session_factory):
    run = await create_seeded_run(session_factory, "graph-scope")
    graph = await GraphService(session_factory).get_graph(run.run_id)
    root = next(node for node in graph.nodes if node.id == run.root_node_id)
    assert root.behavior == "cooperative"
    assert root.own_scope_id
    assert root.own_scope_version == 1
    assert root.own_scope_status == "ACTIVE"
    assert root.inherited_scope_count == 2
    assert root.blocking_scope_id is None
    assert root.blocking_reason is None


async def test_proposal_listing_rejects_unknown_run(session_factory):
    with pytest.raises(NotFoundError):
        await ProposalService(session_factory).list_for_run("missing-run")


def _minimal_bundle() -> dict:
    return {
        "run": {"run_id": "run-1", "root_node_id": "root"},
        "command": {"command_id": "command-1"},
        "recovery": {},
        "sibling_check": {},
        "worker_output": "ok",
        "proof": {"command_id": "command-1"},
        "graph": {"run_id": "run-1"},
        "actions": [],
        "services": [],
    }


def test_evidence_manifest_requires_the_correct_hmac_key(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "tracefence.evidence._git_metadata",
        lambda _repo: {"commit": "a" * 40, "dirty": False},
    )
    pointer = write_evidence_bundle(
        tmp_path,
        _minimal_bundle(),
        repo_dir=tmp_path,
        signing_key="a" * 32,
    )
    resolved, manifest = resolve_evidence_path(pointer, signing_key="a" * 32)
    assert resolved.name == "bundle.json"
    assert manifest["manifest_version"] == 2
    assert manifest["signature"]["algorithm"] == "HMAC-SHA256"

    with pytest.raises(EvidenceIntegrityError, match="different key"):
        resolve_evidence_path(pointer, signing_key="b" * 32)


def test_unsigned_legacy_evidence_is_rejected(tmp_path: Path):
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps(_minimal_bundle()), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError, match="Unsigned legacy"):
        resolve_evidence_path(legacy, signing_key="a" * 32)


async def test_control_runtime_readiness_uses_an_actual_probe(monkeypatch):
    from datetime import UTC, datetime

    from tracefence.api.routes import health

    current = datetime.now(UTC).isoformat()

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                lease_scanner_last_success=current,
                lease_scanner_error=None,
                invariant_auditor_last_success=current,
                invariant_auditor_error=None,
                invariant_outbox_pending=0,
            )
        )
    )
    monkeypatch.setattr(health, "_database_ready", lambda: True)

    async def failed_probe():
        return False

    monkeypatch.setattr(health.control_plane_runtime, "probe", failed_probe)
    payload, ready = await health._readiness_payload(request)
    assert ready is False
    assert payload["control_runtime"] == "unavailable"


def test_evidence_manifest_rejects_schema_version_drift(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "tracefence.evidence._git_metadata",
        lambda _repo: {"commit": "a" * 40, "dirty": False},
    )
    pointer = write_evidence_bundle(
        tmp_path,
        _minimal_bundle(),
        repo_dir=tmp_path,
        signing_key="a" * 32,
    )
    pointer_value = json.loads(pointer.read_text(encoding="utf-8"))
    bundle_dir = tmp_path / pointer_value["bundle_dir"]
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] += 1
    # The manifest signature is now invalid as well, but schema drift should be
    # rejected before any artifact is trusted.
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    import hashlib

    from tracefence.evidence import _pointer_signature

    pointer_value["manifest_sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    pointer_value["signature"]["value"] = _pointer_signature(
        pointer_value, ("a" * 32).encode()
    )
    pointer.write_text(json.dumps(pointer_value), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError, match="schema version"):
        resolve_evidence_path(pointer, signing_key="a" * 32)


def test_worker_cli_rejects_invalid_timing_and_has_no_secret_argument(monkeypatch):
    import sys

    from tracefence.runtime import worker

    source = Path(worker.__file__).read_text(encoding="utf-8")
    assert "--activation-token" not in source

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "tracefence-worker",
            "--node-id",
            "node-1",
            "--mode",
            "cooperative",
            "--heartbeat-interval",
            "0",
        ],
    )
    with pytest.raises(SystemExit):
        worker.parse_args()


async def test_security_headers_are_applied_to_static_assets():
    from tracefence.api.middleware import SecurityHeadersMiddleware

    async def downstream(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/javascript")],
            }
        )
        await send({"type": "http.response.body", "body": b"const ok = true;"})

    sent = await _asgi_request(
        SecurityHeadersMiddleware(downstream),
        path="/assets/app.js",
    )
    headers = dict(sent[0]["headers"])
    assert b"content-security-policy" in headers
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert headers[b"referrer-policy"] == b"no-referrer"
    assert b"frame-ancestors 'none'" in headers[b"content-security-policy"]


async def test_readiness_requires_empty_outbox_when_otlp_is_configured(monkeypatch):
    from dataclasses import replace
    from datetime import UTC, datetime

    from tracefence.api.routes import health
    from tracefence.config import settings

    async def healthy_probe() -> bool:
        return True

    monkeypatch.setattr(health, "settings", replace(settings, otlp_endpoint="http://otel"))
    monkeypatch.setattr(health, "_database_ready", lambda: True)
    monkeypatch.setattr(health, "_database_readable", lambda: True)
    monkeypatch.setattr(health, "_database_writable", lambda: True)
    monkeypatch.setattr(health.control_plane_runtime, "probe", healthy_probe)
    monkeypatch.setattr(
        health,
        "telemetry_health",
        lambda: {
            "status": "READY",
            "configured": True,
            "errors": [],
            "last_successful_flush_at": datetime.now(UTC).isoformat(),
        },
    )
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                lease_scanner_last_success=datetime.now(UTC).isoformat(),
                lease_scanner_error=None,
                invariant_auditor_last_success=datetime.now(UTC).isoformat(),
                invariant_auditor_error=None,
                invariant_outbox_pending=1,
            )
        )
    )
    payload, ready = await health._readiness_payload(request)
    assert ready is False
    assert payload["invariant_auditor"]["outbox_pending"] == 1
    request.app.state.invariant_outbox_pending = 0
    _payload, ready = await health._readiness_payload(request)
    assert ready is True


def test_instrumentation_failure_sets_telemetry_failed_when_otlp_is_required(monkeypatch):
    from dataclasses import replace

    import tracefence.telemetry.setup as telemetry_setup
    from tracefence.config import settings

    monkeypatch.setattr(
        telemetry_setup, "settings", replace(settings, otlp_endpoint="http://otel")
    )
    monkeypatch.setattr(telemetry_setup, "_telemetry_state", "READY")
    monkeypatch.setattr(telemetry_setup, "_telemetry_errors", [])
    monkeypatch.setattr(telemetry_setup, "_instrumentation_errors", [])
    telemetry_setup._record_instrumentation_error("instrumentation unavailable")
    health = telemetry_setup.telemetry_health()
    assert health["status"] == "FAILED"
    assert "instrumentation unavailable" in health["errors"]


def test_evidence_generation_rejects_dirty_or_uncommitted_tree(tmp_path: Path, monkeypatch):
    from tracefence.evidence import validate_evidence_generation

    monkeypatch.setattr(
        "tracefence.evidence._git_metadata",
        lambda _repo: {"commit": "a" * 40, "dirty": True},
    )
    with pytest.raises(EvidenceIntegrityError, match="clean Git worktree"):
        validate_evidence_generation(tmp_path, signing_key="e" * 32)

    monkeypatch.setattr(
        "tracefence.evidence._git_metadata",
        lambda _repo: {"commit": None, "dirty": False},
    )
    with pytest.raises(EvidenceIntegrityError, match="committed HEAD"):
        validate_evidence_generation(tmp_path, signing_key="e" * 32)


def test_evidence_manifest_enforces_expected_commit_and_maximum_age(tmp_path: Path, monkeypatch):
    import hashlib
    import hmac
    from datetime import UTC, datetime, timedelta

    from tracefence.evidence import _pointer_signature, canonical_json_bytes

    commit = "a" * 40
    key = "e" * 32
    monkeypatch.setattr(
        "tracefence.evidence._git_metadata",
        lambda _repo: {"commit": commit, "dirty": False},
    )
    pointer = write_evidence_bundle(
        tmp_path,
        _minimal_bundle(),
        repo_dir=tmp_path,
        signing_key=key,
    )
    with pytest.raises(EvidenceIntegrityError, match="expected release commit"):
        resolve_evidence_path(
            pointer,
            signing_key=key,
            expected_commit="b" * 40,
        )

    pointer_value = json.loads(pointer.read_text(encoding="utf-8"))
    bundle_dir = tmp_path / pointer_value["bundle_dir"]
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["generated_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    unsigned = {name: value for name, value in manifest.items() if name != "signature"}
    manifest["signature"]["value"] = hmac.new(
        key.encode(), canonical_json_bytes(unsigned), hashlib.sha256
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    pointer_value["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    pointer_value["signature"]["value"] = _pointer_signature(
        pointer_value, key.encode()
    )
    pointer.write_text(json.dumps(pointer_value), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError, match="older than"):
        resolve_evidence_path(
            pointer,
            signing_key=key,
            max_age_seconds=60,
        )


async def test_readiness_rejects_stale_scanner_and_auditor_timestamps(monkeypatch):
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta

    from tracefence.api.routes import health
    from tracefence.config import settings

    async def healthy_probe() -> bool:
        return True

    stale = (datetime.now(UTC) - timedelta(seconds=30)).isoformat()
    monkeypatch.setattr(
        health,
        "settings",
        replace(settings, lease_scan_interval_seconds=2, otlp_endpoint=""),
    )
    monkeypatch.setattr(health, "_database_ready", lambda: True)
    monkeypatch.setattr(health.control_plane_runtime, "probe", healthy_probe)
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                lease_scanner_last_success=stale,
                lease_scanner_error=None,
                invariant_auditor_last_success=stale,
                invariant_auditor_error=None,
                invariant_outbox_pending=0,
            )
        )
    )
    payload, ready = await health._readiness_payload(request)
    assert ready is False
    assert payload["lease_scanner"]["fresh"] is False
    assert payload["invariant_auditor"]["fresh"] is False


def test_security_requires_independent_evidence_signing_key():
    from dataclasses import replace

    from tracefence.config import settings

    base = replace(
        settings,
        environment="development",
        operator_key="o" * 32,
        token_hash_secret="t" * 48,
        evidence_signing_key="",
    )
    with pytest.raises(RuntimeError, match="EVIDENCE_SIGNING_KEY is required"):
        base.validate_security()

    with pytest.raises(RuntimeError, match="independent from TRACEFENCE_OPERATOR_KEY"):
        replace(base, evidence_signing_key="o" * 32).validate_security()

    with pytest.raises(RuntimeError, match="independent from TRACEFENCE_TOKEN_HASH_SECRET"):
        replace(base, evidence_signing_key="t" * 48).validate_security()


def test_evidence_pointer_is_authenticated(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "tracefence.evidence._git_metadata",
        lambda _repo: {"commit": "a" * 40, "dirty": False},
    )
    pointer = write_evidence_bundle(
        tmp_path,
        _minimal_bundle(),
        repo_dir=tmp_path,
        signing_key="p" * 32,
    )
    value = json.loads(pointer.read_text(encoding="utf-8"))
    assert value["pointer_version"] == 2
    value["bundle_dir"] = "another-bundle"
    pointer.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError, match="pointer signature is invalid"):
        resolve_evidence_path(pointer, signing_key="p" * 32)


def test_evidence_verifier_resolves_replacement_from_final_graph_state():
    from scripts.verify_end_to_end import _resolve_command_replacement

    graph = {
        "commands": [
            {
                "id": "command-1",
                "replacement_node_id": "replacement-1",
                "target_node_id": "old-node",
            }
        ],
        "nodes": [
            {
                "id": "replacement-1",
                "caused_by_command_id": "command-1",
                "supersedes_node_id": "old-node",
            }
        ],
    }
    command, replacement = _resolve_command_replacement(graph, "command-1")
    assert command["replacement_node_id"] == replacement["id"]
