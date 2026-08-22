from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.lock_casting import lock_payload, write_lock
from scripts.secret_scan import scan_paths
from scripts.verify_end_to_end import VerificationError, _verify_telemetry_gate
from scripts.verify_foundry_receipt import (
    FoundryReceiptError,
    receipt_identity,
    validate_replaced_receipt,
)


def test_secret_scan_reports_only_location_and_type(tmp_path: Path) -> None:
    secret = "ghp_" + ("A" * 40)
    candidate = tmp_path / "candidate.txt"
    candidate.write_text(f"token={secret}\n", encoding="utf-8")

    findings = scan_paths(tmp_path, [candidate])

    assert findings == [{"file": "candidate.txt", "line": 1, "type": "github_token"}]
    assert secret not in json.dumps(findings)


def test_casting_lock_is_content_bound_and_atomic(tmp_path: Path) -> None:
    source = tmp_path / "casting.yaml"
    destination = tmp_path / "casting.source.lock.json"
    source.write_text("kind: Installation\n", encoding="utf-8")

    write_lock(source, destination)

    assert json.loads(destination.read_text(encoding="utf-8")) == lock_payload(source)
    assert not list(tmp_path.glob(".casting.source.lock.json.*"))


def test_source_lock_cannot_satisfy_foundry_deployment_receipt_check(
    tmp_path: Path,
) -> None:
    source = tmp_path / "casting.yaml"
    source_lock = tmp_path / "casting.source.lock.json"
    deployment_receipt = tmp_path / "casting.yaml.lock"
    source.write_text("kind: Installation\n", encoding="utf-8")
    write_lock(source, source_lock)

    before = receipt_identity(deployment_receipt)

    with pytest.raises(FoundryReceiptError, match="did not create"):
        validate_replaced_receipt(
            deployment_receipt,
            before=before,
            source_lock=source_lock,
        )


def test_foundry_receipt_must_be_replaced_and_match_resolved_yaml(
    tmp_path: Path,
) -> None:
    source_lock = tmp_path / "casting.source.lock.json"
    source_lock.write_text('{"lock_version": 1}\n', encoding="utf-8")
    receipt = tmp_path / "casting.yaml.lock"
    receipt.write_text(
        "apiVersion: v1alpha1\n"
        "kind: Installation\n"
        "metadata:\n"
        "  name: tracefence\n"
        "spec:\n"
        "  deployment:\n"
        "    flavor: compose\n"
        "    mode: docker\n",
        encoding="utf-8",
    )
    before = receipt_identity(receipt)

    with pytest.raises(FoundryReceiptError, match="did not replace"):
        validate_replaced_receipt(
            receipt,
            before=before,
            source_lock=source_lock,
        )

    receipt.write_text(
        receipt.read_text(encoding="utf-8") + "  mcp:\n    spec:\n      enabled: true\n",
        encoding="utf-8",
    )
    assert validate_replaced_receipt(
        receipt,
        before=before,
        source_lock=source_lock,
    ).exists


def test_release_verifier_accepts_canonical_unavailable_telemetry_lattice() -> None:
    proof = {
        "runtime_verdict": "VERIFIED",
        "telemetry_verdict": "UNAVAILABLE",
        "overall_verdict": "UNAVAILABLE",
        "trace_ids": [],
    }

    _verify_telemetry_gate(proof, require_telemetry=False)

    proof["overall_verdict"] = "PARTIAL"
    with pytest.raises(VerificationError):
        _verify_telemetry_gate(proof, require_telemetry=False)


def test_public_verdict_documentation_matches_canonical_lattice() -> None:
    root = Path(__file__).resolve().parents[2]
    documents = [
        root / "README.md",
        root / "ARCHITECTURE.md",
        root / "HARDENING_REPORT.md",
        root / "FINAL_REMEDIATION_REPORT.md",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in documents)

    assert "overall proof                    PARTIAL until telemetry verifies" not in combined
    assert "overall proof                           PARTIAL" not in combined
    assert "`PARTIAL`: runtime verifies but telemetry is unavailable" not in combined
    assert "runtime `VERIFIED` + telemetry `UNAVAILABLE` = overall `UNAVAILABLE`" in combined


def test_cyclonedx_cli_is_declared_and_hash_locked_for_release_artifacts() -> None:
    root = Path(__file__).resolve().parents[2]
    build_input = (root / "requirements-build.in").read_text(encoding="utf-8")
    build_lock = (root / "requirements-lock" / "build.txt").read_text(
        encoding="utf-8"
    )

    assert "cyclonedx-bom==7.3.1" in build_input
    assert "cyclonedx-bom==7.3.1" in build_lock
