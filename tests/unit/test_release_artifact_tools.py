from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.lock_casting import lock_payload, write_lock
from scripts.secret_scan import scan_paths
from scripts.verify_end_to_end import VerificationError, _verify_telemetry_gate


def test_secret_scan_reports_only_location_and_type(tmp_path: Path) -> None:
    secret = "ghp_" + ("A" * 40)
    candidate = tmp_path / "candidate.txt"
    candidate.write_text(f"token={secret}\n", encoding="utf-8")

    findings = scan_paths(tmp_path, [candidate])

    assert findings == [{"file": "candidate.txt", "line": 1, "type": "github_token"}]
    assert secret not in json.dumps(findings)


def test_casting_lock_is_content_bound_and_atomic(tmp_path: Path) -> None:
    source = tmp_path / "casting.yaml"
    destination = tmp_path / "casting.yaml.lock"
    source.write_text("kind: Installation\n", encoding="utf-8")

    write_lock(source, destination)

    assert json.loads(destination.read_text(encoding="utf-8")) == lock_payload(source)
    assert not list(tmp_path.glob(".casting.yaml.lock.*"))


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
