from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from tracefence.config import settings
from tracefence.db.engine import SCHEMA_VERSION


class EvidenceIntegrityError(RuntimeError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_metadata(repo_dir: Path) -> dict[str, Any]:
    git = shutil.which("git")

    def run(*args: str) -> str | None:
        if git is None:
            return None
        try:
            completed = subprocess.run(  # nosec B603 - executable resolved via shutil.which; args are internal constants
                [git, *args],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return completed.stdout.strip()

    commit = run("rev-parse", "HEAD")
    status = run("status", "--porcelain")
    return {
        "commit": commit,
        "dirty": bool(status) if status is not None else None,
    }


def _application_version() -> str:
    try:
        return version("tracefence")
    except PackageNotFoundError:
        return "source-tree"


def _evidence_key(explicit: str | None = None) -> bytes:
    value = explicit or settings.evidence_signing_key
    if not value or len(value) < 32:
        raise EvidenceIntegrityError(
            "Evidence signing requires an independent TRACEFENCE_EVIDENCE_SIGNING_KEY "
            "of at least 32 characters"
        )
    return value.encode("utf-8")


def validate_evidence_generation(
    repo_dir: Path,
    *,
    signing_key: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Fail before executing a scenario when evidence cannot be release-grade."""

    key = _evidence_key(signing_key)
    git_metadata = _git_metadata(repo_dir)
    if not isinstance(git_metadata.get("commit"), str) or not git_metadata["commit"]:
        raise EvidenceIntegrityError(
            "Evidence generation requires a Git repository with a committed HEAD"
        )
    if git_metadata.get("dirty") is not False:
        raise EvidenceIntegrityError(
            "Evidence generation requires a clean Git worktree; commit or discard changes first"
        )
    return git_metadata, key


def _manifest_signature(manifest: dict[str, Any], key: bytes) -> str:
    unsigned = {name: value for name, value in manifest.items() if name != "signature"}
    return hmac.new(key, canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()


def _pointer_signature(pointer: dict[str, Any], key: bytes) -> str:
    unsigned = {name: value for name, value in pointer.items() if name != "signature"}
    return hmac.new(key, canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()


def write_evidence_bundle(
    output_dir: Path,
    bundle: dict[str, Any],
    *,
    repo_dir: Path | None = None,
    signing_key: str | None = None,
) -> Path:
    git_metadata, key = validate_evidence_generation(
        repo_dir or Path.cwd(),
        signing_key=signing_key,
    )

    generated_at = datetime.now(UTC)
    directory_name = generated_at.strftime("%Y-%m-%dT%H%M%S.%fZ")
    bundle_dir = output_dir / directory_name
    suffix = 0
    while bundle_dir.exists():
        suffix += 1
        bundle_dir = output_dir / f"{directory_name}-{suffix}"
    bundle_dir.mkdir(parents=True, exist_ok=False)

    artifacts: dict[str, Any] = {
        "run.json": bundle["run"],
        "command.json": bundle["command"],
        "recovery.json": bundle["recovery"],
        "sibling-check.json": bundle["sibling_check"],
        "proof.json": bundle["proof"],
        "graph.json": bundle["graph"],
        "actions.json": bundle["actions"],
        "services.json": bundle["services"],
        "violations.json": bundle.get("violations", []),
        "bundle.json": bundle,
    }
    for filename, value in artifacts.items():
        (bundle_dir / filename).write_bytes(canonical_json_bytes(value) + b"\n")
    (bundle_dir / "worker-output.txt").write_text(
        str(bundle.get("worker_output", "")), encoding="utf-8"
    )

    files = sorted(path.name for path in bundle_dir.iterdir() if path.is_file())
    manifest = {
        "manifest_version": 2,
        "generated_at": generated_at.isoformat(),
        "application_version": _application_version(),
        "schema_version": SCHEMA_VERSION,
        "run_id": bundle["run"]["run_id"],
        "command_id": bundle["command"]["command_id"],
        "git": git_metadata,
        "files": {name: sha256_file(bundle_dir / name) for name in files},
    }
    manifest["signature"] = {
        "algorithm": "HMAC-SHA256",
        "key_id": sha256_bytes(key)[:16],
        "value": _manifest_signature(manifest, key),
    }
    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")

    pointer = {
        "pointer_version": 2,
        "bundle_dir": bundle_dir.name,
        "manifest_sha256": sha256_file(manifest_path),
        "bundle_sha256": manifest["files"]["bundle.json"],
    }
    pointer["signature"] = {
        "algorithm": "HMAC-SHA256",
        "key_id": sha256_bytes(key)[:16],
        "value": _pointer_signature(pointer, key),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    latest_path = output_dir / "latest.json"
    latest_path.write_bytes(canonical_json_bytes(pointer) + b"\n")
    return latest_path


def resolve_evidence_path(
    path: Path,
    *,
    allow_legacy: bool = False,
    signing_key: str | None = None,
    expected_commit: str | None = None,
    max_age_seconds: int | None = None,
) -> tuple[Path, dict[str, Any] | None]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and value.get("pointer_version") == 2:
        key = _evidence_key(signing_key)
        pointer_signature = value.get("signature")
        if (
            not isinstance(pointer_signature, dict)
            or pointer_signature.get("algorithm") != "HMAC-SHA256"
        ):
            raise EvidenceIntegrityError("Evidence pointer signature is missing or unsupported")
        if pointer_signature.get("key_id") != sha256_bytes(key)[:16]:
            raise EvidenceIntegrityError("Evidence pointer was signed by a different key")
        supplied_pointer_signature = pointer_signature.get("value")
        expected_pointer_signature = _pointer_signature(value, key)
        if not isinstance(supplied_pointer_signature, str) or not hmac.compare_digest(
            supplied_pointer_signature,
            expected_pointer_signature,
        ):
            raise EvidenceIntegrityError("Evidence pointer signature is invalid")
        bundle_dir_name = value.get("bundle_dir")
        if not isinstance(bundle_dir_name, str) or not bundle_dir_name:
            raise EvidenceIntegrityError("Evidence pointer has no bundle directory")
        bundle_dir = (path.parent / bundle_dir_name).resolve()
        root = path.parent.resolve()
        if root not in bundle_dir.parents:
            raise EvidenceIntegrityError("Evidence pointer escapes its root directory")
        manifest_path = bundle_dir / "manifest.json"
        if not manifest_path.is_file():
            raise EvidenceIntegrityError("Evidence manifest is missing")
        if sha256_file(manifest_path) != value.get("manifest_sha256"):
            raise EvidenceIntegrityError("Evidence manifest digest does not match pointer")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        verify_manifest(
            bundle_dir,
            manifest,
            signing_key=signing_key,
            expected_commit=expected_commit,
            max_age_seconds=max_age_seconds,
        )
        bundle_path = bundle_dir / "bundle.json"
        if sha256_file(bundle_path) != value.get("bundle_sha256"):
            raise EvidenceIntegrityError("Evidence bundle digest does not match pointer")
        return bundle_path, manifest
    if not allow_legacy:
        raise EvidenceIntegrityError(
            "Unsigned legacy evidence is not accepted; provide a signed evidence/latest.json pointer"
        )
    return path, None


def verify_manifest(
    bundle_dir: Path,
    manifest: dict[str, Any],
    *,
    signing_key: str | None = None,
    expected_commit: str | None = None,
    max_age_seconds: int | None = None,
) -> None:
    if manifest.get("manifest_version") != 2:
        raise EvidenceIntegrityError("Unsupported or unsigned evidence manifest version")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceIntegrityError(
            "Evidence schema version does not match the running application"
        )
    generated_at_raw = manifest.get("generated_at")
    if not isinstance(generated_at_raw, str):
        raise EvidenceIntegrityError("Evidence manifest generation time is missing")
    try:
        generated_at = datetime.fromisoformat(generated_at_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceIntegrityError("Evidence manifest generation time is invalid") from exc
    if generated_at.tzinfo is None:
        raise EvidenceIntegrityError("Evidence manifest generation time must include a timezone")
    if generated_at > datetime.now(UTC) + timedelta(minutes=5):
        raise EvidenceIntegrityError("Evidence manifest generation time is in the future")
    if max_age_seconds is not None:
        if max_age_seconds <= 0:
            raise EvidenceIntegrityError("Evidence maximum age must be positive")
        age = datetime.now(UTC) - generated_at.astimezone(UTC)
        if age > timedelta(seconds=max_age_seconds):
            raise EvidenceIntegrityError("Evidence manifest is older than the allowed maximum age")

    git = manifest.get("git")
    if not isinstance(git, dict):
        raise EvidenceIntegrityError("Evidence manifest Git metadata is missing")
    commit = git.get("commit")
    if not isinstance(commit, str) or not commit:
        raise EvidenceIntegrityError("Evidence manifest has no Git commit")
    if git.get("dirty") is not False:
        raise EvidenceIntegrityError("Evidence was generated from a dirty or unknown Git tree")
    if expected_commit is not None and commit != expected_commit:
        raise EvidenceIntegrityError("Evidence Git commit does not match the expected release commit")
    signature = manifest.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "HMAC-SHA256":
        raise EvidenceIntegrityError("Evidence manifest signature is missing or unsupported")
    key = _evidence_key(signing_key)
    if signature.get("key_id") != sha256_bytes(key)[:16]:
        raise EvidenceIntegrityError("Evidence manifest was signed by a different key")
    expected_signature = _manifest_signature(manifest, key)
    supplied_signature = signature.get("value")
    if not isinstance(supplied_signature, str) or not hmac.compare_digest(
        supplied_signature, expected_signature
    ):
        raise EvidenceIntegrityError("Evidence manifest signature is invalid")
    files = manifest.get("files")
    if not isinstance(files, dict) or "bundle.json" not in files:
        raise EvidenceIntegrityError("Evidence manifest has no file digest map")
    for filename, expected in files.items():
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise EvidenceIntegrityError("Evidence manifest contains an unsafe filename")
        path = bundle_dir / filename
        if not path.is_file():
            raise EvidenceIntegrityError(f"Evidence artifact is missing: {filename}")
        actual = sha256_file(path)
        if actual != expected:
            raise EvidenceIntegrityError(f"Evidence artifact digest mismatch: {filename}")

    bundle = json.loads((bundle_dir / "bundle.json").read_text(encoding="utf-8"))
    if bundle.get("run", {}).get("run_id") != manifest.get("run_id"):
        raise EvidenceIntegrityError("Manifest run ID does not match bundle")
    if bundle.get("command", {}).get("command_id") != manifest.get("command_id"):
        raise EvidenceIntegrityError("Manifest command ID does not match bundle")
