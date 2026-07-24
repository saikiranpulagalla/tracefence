"""Deterministic high-confidence secret scan for release artifacts."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any

# Security: subprocess is limited to the fixed, read-only Git argv in repository discovery.

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".css",
    ".env",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def tracked_and_unignored_files(root: Path) -> list[Path]:
    """Return Git-visible files without traversing ignored caches or evidence."""
    command = ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    # The fixed argv contains no user input and is used only for read-only repository discovery.
    result = subprocess.run(  # nosec B603
        command,
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def scan_paths(root: Path, paths: list[Path]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in paths:
        if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for secret_type, pattern in PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {
                            "file": path.relative_to(root).as_posix(),
                            "line": line_number,
                            "type": secret_type,
                        }
                    )
    return findings


def atomic_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    findings = scan_paths(root, tracked_and_unignored_files(root))
    payload = {
        "scanner": "tracefence-high-confidence-v1",
        "status": "PASS" if not findings else "FAIL",
        "findings": findings,
    }
    if args.output:
        atomic_private_json(args.output.resolve(), payload)
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
