"""Fail when a release Git tag and Python package version describe different releases."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import tomllib
from pathlib import Path


class ReleaseVersionError(ValueError):
    """Raised when release metadata is missing or inconsistent."""


_TAG_PATTERN = re.compile(
    r"^v(?P<release>\d+\.\d+\.\d+)(?:-(?P<pre>a|b|rc)(?P<number>\d+))?$"
)


def python_version_from_tag(tag: str) -> str:
    match = _TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ReleaseVersionError(f"Unsupported release tag format: {tag}")
    prerelease = match.group("pre")
    if prerelease is None:
        return match.group("release")
    return f"{match.group('release')}{prerelease}{match.group('number')}"


def package_version(pyproject: Path) -> str:
    with pyproject.open("rb") as handle:
        payload = tomllib.load(handle)
    try:
        value = payload["project"]["version"]
    except KeyError as exc:
        raise ReleaseVersionError("pyproject.toml has no project.version") from exc
    if not isinstance(value, str) or not value:
        raise ReleaseVersionError("pyproject.toml project.version is invalid")
    return value


def assert_tag_matches_package(tag: str, version: str) -> None:
    expected = python_version_from_tag(tag)
    if expected != version:
        raise ReleaseVersionError(
            f"Git tag {tag} represents {expected}, which does not match package {version}"
        )


def _current_tag() -> str | None:
    if os.getenv("GITHUB_REF_TYPE") == "tag":
        return os.getenv("GITHUB_REF_NAME")
    completed = subprocess.run(
        ["git", "describe", "--tags", "--exact-match"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    tag = completed.stdout.strip()
    return tag or None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag")
    parser.add_argument(
        "--pyproject",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "pyproject.toml",
    )
    args = parser.parse_args()
    tag = args.tag or _current_tag()
    if tag is None:
        return
    try:
        assert_tag_matches_package(tag, package_version(args.pyproject))
    except ReleaseVersionError as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
