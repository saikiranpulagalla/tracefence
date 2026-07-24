from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_release_version import (
    ReleaseVersionError,
    assert_tag_matches_package,
    package_version,
    python_version_from_tag,
)

ROOT = Path(__file__).resolve().parents[2]


def test_release_tag_normalizes_to_pep_440_version() -> None:
    assert python_version_from_tag("v0.2.1-rc2") == "0.2.1rc2"
    assert_tag_matches_package("v0.2.1-rc2", "0.2.1rc2")


def test_mismatched_release_tag_is_rejected() -> None:
    with pytest.raises(ReleaseVersionError, match="does not match"):
        assert_tag_matches_package("v0.2.1-rc2", "0.2.0")


def test_repository_release_version_and_artifact_expectations_are_rc2() -> None:
    assert package_version(ROOT / "pyproject.toml") == "0.2.1rc2"
    expected = {
        "tracefence-0.2.1rc2-py3-none-any.whl",
        "tracefence-0.2.1rc2.tar.gz",
    }
    report_text = (ROOT / "FINAL_REMEDIATION_REPORT.md").read_text(encoding="utf-8")
    assert all(name in report_text for name in expected)
