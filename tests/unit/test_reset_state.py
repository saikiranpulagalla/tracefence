from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

from scripts import reset_state


def test_reset_target_must_be_expected_sqlite_file_inside_data_dir(
    tmp_path: Path,
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    expected = data_dir / "tracefence.db"

    assert reset_state.validate_reset_target(
        f"sqlite+pysqlite:///{expected.as_posix()}",
        data_dir,
    ) == expected.resolve()

    with pytest.raises(RuntimeError, match="outside"):
        reset_state.validate_reset_target(
            f"sqlite+pysqlite:///{(tmp_path / 'escape.db').as_posix()}",
            data_dir,
        )
    with pytest.raises(RuntimeError, match="filename"):
        reset_state.validate_reset_target(
            f"sqlite+pysqlite:///{(data_dir / 'other.db').as_posix()}",
            data_dir,
        )
    with pytest.raises(RuntimeError, match="only SQLite"):
        reset_state.validate_reset_target(
            "postgresql://localhost/tracefence",
            data_dir,
        )


def test_reset_rejects_symlink_before_deleting_any_file(
    tmp_path: Path,
    monkeypatch,
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database = data_dir / "tracefence.db"
    database.write_bytes(b"database")
    wal = Path(f"{database}-wal")
    wal.write_bytes(b"symlink placeholder")
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == wal or original_is_symlink(path),
    )

    monkeypatch.setattr(
        reset_state,
        "settings",
        replace(
            reset_state.settings,
            database_url=f"sqlite+pysqlite:///{database.as_posix()}",
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reset_state.py",
            "--yes",
            "--data-dir",
            str(data_dir),
            "--expected-path",
            str(database),
        ],
    )

    with pytest.raises(RuntimeError, match="symlink"):
        reset_state.main()
    assert database.read_bytes() == b"database"


def test_reset_requires_exact_path_confirmation(
    tmp_path: Path,
    monkeypatch,
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database = data_dir / "tracefence.db"
    database.write_bytes(b"database")
    monkeypatch.setattr(
        reset_state,
        "settings",
        replace(
            reset_state.settings,
            database_url=f"sqlite+pysqlite:///{database.as_posix()}",
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reset_state.py",
            "--yes",
            "--data-dir",
            str(data_dir),
            "--expected-path",
            str(data_dir / "different.db"),
        ],
    )

    with pytest.raises(RuntimeError, match="does not exactly match"):
        reset_state.main()
    assert database.exists()


def test_reset_rejects_broad_data_directory_and_non_regular_target(
    tmp_path: Path,
):
    home_target = Path.home() / "tracefence.db"
    with pytest.raises(RuntimeError, match="root, home, or system"):
        reset_state.validate_reset_target(
            f"sqlite+pysqlite:///{home_target.as_posix()}",
            Path.home(),
        )

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database_directory = data_dir / "tracefence.db"
    database_directory.mkdir()
    target = reset_state.validate_reset_target(
        f"sqlite+pysqlite:///{database_directory.as_posix()}",
        data_dir,
    )
    with pytest.raises(RuntimeError, match="non-regular"):
        reset_state._validated_candidates(target)
