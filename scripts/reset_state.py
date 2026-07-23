from __future__ import annotations

import argparse
import os
from pathlib import Path

from sqlalchemy.engine import make_url

from tracefence.config import settings

EXPECTED_DATABASE_FILENAME = "tracefence.db"


def _absolute(path: Path) -> Path:
    return path if path.is_absolute() else (Path.cwd() / path).absolute()


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Refusing symlink reset target: {path}")


def _reject_broad_directory(data_dir: Path) -> None:
    resolved = data_dir.resolve()
    protected = {Path(resolved.anchor), Path.home().resolve()}
    for variable in ("WINDIR", "ProgramFiles", "ProgramFiles(x86)"):
        value = os.getenv(variable)
        if value:
            protected.add(Path(value).resolve())
    if resolved in protected:
        raise RuntimeError(
            f"Refusing root, home, or system data directory: {resolved}"
        )


def validate_reset_target(database_url: str, data_dir: Path) -> Path:
    parsed = make_url(database_url)
    if parsed.get_backend_name() != "sqlite":
        raise RuntimeError("reset_state.py supports only SQLite databases")
    if parsed.drivername not in {
        "sqlite",
        "sqlite+pysqlite",
        "sqlite+aiosqlite",
    }:
        raise RuntimeError("reset_state.py supports only SQLite with pysqlite")
    if parsed.query:
        raise RuntimeError("SQLite URI query parameters are not accepted for reset")
    raw = parsed.database
    if not raw or raw == ":memory:":
        raise RuntimeError("The configured database is in-memory and needs no reset")

    untrusted_data_dir = _absolute(data_dir)
    _reject_symlink(untrusted_data_dir)
    _reject_broad_directory(untrusted_data_dir)
    resolved_data_dir = untrusted_data_dir.resolve()

    untrusted_target = _absolute(Path(raw))
    _reject_symlink(untrusted_target)
    for parent in untrusted_target.parents:
        if parent == untrusted_data_dir:
            break
        _reject_symlink(parent)
    resolved_target = untrusted_target.resolve()
    if resolved_data_dir not in resolved_target.parents:
        raise RuntimeError(
            f"Refusing database path outside explicit data directory: {resolved_target}"
        )
    if resolved_target.name != EXPECTED_DATABASE_FILENAME:
        raise RuntimeError(
            "Refusing unexpected database filename; expected "
            f"{EXPECTED_DATABASE_FILENAME}"
        )
    return resolved_target


def _validated_candidates(path: Path) -> tuple[Path, ...]:
    candidates = (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
    for candidate in candidates:
        _reject_symlink(candidate)
        if candidate.exists() and not candidate.is_file():
            raise RuntimeError(
                f"Refusing non-regular SQLite reset target: {candidate}"
            )
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Delete the local TraceFence SQLite state")
    parser.add_argument("--yes", action="store_true", help="Confirm destructive deletion")
    parser.add_argument(
        "--data-dir",
        type=Path,
        required=True,
        help="Explicit project data directory containing tracefence.db",
    )
    parser.add_argument(
        "--expected-path",
        type=Path,
        required=True,
        help="Exact configured database path to confirm",
    )
    args = parser.parse_args()
    if not args.yes:
        parser.error("Pass --yes to confirm deletion")

    path = validate_reset_target(settings.database_url, args.data_dir)
    confirmed = _absolute(args.expected_path).resolve()
    if confirmed != path:
        raise RuntimeError(
            f"Confirmation path {confirmed} does not exactly match {path}"
        )
    candidates = _validated_candidates(path)
    print(f"Confirmed reset target: {path}")
    removed = False
    for candidate in candidates:
        if candidate.exists():
            candidate.unlink()
            print(f"Removed {candidate}")
            removed = True
    if not removed:
        print(f"No database files found at {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
