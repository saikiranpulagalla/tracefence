from __future__ import annotations

import argparse
from pathlib import Path

from tracefence.config import settings


def sqlite_path(database_url: str) -> Path:
    normalized = database_url.replace("sqlite+aiosqlite://", "sqlite+pysqlite://")
    prefix = "sqlite+pysqlite:///"
    if not normalized.startswith(prefix):
        raise RuntimeError("reset_state.py supports only file-backed SQLite databases")
    raw = normalized.removeprefix(prefix)
    if raw == ":memory:":
        raise RuntimeError("The configured database is in-memory and needs no reset")
    return Path(raw).resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description="Delete the local TraceFence SQLite state")
    parser.add_argument("--yes", action="store_true", help="Confirm destructive deletion")
    args = parser.parse_args()
    if not args.yes:
        parser.error("Pass --yes to confirm deletion")

    path = sqlite_path(settings.database_url)
    removed = False
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if candidate.exists():
            candidate.unlink()
            print(f"Removed {candidate}")
            removed = True
    if not removed:
        print(f"No database files found at {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
