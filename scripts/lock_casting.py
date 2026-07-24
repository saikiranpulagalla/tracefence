"""Create an environment-neutral integrity lock for casting.yaml."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path


def lock_payload(source: Path) -> dict[str, str | int]:
    content = source.read_bytes()
    return {
        "lock_version": 1,
        "source": source.name,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def write_lock(source: Path, destination: Path) -> None:
    payload = lock_payload(source)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    write_lock(root / "casting.yaml", root / "casting.yaml.lock")


if __name__ == "__main__":
    main()
