"""Restore upstream platform markers that pip-compile resolves on its host OS."""

from __future__ import annotations

import re
from pathlib import Path

PYWIN32_LINE = re.compile(r"^pywin32==(?P<version>[^\s;]+) \\$", re.MULTILINE)
PYWIN32_MARKER = 'sys_platform == "win32" and python_version < "3.14"'


def normalize_full_lock(path: Path) -> bool:
    original = path.read_text(encoding="utf-8")
    normalized, count = PYWIN32_LINE.subn(
        rf"pywin32==\g<version> ; {PYWIN32_MARKER} \\",
        original,
    )
    if count:
        path.write_text(normalized, encoding="utf-8")
    return bool(count)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    normalize_full_lock(root / "requirements-lock" / "full.txt")


if __name__ == "__main__":
    main()
