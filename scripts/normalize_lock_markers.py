"""Restore upstream platform markers that pip-compile resolves on its host OS."""

from __future__ import annotations

import re
from argparse import ArgumentParser
from pathlib import Path

PYWIN32_LINE = re.compile(r"^pywin32==(?P<version>[^\s;]+) \\$", re.MULTILINE)
PYWIN32_MARKER = 'sys_platform == "win32" and python_version < "3.14"'
PYWIN32_BLOCK = re.compile(
    r"^pywin32==[^\n]+ \\\n"
    r"(?:    --hash=sha256:[0-9a-f]{64} \\\n)*"
    r"    --hash=sha256:[0-9a-f]{64}\n"
    r"    # via mcp\n",
    re.MULTILINE,
)
PYWIN32_INSERTION_POINT = re.compile(r"(?=^referencing==)", re.MULTILINE)


def normalize_full_lock(path: Path, previous_full_lock: Path | None = None) -> bool:
    original = path.read_text(encoding="utf-8")
    normalized, count = PYWIN32_LINE.subn(
        rf"pywin32==\g<version> ; {PYWIN32_MARKER} \\",
        original,
    )
    if "pywin32==" not in normalized and previous_full_lock is not None:
        previous = previous_full_lock.read_text(encoding="utf-8")
        match = PYWIN32_BLOCK.search(previous)
        if match is not None:
            normalized, restored = PYWIN32_INSERTION_POINT.subn(
                match.group(0), normalized, count=1
            )
            count += restored
    if count:
        path.write_text(normalized, encoding="utf-8")
    return bool(count)


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--previous-full-lock", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    normalize_full_lock(
        root / "requirements-lock" / "full.txt",
        previous_full_lock=args.previous_full_lock,
    )


if __name__ == "__main__":
    main()
