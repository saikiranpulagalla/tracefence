"""Compile TraceFence locks in a disposable released-compatible toolchain.

pip-tools 7.6.0 cannot run with the fixed pip used by the audit environment.
The compiler's own pip is therefore isolated from the secure dependency set it
emits.  The generated development lock remains pinned to pip 26.2.1.
"""

from __future__ import annotations

# This tool invokes only fixed local compiler commands with argument vectors.
import os
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

COMPILER_PIP = "pip==26.1.2"
COMPILER_PIP_TOOLS = "pip-tools==7.6.0"
ROOT = Path(__file__).resolve().parents[1]
LOCK_SPECS = (
    (
        "requirements-lock/runtime.txt",
        ("requirements.txt",),
        (),
    ),
    (
        "requirements-lock/development.txt",
        ("requirements-dev.txt",),
        ("--allow-unsafe",),
    ),
    (
        "requirements-lock/full.txt",
        ("requirements-full.txt",),
        (),
    ),
    (
        "requirements-lock/build.txt",
        ("requirements-build.in",),
        ("--allow-unsafe",),
    ),
)


def _python_in(virtualenv: Path) -> Path:
    if os.name == "nt":
        return virtualenv / "Scripts" / "python.exe"
    return virtualenv / "bin" / "python"


def _run(arguments: Sequence[str]) -> None:
    # Fixed argument vectors only; no shell or user-supplied command input.
    subprocess.run(  # nosec B603
        arguments, cwd=ROOT, check=True, shell=False
    )


def main() -> int:
    (ROOT / "requirements-lock").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tracefence-lock-compiler-") as temporary:
        compiler_root = Path(temporary)
        _run((sys.executable, "-m", "venv", str(compiler_root)))
        compiler_python = _python_in(compiler_root)
        _run(
            (
                str(compiler_python),
                "-m",
                "pip",
                "install",
                "--upgrade",
                COMPILER_PIP,
                COMPILER_PIP_TOOLS,
            )
        )
        for output, inputs, extra_arguments in LOCK_SPECS:
            _run(
                (
                    str(compiler_python),
                    "-m",
                    "piptools",
                    "compile",
                    "--generate-hashes",
                    "--resolver=backtracking",
                    *extra_arguments,
                    "--output-file",
                    output,
                    *inputs,
                )
            )
    _run((sys.executable, str(ROOT / "scripts" / "normalize_lock_markers.py")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
