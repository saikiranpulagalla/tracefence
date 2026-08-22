"""Compile TraceFence locks in a disposable released-compatible toolchain.

pip-tools 7.6.0 cannot run with the fixed pip used by the audit environment.
The compiler's own pip is therefore isolated from the secure dependency set it
emits. The generated development lock remains pinned to pip 26.2.1.
"""

from __future__ import annotations

# This tool invokes only fixed local compiler commands with argument vectors.
import argparse
import os
import platform
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

COMPILER_PIP = "pip==26.1.2"
COMPILER_PIP_TOOLS = "pip-tools==7.6.0"
ROOT = Path(__file__).resolve().parents[1]
SHARED_LOCK_SPECS = (
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
        "requirements-lock/build.txt",
        ("requirements-build.in",),
        ("--allow-unsafe",),
    ),
)


def current_lock_platform() -> str:
    """Return the supported native resolver platform, or fail closed."""
    system = platform.system()
    if system == "Linux":
        return "linux"
    if system == "Windows":
        return "windows"
    raise RuntimeError(
        "TraceFence locks are supported only on native Linux/WSL or Windows "
        f"resolvers; detected {system!r}."
    )


def full_lock_for_platform(lock_platform: str) -> Path:
    if lock_platform not in {"linux", "windows"}:
        raise ValueError(f"Unsupported TraceFence lock platform: {lock_platform!r}")
    return Path("requirements-lock") / f"full-{lock_platform}.txt"


def full_lock_for_current_platform() -> Path:
    return full_lock_for_platform(current_lock_platform())


def _arguments(arguments: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=("linux", "windows"),
        help="Assert the native resolver platform; this does not cross-compile locks.",
    )
    parser.add_argument(
        "--print-full-lock",
        action="store_true",
        help="Print the full lock path selected for the native resolver platform.",
    )
    parsed = parser.parse_args(arguments)
    actual = current_lock_platform()
    if parsed.platform is not None and parsed.platform != actual:
        parser.error(
            f"--platform {parsed.platform!r} does not match native resolver "
            f"platform {actual!r}; cross-platform lock resolution is forbidden"
        )
    return parsed


def _python_in(virtualenv: Path) -> Path:
    if os.name == "nt":
        return virtualenv / "Scripts" / "python.exe"
    return virtualenv / "bin" / "python"


def _run(arguments: Sequence[str]) -> None:
    # Fixed argument vectors only; no shell or user-supplied command input.
    subprocess.run(  # nosec B603
        arguments, cwd=ROOT, check=True, shell=False
    )


def main(arguments: Sequence[str] | None = None) -> int:
    arguments = _arguments(arguments)
    full_lock = full_lock_for_current_platform()
    if arguments.print_full_lock:
        print(full_lock.as_posix())
        return 0

    lock_specs = (
        *SHARED_LOCK_SPECS,
        (full_lock.as_posix(), ("requirements-full.txt",), ()),
    )
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
        for output, inputs, extra_arguments in lock_specs:
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
