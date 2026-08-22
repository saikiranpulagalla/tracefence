from __future__ import annotations

import pytest

from scripts import compile_locks


def test_linux_platform_selects_linux_full_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compile_locks.platform, "system", lambda: "Linux")

    assert compile_locks.current_lock_platform() == "linux"
    assert compile_locks.runtime_lock_for_current_platform().as_posix() == (
        "requirements-lock/runtime-linux.txt"
    )
    assert compile_locks.full_lock_for_current_platform().as_posix() == (
        "requirements-lock/full-linux.txt"
    )
    assert compile_locks.main(["--platform", "linux", "--print-full-lock"]) == 0


def test_windows_platform_selects_windows_full_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compile_locks.platform, "system", lambda: "Windows")

    assert compile_locks.current_lock_platform() == "windows"
    assert compile_locks.runtime_lock_for_current_platform().as_posix() == (
        "requirements-lock/runtime-windows.txt"
    )
    assert compile_locks.full_lock_for_current_platform().as_posix() == (
        "requirements-lock/full-windows.txt"
    )


def test_unsupported_platform_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compile_locks.platform, "system", lambda: "Darwin")

    with pytest.raises(RuntimeError, match="supported only"):
        compile_locks.current_lock_platform()


def test_cross_platform_lock_request_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compile_locks.platform, "system", lambda: "Linux")

    with pytest.raises(SystemExit):
        compile_locks.main(["--platform", "windows", "--print-full-lock"])


def test_lock_compiler_never_selects_ambiguous_platform_locks() -> None:
    compiler = compile_locks.ROOT / "scripts" / "compile_locks.py"
    source = compiler.read_text(encoding="utf-8")

    assert "requirements-lock/runtime.txt" not in source
    assert "requirements-lock/full.txt" not in source
    assert compile_locks.runtime_lock_for_platform("linux").name == "runtime-linux.txt"
    assert compile_locks.runtime_lock_for_platform("windows").name == "runtime-windows.txt"
    assert compile_locks.full_lock_for_platform("linux").name == "full-linux.txt"
    assert compile_locks.full_lock_for_platform("windows").name == "full-windows.txt"
