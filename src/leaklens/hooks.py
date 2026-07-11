"""Managed Git pre-commit hook installation."""

from __future__ import annotations

import os
from pathlib import Path

MARKER = "# Managed by LeakLens"
SCRIPT = f"""#!/bin/sh
{MARKER}
exec leaklens scan --staged --format table
"""


def install_hook(repository: str | Path = ".", *, force: bool = False) -> Path:
    root = Path(repository).resolve()
    hooks = root / ".git" / "hooks"
    if not hooks.is_dir():
        raise ValueError(f"{root} is not a Git repository with local hooks")
    hook = hooks / "pre-commit"
    if (
        hook.exists()
        and MARKER not in hook.read_text(encoding="utf-8", errors="replace")
        and not force
    ):
        raise FileExistsError(f"{hook} already exists; use --force only after reviewing it")
    hook.write_text(SCRIPT, encoding="utf-8")
    hook.chmod(hook.stat().st_mode | 0o111)
    return hook


def uninstall_hook(repository: str | Path = ".") -> bool:
    hook = Path(repository).resolve() / ".git" / "hooks" / "pre-commit"
    if not hook.exists():
        return False
    if MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
        raise ValueError(f"refusing to remove unmanaged hook {hook}")
    hook.unlink()
    return True


def hook_is_executable(path: Path) -> bool:
    return os.access(path, os.X_OK)
