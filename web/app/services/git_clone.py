"""Git clone helpers for audit tasks."""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def _git_timeout() -> int:
    try:
        from strix.config import load_settings

        return int(load_settings().runtime.git_timeout)
    except Exception:
        return 300


def clone_repository(
    url: str,
    dest: Path,
    *,
    branch: str | None = None,
    commit: str | None = None,
) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise GitError(f"clone destination already exists: {dest}")

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([url, str(dest)])

    timeout = _git_timeout()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git clone timed out after {exc.timeout}s") from exc
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or result.stdout.strip() or "git clone failed")

    if commit:
        try:
            checkout = subprocess.run(
                ["git", "checkout", commit],
                cwd=dest,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitError(f"git checkout timed out after {exc.timeout}s") from exc
        if checkout.returncode != 0:
            raise GitError(checkout.stderr.strip() or "git checkout failed")

    return dest
