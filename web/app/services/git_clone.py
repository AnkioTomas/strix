"""Git clone helpers for audit tasks."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from app.services.git_askpass import PASSWORD_ENV, USERNAME_ENV


if TYPE_CHECKING:
    from app.config import Settings


class GitError(RuntimeError):
    pass


def clone_repository(
    url: str,
    dest: Path,
    *,
    branch: str | None = None,
    commit: str | None = None,
    settings: Settings | None = None,
) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise GitError(f"clone destination already exists: {dest}")

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([url, str(dest)])

    env = _clone_env(settings)
    try:
        result = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, check=False, timeout=300, env=env
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git clone timed out after {exc.timeout}s") from exc
    if result.returncode != 0:
        raise GitError(
            _redact(
                result.stderr.strip() or result.stdout.strip() or "git clone failed",
                settings,
            )
        )

    if commit:
        try:
            checkout = subprocess.run(  # noqa: S603
                ["git", "checkout", commit],  # noqa: S607
                cwd=dest,
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitError(f"git checkout timed out after {exc.timeout}s") from exc
        if checkout.returncode != 0:
            raise GitError(
                _redact(checkout.stderr.strip() or "git checkout failed", settings)
            )

    return dest


def _clone_env(settings: Settings | None) -> dict[str, str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    # Internal Gitea often uses a private CA / self-signed cert.
    env["GIT_SSL_NO_VERIFY"] = "1"
    env.pop(USERNAME_ENV, None)
    env.pop(PASSWORD_ENV, None)

    auth = settings.git_auth() if settings is not None else None
    if not auth:
        # Still force sslVerify off even without credentials.
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = "http.sslVerify"
        env["GIT_CONFIG_VALUE_0"] = "false"
        return env

    env["GIT_ASKPASS"] = _askpass_program()
    env[USERNAME_ENV] = auth[0]
    env[PASSWORD_ENV] = auth[1]
    # Disable credential helpers so they cannot prompt or persist the token.
    env["GIT_CONFIG_COUNT"] = "2"
    env["GIT_CONFIG_KEY_0"] = "credential.helper"
    env["GIT_CONFIG_VALUE_0"] = ""
    env["GIT_CONFIG_KEY_1"] = "http.sslVerify"
    env["GIT_CONFIG_VALUE_1"] = "false"
    return env


def _askpass_program() -> str:
    path = Path(__file__).resolve().parent / "git_askpass.py"
    mode = path.stat().st_mode
    if not mode & stat.S_IXUSR:
        path.chmod(mode | stat.S_IXUSR)
    return str(path)


def _redact(text: str, settings: Settings | None) -> str:
    if settings is None:
        return text
    secrets = [settings.git_token.strip(), settings.git_username.strip()]
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text
